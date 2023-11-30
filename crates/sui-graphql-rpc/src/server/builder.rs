// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::config::{MAX_CONCURRENT_REQUESTS, RPC_TIMEOUT_ERR_SLEEP_RETRY_PERIOD};
use crate::context_data::package_cache::DbPackageStore;
use crate::mutations::Mutation;
use crate::{
    config::ServerConfig,
    context_data::db_data_provider::PgManager,
    error::Error,
    extensions::{
        feature_gate::FeatureGate,
        logger::Logger,
        query_limits_checker::{QueryLimitsChecker, ShowUsage},
        timeout::Timeout,
    },
    metrics::RequestMetrics,
    server::version::{check_version_middleware, set_version_middleware},
    types::query::{Query, SuiGraphQLSchema},
};
use async_graphql::EmptySubscription;
use async_graphql::{extensions::ExtensionFactory, Schema, SchemaBuilder};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::http::HeaderMap;
use axum::routing::{post, MethodRouter};
use axum::{
    extract::{connect_info::IntoMakeServiceWithConnectInfo, ConnectInfo},
    middleware,
};
use axum::{headers::Header, Router};
use hyper::server::conn::AddrIncoming as HyperAddrIncoming;
use hyper::Server as HyperServer;
use std::{any::Any, net::SocketAddr, sync::Arc, time::Instant};
use sui_package_resolver::{PackageStoreWithLruCache, Resolver};
use sui_sdk::SuiClientBuilder;
use tokio::sync::OnceCell;

pub struct Server {
    pub server: HyperServer<HyperAddrIncoming, IntoMakeServiceWithConnectInfo<Router, SocketAddr>>,
}

impl Server {
    pub async fn run(self) -> Result<(), Error> {
        get_or_init_server_start_time().await;
        self.server
            .await
            .map_err(|e| Error::Internal(format!("Server run failed: {}", e)))
    }
}

pub(crate) struct ServerBuilder {
    port: u16,
    host: String,

    schema: SchemaBuilder<Query, Mutation, EmptySubscription>,
    ide_title: Option<String>,

    router: Option<Router>,
}

impl ServerBuilder {
    pub fn new(port: u16, host: String) -> Self {
        Self {
            port,
            host,
            schema: async_graphql::Schema::build(Query, Mutation, EmptySubscription),
            ide_title: None,
            router: None,
        }
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn max_query_depth(mut self, max_depth: u32) -> Self {
        self.schema = self.schema.limit_depth(max_depth as usize);
        self
    }

    pub fn max_query_nodes(mut self, max_nodes: u32) -> Self {
        self.schema = self.schema.limit_complexity(max_nodes as usize);
        self
    }

    pub fn context_data(mut self, context_data: impl Any + Send + Sync) -> Self {
        self.schema = self.schema.data(context_data);
        self
    }

    pub fn extension(mut self, extension: impl ExtensionFactory) -> Self {
        self.schema = self.schema.extension(extension);
        self
    }

    fn ide_title(mut self, name: String) -> Self {
        self.ide_title = Some(name);
        self
    }

    fn build_schema(self) -> Schema<Query, Mutation, EmptySubscription> {
        self.schema.finish()
    }

    fn build_components(
        self,
    ) -> (
        String,
        Option<String>,
        Schema<Query, Mutation, EmptySubscription>,
        Router,
    ) {
        let address = self.address();
        let ServerBuilder {
            schema,
            // TODO: remove this once we have expose layer in builder.
            // This should be set in the builder.
            ide_title,
            router,
            ..
        } = self;
        (
            address,
            ide_title,
            schema.finish(),
            router.expect("Router not initialized"),
        )
    }

    fn init_router(&mut self) {
        if self.router.is_none() {
            let router: Router = Router::new()
                .route("/", post(graphql_handler))
                .route("/health", axum::routing::get(health_checks))
                .route("/schema", axum::routing::get(get_schema))
                .layer(middleware::from_fn(check_version_middleware))
                .layer(middleware::from_fn(set_version_middleware));
            self.router = Some(router);
        }
    }

    pub fn route(mut self, path: &str, method_handler: MethodRouter) -> Self {
        self.init_router();
        self.router = self.router.map(|router| router.route(path, method_handler));
        self
    }

    pub fn build(self) -> Result<Server, Error> {
        let (address, ide_title, schema, router) = self.build_components();

        let app = router
            .layer(axum::extract::Extension(schema))
            // TODO: remove this once we have expose layer in builder.
            // This should be set in the builder.
            .layer(axum::extract::Extension(ide_title));

        Ok(Server {
            server: axum::Server::bind(
                &address
                    .parse()
                    .map_err(|_| Error::Internal(format!("Failed to parse address {}", address)))?,
            )
            .serve(app.into_make_service_with_connect_info::<SocketAddr>()),
        })
    }

    pub async fn from_yaml_config(path: &str) -> Result<Self, Error> {
        let config = ServerConfig::from_yaml(path)?;
        Self::from_config(&config).await
    }

    pub async fn from_config(config: &ServerConfig) -> Result<Self, Error> {
        let mut builder =
            ServerBuilder::new(config.connection.port, config.connection.host.clone());

        let name_service_config = config.name_service.clone();
        let reader = PgManager::reader_with_config(
            config.connection.db_url.clone(),
            config.connection.db_pool_size,
        )
        .map_err(|e| Error::Internal(format!("Failed to create pg connection pool: {}", e)))?;
        let pg_conn_pool = PgManager::new(reader.clone(), config.service.limits);
        let package_store = DbPackageStore(reader);
        let package_cache = PackageStoreWithLruCache::new(package_store);
        let fn_rpc_url = config
            .tx_exec_full_node
            .node_rpc_urls
            // TODO: decide how to handle multiple fullnode urls
            // Maybe allow changing sdk client if one of the urls fails
            .first()
            .ok_or(Error::Internal(
                "No fullnode urls found in config".to_string(),
            ))?;
        // SDK for talking to fullnode. Used for executing transactions only
        // TODO: wrap this in custom logic to pick proper fullnode url
        let sui_sdk_client = SuiClientBuilder::default()
            .request_timeout(RPC_TIMEOUT_ERR_SLEEP_RETRY_PERIOD)
            .max_concurrent_requests(MAX_CONCURRENT_REQUESTS)
            .build(fn_rpc_url)
            .await
            .map_err(|e| Error::Internal(format!("Failed to create SuiClient: {}", e)))?;

        let prom_addr: SocketAddr = format!(
            "{}:{}",
            config.connection.prom_url, config.connection.prom_port
        )
        .parse()
        .map_err(|_| {
            Error::Internal(format!(
                "Failed to parse url {}, port {} into socket address",
                config.connection.prom_url, config.connection.prom_port
            ))
        })?;
        let registry_service = mysten_metrics::start_prometheus_server(prom_addr);
        println!("Starting Prometheus HTTP endpoint at {}", prom_addr);
        let registry = registry_service.default_registry();

        let metrics = RequestMetrics::new(&registry);

        builder = builder
            .max_query_depth(config.service.limits.max_query_depth)
            .max_query_nodes(config.service.limits.max_query_nodes)
            .context_data(config.service.clone())
            .context_data(pg_conn_pool)
            .context_data(Resolver::new(package_cache))
            .context_data(sui_sdk_client)
            .context_data(name_service_config)
            .ide_title(config.ide.ide_title.clone())
            .context_data(Arc::new(metrics))
            .context_data(config.clone());

        if config.internal_features.feature_gate {
            builder = builder.extension(FeatureGate);
        }
        if config.internal_features.logger {
            builder = builder.extension(Logger::default());
        }
        if config.internal_features.query_limits_checker {
            builder = builder.extension(QueryLimitsChecker::default());
        }
        if config.internal_features.query_timeout {
            builder = builder.extension(Timeout);
        }

        Ok(builder)
    }
}

async fn get_schema() -> impl axum::response::IntoResponse {
    let schema = include_str!("../../schema/current_progress_schema.graphql").to_string();
    let schema = format!(
        r#"
    <span style="white-space: pre;">{}
    </span>
    "#,
        schema
    );

    axum::response::Html(schema)
}

async fn graphql_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    schema: axum::Extension<SuiGraphQLSchema>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut req = req.into_inner();
    if headers.contains_key(ShowUsage::name()) {
        req.data.insert(ShowUsage)
    }
    // Capture the IP address of the client
    // Note: if a load balancer is used it must be configured to forward the client IP address
    req.data.insert(addr);
    schema.execute(req).await.into()
}

async fn health_checks(
    schema: axum::Extension<SuiGraphQLSchema>,
) -> impl axum::response::IntoResponse {
    // Simple request to check if the DB is up
    // TODO: add more checks
    let req = r#"
        query {
            chainIdentifier
        }
        "#;
    let db_up = match schema.execute(req).await.is_ok() {
        true => "UP",
        false => "DOWN",
    };
    let uptime = get_or_init_server_start_time()
        .await
        .elapsed()
        .as_secs_f64();
    format!(
        r#"{{"status": "UP","uptime": {},"checks": {{"DB": "{}",}}}}
        "#,
        uptime, db_up
    )
}

// One server per proc, so this is okay
async fn get_or_init_server_start_time() -> &'static Instant {
    static ONCE: OnceCell<Instant> = OnceCell::const_new();
    ONCE.get_or_init(|| async move { Instant::now() }).await
}

pub mod tests {
    use super::*;
    use crate::{
        config::{ConnectionConfig, Limits, ServiceConfig},
        context_data::db_data_provider::PgManager,
        extensions::query_limits_checker::QueryLimitsChecker,
        extensions::timeout::Timeout,
        metrics::RequestMetrics,
        test_infra::cluster::{serve_executor, ExecutorCluster, DEFAULT_INTERNAL_DATA_SOURCE_PORT},
    };
    use async_graphql::{
        extensions::{Extension, ExtensionContext, NextExecute},
        Response,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use simulacrum::Simulacrum;
    use std::sync::Arc;
    use std::time::Duration;

    async fn prep_cluster() -> (ConnectionConfig, ExecutorCluster) {
        let rng = StdRng::from_seed([12; 32]);
        let mut sim = Simulacrum::new_with_rng(rng);

        sim.create_checkpoint();

        let connection_config = ConnectionConfig::ci_integration_test_cfg();

        (
            connection_config.clone(),
            serve_executor(
                connection_config,
                DEFAULT_INTERNAL_DATA_SOURCE_PORT,
                Arc::new(sim),
            )
            .await,
        )
    }

    pub async fn test_timeout_impl() {
        let (connection_config, _cluster) = prep_cluster().await;

        struct TimedExecuteExt {
            pub min_req_delay: Duration,
        }

        impl ExtensionFactory for TimedExecuteExt {
            fn create(&self) -> Arc<dyn Extension> {
                Arc::new(TimedExecuteExt {
                    min_req_delay: self.min_req_delay,
                })
            }
        }

        #[async_trait::async_trait]
        impl Extension for TimedExecuteExt {
            async fn execute(
                &self,
                ctx: &ExtensionContext<'_>,
                operation_name: Option<&str>,
                next: NextExecute<'_>,
            ) -> Response {
                tokio::time::sleep(self.min_req_delay).await;
                next.run(ctx, operation_name).await
            }
        }

        async fn test_timeout(
            delay: Duration,
            timeout: Duration,
            connection_config: &ConnectionConfig,
        ) -> Response {
            let db_url: String = connection_config.db_url.clone();
            let reader = PgManager::reader(db_url).expect("Failed to create pg connection pool");
            let pg_conn_pool = PgManager::new(reader, Limits::default());
            let mut cfg = ServiceConfig::default();
            cfg.limits.request_timeout_ms = timeout.as_millis() as u64;

            let schema = ServerBuilder::new(8000, "127.0.0.1".to_string())
                .context_data(pg_conn_pool)
                .context_data(cfg)
                .extension(TimedExecuteExt {
                    min_req_delay: delay,
                })
                .extension(Timeout)
                .build_schema();
            schema.execute("{ chainIdentifier }").await
        }

        let timeout = Duration::from_millis(1000);
        let delay = Duration::from_millis(100);

        // Should complete successfully
        let resp = test_timeout(delay, timeout, &connection_config).await;
        assert!(resp.is_ok());

        // Should timeout
        let errs: Vec<_> = test_timeout(timeout, timeout, &connection_config)
            .await
            .into_result()
            .unwrap_err()
            .into_iter()
            .map(|e| e.message)
            .collect();
        let exp = format!("Request timed out. Limit: {}s", timeout.as_secs_f32());
        assert_eq!(errs, vec![exp]);
    }

    pub async fn test_query_depth_limit_impl() {
        let (connection_config, _cluster) = prep_cluster().await;

        async fn exec_query_depth_limit(
            depth: u32,
            query: &str,
            connection_config: &ConnectionConfig,
        ) -> Response {
            let db_url: String = connection_config.db_url.clone();
            let reader = PgManager::reader(db_url).expect("Failed to create pg connection pool");
            let pg_conn_pool = PgManager::new(reader, Limits::default());
            let schema = ServerBuilder::new(8000, "127.0.0.1".to_string())
                .context_data(pg_conn_pool)
                .max_query_depth(depth)
                .build_schema();
            schema.execute(query).await
        }

        // Should complete successfully
        let resp = exec_query_depth_limit(1, "{ chainIdentifier }", &connection_config).await;
        assert!(resp.is_ok());
        let resp = exec_query_depth_limit(
            5,
            "{ chainIdentifier protocolConfig { configs { value key }} }",
            &connection_config,
        )
        .await;
        assert!(resp.is_ok());

        // Should fail
        let errs: Vec<_> = exec_query_depth_limit(0, "{ chainIdentifier }", &connection_config)
            .await
            .into_result()
            .unwrap_err()
            .into_iter()
            .map(|e| e.message)
            .collect();

        assert_eq!(errs, vec!["Query is nested too deep.".to_string()]);
        let errs: Vec<_> = exec_query_depth_limit(
            2,
            "{ chainIdentifier protocolConfig { configs { value key }} }",
            &connection_config,
        )
        .await
        .into_result()
        .unwrap_err()
        .into_iter()
        .map(|e| e.message)
        .collect();
        assert_eq!(errs, vec!["Query is nested too deep.".to_string()]);
    }

    pub async fn test_query_node_limit_impl() {
        let (connection_config, _cluster) = prep_cluster().await;

        async fn exec_query_node_limit(
            nodes: u32,
            query: &str,
            connection_config: &ConnectionConfig,
        ) -> Response {
            let db_url: String = connection_config.db_url.clone();
            let reader = PgManager::reader(db_url).expect("Failed to create pg connection pool");
            let pg_conn_pool = PgManager::new(reader, Limits::default());
            let schema = ServerBuilder::new(8000, "127.0.0.1".to_string())
                .context_data(pg_conn_pool)
                .max_query_nodes(nodes)
                .build_schema();
            schema.execute(query).await
        }

        // Should complete successfully
        let resp = exec_query_node_limit(1, "{ chainIdentifier }", &connection_config).await;
        assert!(resp.is_ok());
        let resp = exec_query_node_limit(
            5,
            "{ chainIdentifier protocolConfig { configs { value key }} }",
            &connection_config,
        )
        .await;
        assert!(resp.is_ok());

        // Should fail
        let err: Vec<_> = exec_query_node_limit(0, "{ chainIdentifier }", &connection_config)
            .await
            .into_result()
            .unwrap_err()
            .into_iter()
            .map(|e| e.message)
            .collect();
        assert_eq!(err, vec!["Query is too complex.".to_string()]);

        let err: Vec<_> = exec_query_node_limit(
            4,
            "{ chainIdentifier protocolConfig { configs { value key }} }",
            &connection_config,
        )
        .await
        .into_result()
        .unwrap_err()
        .into_iter()
        .map(|e| e.message)
        .collect();
        assert_eq!(err, vec!["Query is too complex.".to_string()]);
    }

    pub async fn test_query_default_page_limit_impl() {
        let rng = StdRng::from_seed([12; 32]);
        let mut sim = Simulacrum::new_with_rng(rng);

        sim.create_checkpoint();
        sim.create_checkpoint();

        let connection_config = ConnectionConfig::ci_integration_test_cfg();
        let limits = Limits {
            default_page_size: 1,
            ..Default::default()
        };
        let db_url: String = connection_config.db_url.clone();
        let reader = PgManager::reader(db_url).expect("Failed to create pg connection pool");
        let pg_conn_pool = PgManager::new(reader, limits);
        let schema = ServerBuilder::new(8000, "127.0.0.1".to_string())
            .context_data(pg_conn_pool)
            .build_schema();

        let resp = schema
            .execute("{ checkpointConnection { nodes { sequenceNumber } } }")
            .await;
        let data = resp.data.clone().into_json().unwrap();
        let checkpoints = data
            .get("checkpointConnection")
            .unwrap()
            .get("nodes")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(
            checkpoints.len(),
            1,
            "Checkpoints should have exactly one element"
        );

        let resp = schema
            .execute("{ checkpointConnection(first: 2) { nodes { sequenceNumber } } }")
            .await;
        let data = resp.data.clone().into_json().unwrap();
        let checkpoints = data
            .get("checkpointConnection")
            .unwrap()
            .get("nodes")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(
            checkpoints.len(),
            2,
            "Checkpoints should return two elements"
        );
    }

    pub async fn test_query_max_page_limit_impl() {
        let (connection_config, _cluster) = prep_cluster().await;

        let db_url: String = connection_config.db_url.clone();
        let reader = PgManager::reader(db_url).expect("Failed to create pg connection pool");
        let pg_conn_pool = PgManager::new(reader, Limits::default());
        let schema = ServerBuilder::new(8000, "127.0.0.1".to_string())
            .context_data(pg_conn_pool)
            .build_schema();

        // Should complete successfully
        let resp = schema
            .execute("{ objectConnection(first: 1) { nodes { version } } }")
            .await;
        assert!(resp.is_ok());

        // Should fail
        let err: Vec<_> = schema
            .execute("{ objectConnection(first: 51) { nodes { version } } }")
            .await
            .into_result()
            .unwrap_err()
            .into_iter()
            .map(|e| e.message)
            .collect();
        assert_eq!(
            err,
            vec!["Page size exceeded - requested: 51, limit: 50".to_string()]
        );
    }

    pub async fn test_query_complexity_metrics_impl() {
        let (connection_config, _cluster) = prep_cluster().await;

        let binding_address: SocketAddr = "0.0.0.0:9185".parse().unwrap();
        let registry = mysten_metrics::start_prometheus_server(binding_address).default_registry();
        let metrics = RequestMetrics::new(&registry);
        let metrics = Arc::new(metrics);
        let metrics2 = metrics.clone();

        let service_config = ServiceConfig::default();

        let db_url: String = connection_config.db_url.clone();
        let reader = PgManager::reader(db_url).expect("Failed to create pg connection pool");
        let pg_conn_pool = PgManager::new(reader, service_config.limits);
        let schema = ServerBuilder::new(8000, "127.0.0.1".to_string())
            .max_query_depth(service_config.limits.max_query_depth)
            .max_query_nodes(service_config.limits.max_query_nodes)
            .context_data(service_config)
            .context_data(pg_conn_pool)
            .context_data(metrics)
            .extension(QueryLimitsChecker::default())
            .build_schema();
        let _ = schema.execute("{ chainIdentifier }").await;

        assert_eq!(metrics2.num_nodes.get_sample_count(), 1);
        assert_eq!(metrics2.query_depth.get_sample_count(), 1);
        assert_eq!(metrics2.num_nodes.get_sample_sum(), 1.);
        assert_eq!(metrics2.query_depth.get_sample_sum(), 1.);

        let _ = schema
            .execute("{ chainIdentifier protocolConfig { configs { value key }} }")
            .await;
        assert_eq!(metrics2.num_nodes.get_sample_count(), 2);
        assert_eq!(metrics2.query_depth.get_sample_count(), 2);
        assert_eq!(metrics2.num_nodes.get_sample_sum(), 2. + 4.);
        assert_eq!(metrics2.query_depth.get_sample_sum(), 1. + 3.);
    }
}
