// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

use super::QueryExecutor;
use crate::{config::Limits, error::Error, metrics::Metrics};
use async_trait::async_trait;
use diesel::{
    pg::Pg,
    query_builder::{Query, QueryFragment, QueryId},
    query_dsl::LoadQuery,
    QueryResult, RunQueryDsl,
};
use sui_indexer::indexer_reader::IndexerReader;

use tracing::error;
use uuid::Uuid;

pub(crate) struct PgExecutor {
    pub inner: IndexerReader,
    pub limits: Limits,
    pub metrics: Metrics,
}

pub(crate) struct PgConnection<'c> {
    max_cost: u64,
    conn: &'c mut diesel::PgConnection,
}

impl PgExecutor {
    pub(crate) fn new(inner: IndexerReader, limits: Limits, metrics: Metrics) -> Self {
        Self {
            inner,
            limits,
            metrics,
        }
    }
}

#[async_trait]
impl QueryExecutor for PgExecutor {
    type Connection = diesel::PgConnection;
    type Backend = Pg;
    type DbConnection<'c> = PgConnection<'c>;

    async fn execute<T, U, E>(&self, txn: T) -> Result<U, Error>
    where
        T: FnOnce(&mut Self::DbConnection<'_>) -> Result<U, E>,
        E: From<diesel::result::Error> + std::error::Error,
        T: Send + 'static,
        U: Send + 'static,
        E: Send + 'static,
    {
        let max_cost = self.limits.max_db_query_cost;
        let instant = Instant::now();
        let result = self
            .inner
            .run_query_async(move |conn| txn(&mut PgConnection { max_cost, conn }))
            .await;
        let elapsed = instant.elapsed();
        self.metrics
            .observe_db_data(elapsed.as_secs(), result.is_ok());
        if let Err(e) = &result {
            error!("DB query error: {e:?}");
        }
        result.map_err(|e| Error::Internal(e.to_string()))
    }

    async fn execute_repeatable<T, U, E>(&self, txn: T) -> Result<U, Error>
    where
        T: FnOnce(&mut Self::DbConnection<'_>) -> Result<U, E>,
        E: From<diesel::result::Error> + std::error::Error,
        T: Send + 'static,
        U: Send + 'static,
        E: Send + 'static,
    {
        let max_cost = self.limits.max_db_query_cost;
        let instant = Instant::now();
        let result = self
            .inner
            .run_query_repeatable_async(move |conn| txn(&mut PgConnection { max_cost, conn }))
            .await;
        let elapsed = instant.elapsed();
        self.metrics
            .observe_db_data(elapsed.as_secs(), result.is_ok());
        if let Err(e) = &result {
            error!("DB query error: {e:?}");
        }
        result.map_err(|e| Error::Internal(e.to_string()))
    }
}

impl<'c> super::DbConnection for PgConnection<'c> {
    type Connection = diesel::PgConnection;
    type Backend = Pg;

    fn result<Q, U>(&mut self, query: impl Fn() -> Q, query_id: &Uuid) -> QueryResult<U>
    where
        Q: diesel::query_builder::Query,
        Q: LoadQuery<'static, Self::Connection, U>,
        Q: QueryId + QueryFragment<Self::Backend>,
    {
        if !query_id.is_nil() {
            query_cost::log(self.conn, self.max_cost, query());
        }
        query().get_result(self.conn)
    }

    fn results<Q, U>(&mut self, query: impl Fn() -> Q, query_id: &Uuid) -> QueryResult<Vec<U>>
    where
        Q: diesel::query_builder::Query,
        Q: LoadQuery<'static, Self::Connection, U>,
        Q: QueryId + QueryFragment<Self::Backend>,
    {
        if !query_id.is_nil() {
            query_cost::log(self.conn, self.max_cost, query());
        }
        query().get_results(self.conn)
    }
}

/// Support for calculating estimated query cost using EXPLAIN and then logging it.
mod query_cost {
    use super::*;

    use diesel::{query_builder::AstPass, sql_types::Text, PgConnection, QueryResult};
    use serde_json::Value;
    use tap::{TapFallible, TapOptional};
    use tracing::{info, warn};

    #[derive(Debug, Clone, Copy, QueryId)]
    struct Explained<Q> {
        query: Q,
    }

    impl<Q: Query> Query for Explained<Q> {
        type SqlType = Text;
    }

    impl<Q> RunQueryDsl<PgConnection> for Explained<Q> {}

    impl<Q: QueryFragment<Pg>> QueryFragment<Pg> for Explained<Q> {
        fn walk_ast<'b>(&'b self, mut out: AstPass<'_, 'b, Pg>) -> QueryResult<()> {
            out.push_sql("EXPLAIN (FORMAT JSON) ");
            self.query.walk_ast(out.reborrow())?;
            Ok(())
        }
    }

    /// Run `EXPLAIN` on the `query`, and log the estimated cost.
    pub(crate) fn log<Q>(conn: &mut PgConnection, max_db_query_cost: u64, query: Q)
    where
        Q: Query + QueryId + QueryFragment<Pg> + RunQueryDsl<PgConnection>,
    {
        let Some(cost) = explain(conn, query) else {
            warn!("Failed to extract cost from EXPLAIN.");
            return;
        };

        if cost > max_db_query_cost as f64 {
            warn!(cost, max_db_query_cost, exceeds = true, "Estimated cost");
        } else {
            info!(cost, max_db_query_cost, exceeds = false, "Estimated cost");
        }
    }

    pub(crate) fn explain<Q>(conn: &mut PgConnection, query: Q) -> Option<f64>
    where
        Q: Query + QueryId + QueryFragment<Pg> + RunQueryDsl<PgConnection>,
    {
        let result: String = Explained { query }
            .get_result(conn)
            .tap_err(|e| warn!("Failed to run EXPLAIN: {e}"))
            .ok()?;

        let parsed = serde_json::from_str(&result)
            .tap_err(|e| warn!("Failed to parse EXPLAIN result: {e}"))
            .ok()?;

        extract_cost(&parsed).tap_none(|| warn!("Failed to extract cost from EXPLAIN"))
    }

    fn extract_cost(parsed: &Value) -> Option<f64> {
        parsed.get(0)?.get("Plan")?.get("Total Cost")?.as_f64()
    }
}

#[cfg(all(test, feature = "pg_integration"))]
mod tests {
    use super::*;
    use crate::config::DEFAULT_SERVER_DB_URL;
    use diesel::QueryDsl;
    use sui_framework::BuiltInFramework;
    use sui_indexer::{
        get_pg_pool_connection, models_v2::objects::StoredObject, new_pg_connection_pool_impl,
        schema_v2::objects, types_v2::IndexedObject, utils::reset_database,
    };

    #[test]
    fn test_query_cost() {
        let pool = new_pg_connection_pool_impl(DEFAULT_SERVER_DB_URL, Some(5)).unwrap();
        let mut conn = get_pg_pool_connection(&pool).unwrap();
        reset_database(&mut conn, /* drop_all */ true, /* use_v2 */ true).unwrap();

        let objects: Vec<StoredObject> = BuiltInFramework::iter_system_packages()
            .map(|pkg| IndexedObject::from_object(1, pkg.genesis_object(), None).into())
            .collect();

        let expect = objects.len();
        let actual = diesel::insert_into(objects::dsl::objects)
            .values(objects)
            .execute(&mut conn)
            .unwrap();

        assert_eq!(expect, actual, "Failed to write objects");

        use objects::dsl;
        let query_one = dsl::objects.select(dsl::objects.star()).limit(1);
        let query_all = dsl::objects.select(dsl::objects.star());

        // Test estimating query costs
        let cost_one = query_cost::explain(&mut conn, query_one).unwrap();
        let cost_all = query_cost::explain(&mut conn, query_all).unwrap();

        assert!(
            cost_one < cost_all,
            "cost_one = {cost_one} >= {cost_all} = cost_all"
        );
    }
}
