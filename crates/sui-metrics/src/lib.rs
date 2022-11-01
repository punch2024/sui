// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use once_cell::sync::OnceCell;
use prometheus::{register_int_gauge_vec_with_registry, IntGaugeVec, Registry};

pub use scopeguard;

#[derive(Debug)]
pub struct Metrics {
    pub tasks: IntGaugeVec,
    pub futures: IntGaugeVec,
}

impl Metrics {
    fn new(registry: &Registry) -> Self {
        Self {
            tasks: register_int_gauge_vec_with_registry!(
                "monitored_tasks",
                "Number of running tasks per callsite.",
                &["callsite"],
                registry,
            )
            .unwrap(),
            futures: register_int_gauge_vec_with_registry!(
                "monitored_futures",
                "Number of pending futures per callsite.",
                &["callsite"],
                registry,
            )
            .unwrap(),
        }
    }
}

static METRICS: OnceCell<Metrics> = OnceCell::new();

pub fn init_metrics(registry: &Registry) {
    METRICS
        .set(Metrics::new(registry))
        .expect("sui_metrics::init_metrics duplicate init")
}

pub fn get_metrics() -> Option<&'static Metrics> {
    METRICS.get()
}

#[macro_export]
macro_rules! monitored_future {
    ($fut: expr) => {{
        monitored_future!(futures, $fut)
    }};

    ($metric: ident, $fut: expr) => {{
        let name = format!("{}_{}", file!(), line!());

        async move {
            let metrics = sui_metrics::get_metrics();

            let _guard = if let Some(m) = &metrics {
                m.$metric.with_label_values(&[&name]).inc();
                Some(sui_metrics::scopeguard::guard(m, |metrics| {
                    m.$metric.with_label_values(&[&name]).dec();
                }))
            } else {
                None
            };

            $fut.await
        }
    }};
}

#[macro_export]
macro_rules! spawn_monitored_task {
    ($fut: expr) => {
        tokio::task::spawn(sui_metrics::monitored_future!(tasks, $fut))
    };
}
