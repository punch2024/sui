// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, net::IpAddr, sync::Arc};

use count_min_sketch::CountMinSketch32;
use mysten_metrics::spawn_monitored_task;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::time::Duration;
use std::time::{Instant, SystemTime};
use sui_types::traffic_control::{FreqThresholdConfig, PolicyConfig, PolicyType, ServiceResponse};
use tracing::info;

pub struct TrafficSketch {
    /// Circular buffer Count Min Sketches representing a sliding window
    /// of traffic data. Note that the 32 in CountMinSketch32 represents
    /// the number of bits used to represent the count in the sketch. Since
    /// we only count on a sketch for a window of `update_interval`, we only
    /// need enough precision to represent the max expected unique IP addresses
    /// we may see in that window. For a 10 second period, we might conservatively
    /// expect 100,000, which can be represented in 17 bits, but not 16. We can
    /// potentially lower the memory consumption by using CountMinSketch16, which
    /// will reliably support up to ~65,000 unique IP addresses in the window.
    sketches: VecDeque<CountMinSketch32<IpAddr>>,
    window_size: Duration,
    update_interval: Duration,
    last_reset_time: Instant,
    current_sketch_index: usize,
}

impl TrafficSketch {
    pub fn new(
        window_size: Duration,
        update_interval: Duration,
        sketch_capacity: usize,
        sketch_probability: f64,
        sketch_tolerance: f64,
    ) -> Self {
        // intentionally round down via integer division. We can't have a partial sketch
        let num_sketches = window_size.as_secs() / update_interval.as_secs();
        let new_window_size = Duration::from_secs(num_sketches * update_interval.as_secs());
        if new_window_size != window_size {
            info!(
                "Rounding traffic sketch window size down to {} seconds to make it an integer multiple of update interval {} seconds.",
                new_window_size.as_secs(),
                update_interval.as_secs(),
            );
        }
        let window_size = new_window_size;

        assert!(
            window_size < Duration::from_secs(600),
            "window_size too large. Max 600 seconds"
        );
        assert!(
            update_interval < window_size,
            "Update interval may not be larger than window size"
        );
        assert!(
            update_interval >= Duration::from_secs(1),
            "Update interval too short, must be at least 1 second"
        );
        assert!(num_sketches <= 10, "Given parameters require too many sketches to be stored. Reduce window size or increase update interval.");
        let mem_estimate = (num_sketches as usize)
            * CountMinSketch32::<IpAddr>::estimate_memory(
                sketch_capacity,
                sketch_probability,
                sketch_tolerance,
            )
            .expect("Failed to estimate memory for CountMinSketch32");
        assert!(mem_estimate < 128_000_000, "Memory estimate for traffic sketch exceeds 128MB. Reduce window size or increase update interval.");

        let mut sketches = VecDeque::with_capacity(num_sketches as usize);
        for _ in 0..num_sketches {
            sketches.push_back(
                CountMinSketch32::<IpAddr>::new(
                    sketch_capacity,
                    sketch_probability,
                    sketch_tolerance,
                )
                .expect("Failed to create CountMinSketch32"),
            );
        }
        Self {
            sketches,
            window_size,
            update_interval,
            last_reset_time: Instant::now(),
            current_sketch_index: 0,
        }
    }

    pub fn increment_count(&mut self, ip: IpAddr) {
        // reset all expired intervals
        let current_time = Instant::now();
        let mut elapsed = current_time.duration_since(self.last_reset_time);
        while elapsed >= self.update_interval {
            self.rotate_window();
            elapsed -= self.update_interval;
        }
        // Increment in the current active sketch
        self.sketches[self.current_sketch_index].increment(&ip);
    }

    pub fn get_request_rate(&self, ip: &IpAddr) -> f64 {
        let count: u32 = self.sketches.iter().map(|sketch| sketch.estimate(ip)).sum();
        count as f64 / self.window_size.as_secs() as f64
    }

    fn rotate_window(&mut self) {
        self.current_sketch_index = (self.current_sketch_index + 1) % self.sketches.len();
        self.sketches[self.current_sketch_index].clear();
        self.last_reset_time = Instant::now();
    }
}

#[derive(Clone, Debug)]
pub struct TrafficTally {
    pub connection_ip: Option<IpAddr>,
    pub proxy_ip: Option<IpAddr>,
    pub result: ServiceResponse,
    pub timestamp: SystemTime,
}

#[derive(Clone, Debug, Default)]
pub struct PolicyResponse {
    pub block_connection_ip: Option<IpAddr>,
    pub block_proxy_ip: Option<IpAddr>,
}

pub trait Policy {
    // returns, e.g. (true, false) if connection_ip should be added to blocklist
    // and proxy_ip should not
    fn handle_tally(&mut self, tally: TrafficTally) -> PolicyResponse;
    fn policy_config(&self) -> &PolicyConfig;
}

// Nonserializable representation, also note that inner types are
// not object safe, so we can't use a trait object instead
pub enum TrafficControlPolicy {
    FreqThreshold(FreqThresholdPolicy),
    NoOp(NoOpPolicy),
    // Test policies below this point
    TestNConnIP(TestNConnIPPolicy),
    TestInspectIp(TestInspectIpPolicy),
    TestPanicOnInvocation(TestPanicOnInvocationPolicy),
}

impl Policy for TrafficControlPolicy {
    fn handle_tally(&mut self, tally: TrafficTally) -> PolicyResponse {
        match self {
            TrafficControlPolicy::NoOp(policy) => policy.handle_tally(tally),
            TrafficControlPolicy::FreqThreshold(policy) => policy.handle_tally(tally),
            TrafficControlPolicy::TestNConnIP(policy) => policy.handle_tally(tally),
            TrafficControlPolicy::TestInspectIp(policy) => policy.handle_tally(tally),
            TrafficControlPolicy::TestPanicOnInvocation(policy) => policy.handle_tally(tally),
        }
    }

    fn policy_config(&self) -> &PolicyConfig {
        match self {
            TrafficControlPolicy::NoOp(policy) => policy.policy_config(),
            TrafficControlPolicy::FreqThreshold(policy) => policy.policy_config(),
            TrafficControlPolicy::TestNConnIP(policy) => policy.policy_config(),
            TrafficControlPolicy::TestInspectIp(policy) => policy.policy_config(),
            TrafficControlPolicy::TestPanicOnInvocation(policy) => policy.policy_config(),
        }
    }
}

impl TrafficControlPolicy {
    pub async fn from_spam_config(policy_config: PolicyConfig) -> Self {
        Self::from_config(policy_config.clone().spam_policy_type, policy_config).await
    }
    pub async fn from_error_config(policy_config: PolicyConfig) -> Self {
        Self::from_config(policy_config.clone().error_policy_type, policy_config).await
    }
    pub async fn from_config(policy_type: PolicyType, policy_config: PolicyConfig) -> Self {
        match policy_type {
            PolicyType::NoOp => Self::NoOp(NoOpPolicy::new(policy_config)),
            PolicyType::FreqThreshold(freq_threshold_config) => Self::FreqThreshold(
                FreqThresholdPolicy::new(policy_config, freq_threshold_config),
            ),
            PolicyType::TestNConnIP(n) => {
                Self::TestNConnIP(TestNConnIPPolicy::new(policy_config, n).await)
            }
            PolicyType::TestInspectIp => {
                Self::TestInspectIp(TestInspectIpPolicy::new(policy_config))
            }
            PolicyType::TestPanicOnInvocation => {
                Self::TestPanicOnInvocation(TestPanicOnInvocationPolicy::new(policy_config))
            }
        }
    }
}

////////////// *** Policy definitions *** //////////////

pub struct FreqThresholdPolicy {
    config: PolicyConfig,
    sketch: TrafficSketch,
    threshold: u64,
}

impl FreqThresholdPolicy {
    pub fn new(
        config: PolicyConfig,
        FreqThresholdConfig {
            threshold,
            window_size_secs,
            update_interval_secs,
            sketch_capacity,
            sketch_probability,
            sketch_tolerance,
        }: FreqThresholdConfig,
    ) -> Self {
        let sketch = TrafficSketch::new(
            Duration::from_secs(window_size_secs),
            Duration::from_secs(update_interval_secs),
            sketch_capacity,
            sketch_probability,
            sketch_tolerance,
        );
        Self {
            config,
            sketch,
            threshold,
        }
    }

    fn handle_tally(&mut self, tally: TrafficTally) -> PolicyResponse {
        if let Some(ip) = tally.connection_ip {
            self.sketch.increment_count(ip);
            if self.sketch.get_request_rate(&ip) >= self.threshold as f64 {
                return PolicyResponse {
                    block_connection_ip: Some(ip),
                    block_proxy_ip: None,
                };
            }
        }
        PolicyResponse::default()
    }

    fn policy_config(&self) -> &PolicyConfig {
        &self.config
    }
}

////////////// *** Test policies below this point *** //////////////

#[derive(Clone)]
pub struct NoOpPolicy {
    config: PolicyConfig,
}

impl NoOpPolicy {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    fn handle_tally(&mut self, _tally: TrafficTally) -> PolicyResponse {
        PolicyResponse::default()
    }

    fn policy_config(&self) -> &PolicyConfig {
        &self.config
    }
}

#[derive(Clone)]
pub struct TestNConnIPPolicy {
    config: PolicyConfig,
    frequencies: Arc<RwLock<HashMap<IpAddr, u64>>>,
    threshold: u64,
}

impl TestNConnIPPolicy {
    pub async fn new(config: PolicyConfig, threshold: u64) -> Self {
        let frequencies = Arc::new(RwLock::new(HashMap::new()));
        let frequencies_clone = frequencies.clone();
        spawn_monitored_task!(run_clear_frequencies(
            frequencies_clone,
            config.connection_blocklist_ttl_sec * 2,
        ));
        Self {
            config,
            frequencies,
            threshold,
        }
    }

    fn handle_tally(&mut self, tally: TrafficTally) -> PolicyResponse {
        let ip = if let Some(ip) = tally.connection_ip {
            ip
        } else {
            return PolicyResponse::default();
        };

        // increment the count for the IP
        let mut frequencies = self.frequencies.write();
        let count = frequencies.entry(tally.connection_ip.unwrap()).or_insert(0);
        *count += 1;
        PolicyResponse {
            block_connection_ip: if *count >= self.threshold {
                Some(ip)
            } else {
                None
            },
            block_proxy_ip: None,
        }
    }

    fn policy_config(&self) -> &PolicyConfig {
        &self.config
    }
}

async fn run_clear_frequencies(frequencies: Arc<RwLock<HashMap<IpAddr, u64>>>, window_secs: u64) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(window_secs)).await;
        frequencies.write().clear();
    }
}

#[derive(Clone)]
pub struct TestInspectIpPolicy {
    config: PolicyConfig,
}

impl TestInspectIpPolicy {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    fn handle_tally(&mut self, tally: TrafficTally) -> PolicyResponse {
        assert!(tally.proxy_ip.is_some(), "Expected proxy_ip to be present");
        PolicyResponse {
            block_connection_ip: None,
            block_proxy_ip: None,
        }
    }

    fn policy_config(&self) -> &PolicyConfig {
        &self.config
    }
}

#[derive(Clone)]
pub struct TestPanicOnInvocationPolicy {
    config: PolicyConfig,
}

impl TestPanicOnInvocationPolicy {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    fn handle_tally(&mut self, _: TrafficTally) -> PolicyResponse {
        panic!("Tally for this policy should never be invoked")
    }

    fn policy_config(&self) -> &PolicyConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use sui_macros::sim_test;
    use sui_types::traffic_control::{
        DEFAULT_SKETCH_CAPACITY, DEFAULT_SKETCH_PROBABILITY, DEFAULT_SKETCH_TOLERANCE,
    };

    #[sim_test]
    async fn test_freq_threshold_policy() {
        // Create freq policy that will block on average frequency 2 requests per second
        // as observed over a 5 second window
        let mut policy = TrafficControlPolicy::FreqThreshold(FreqThresholdPolicy::new(
            PolicyConfig::default(),
            FreqThresholdConfig {
                threshold: 2,
                window_size_secs: 5,
                update_interval_secs: 1,
                ..Default::default()
            },
        ));
        let alice = TrafficTally {
            connection_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            proxy_ip: None,
            result: ServiceResponse::Validator(Ok(())),
            timestamp: SystemTime::now(),
        };
        let bob = TrafficTally {
            connection_ip: Some(IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1))),
            proxy_ip: None,
            result: ServiceResponse::Validator(Ok(())),
            timestamp: SystemTime::now(),
        };

        // initial 2 tallies for alice, should not block
        for _ in 0..2 {
            let response = policy.handle_tally(alice.clone());
            assert_eq!(response.block_connection_ip, None);
            assert_eq!(response.block_proxy_ip, None);
        }

        // meanwhile bob spams 10 requests at once and is blocked
        for _ in 0..9 {
            let response = policy.handle_tally(bob.clone());
            assert_eq!(response.block_connection_ip, None);
            assert_eq!(response.block_proxy_ip, None);
        }
        let response = policy.handle_tally(bob.clone());
        assert_eq!(response.block_proxy_ip, None);
        assert_eq!(response.block_connection_ip, bob.connection_ip);

        // 2 more tallies, so far we are above 2 tallies
        // per second, but over the average window of 5 seconds
        // we are still below the threshold. Should not block
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        for _ in 0..2 {
            let response = policy.handle_tally(alice.clone());
            assert_eq!(response.block_connection_ip, None);
            assert_eq!(response.block_proxy_ip, None);
        }
        // bob is no longer blocked, as we moved past the bursty traffic
        // in the sliding window
        let _ = policy.handle_tally(bob.clone());
        let response = policy.handle_tally(bob.clone());
        assert_eq!(response.block_proxy_ip, None);
        assert_eq!(response.block_connection_ip, bob.connection_ip);

        // close to threshold for alice, but still below
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        for _ in 0..5 {
            let response = policy.handle_tally(alice.clone());
            assert_eq!(response.block_connection_ip, None);
            assert_eq!(response.block_proxy_ip, None);
        }

        // should block alice now
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let response = policy.handle_tally(alice.clone());
        assert_eq!(response.block_connection_ip, alice.connection_ip);
        assert_eq!(response.block_proxy_ip, None);
    }

    #[sim_test]
    async fn test_traffic_sketch_mem_estimate() {
        // Test for getting a rough estimate of memory usage for the traffic sketch
        // given certain parameters. Parameters below are the default.
        // With default parameters, memory estimate is 113 MB.
        let window_size = Duration::from_secs(30);
        let update_interval = Duration::from_secs(5);
        let mem_estimate = CountMinSketch32::<IpAddr>::estimate_memory(
            DEFAULT_SKETCH_CAPACITY,
            DEFAULT_SKETCH_PROBABILITY,
            DEFAULT_SKETCH_TOLERANCE,
        )
        .unwrap()
            * (window_size.as_secs() / update_interval.as_secs()) as usize;
        assert!(
            mem_estimate < 128_000_000,
            "Memory estimate {mem_estimate} for traffic sketch exceeds 128MB."
        );
    }
}
