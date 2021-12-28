// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]

use bytes::Bytes;
use fastpay::{network, transport};
use fastpay_core::authority::*;
use fastx_types::{base_types::*, committee::*, messages::*, object::Object, serialize::*};
use futures::stream::StreamExt;
use log::*;
use std::time::{Duration, Instant};
use structopt::StructOpt;
use tokio::{runtime::Builder, time};

use std::thread;

#[derive(Debug, Clone, StructOpt)]
#[structopt(
    name = "FastPay Benchmark",
    about = "Local end-to-end test and benchmark of the FastPay protocol"
)]
struct ClientServerBenchmark {
    /// Choose a network protocol between Udp and Tcp
    #[structopt(long, default_value = "udp")]
    protocol: transport::NetworkProtocol,
    /// Hostname
    #[structopt(long, default_value = "127.0.0.1")]
    host: String,
    /// Base port number
    #[structopt(long, default_value = "9555")]
    port: u32,
    /// Size of the FastPay committee
    #[structopt(long, default_value = "10")]
    committee_size: usize,
    /// Maximum number of requests in flight (0 for blocking client)
    #[structopt(long, default_value = "1000")]
    max_in_flight: usize,
    /// Number of accounts and transactions used in the benchmark
    #[structopt(long, default_value = "40000")]
    num_accounts: usize,
    /// Timeout for sending queries (us)
    #[structopt(long, default_value = "4000000")]
    send_timeout_us: u64,
    /// Timeout for receiving responses (us)
    #[structopt(long, default_value = "4000000")]
    recv_timeout_us: u64,
    /// Maximum size of datagrams received and sent (bytes)
    #[structopt(long, default_value = transport::DEFAULT_MAX_DATAGRAM_SIZE)]
    buffer_size: usize,
}

fn main() {
    env_logger::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let benchmark = ClientServerBenchmark::from_args();

    let (state, orders) = benchmark.make_structures();

    // Start the servers on the thread pool

    // Make special single-core runtime for each server
    let b = benchmark.clone();
    thread::spawn(move || {
        let mut runtime = Builder::new()
            .enable_all()
            .basic_scheduler()
            .thread_stack_size(15 * 1024 * 1024)
            .build()
            .unwrap();

        runtime.block_on(async move {
            let server = b.spawn_server(state).await;
            if let Err(err) = server.join().await {
                error!("Server ended with an error: {}", err);
            }
        });
    });

    let mut runtime = Builder::new()
        .enable_all()
        .basic_scheduler()
        .thread_stack_size(15 * 1024 * 1024)
        .build()
        .unwrap();
    runtime.block_on(benchmark.launch_client(orders));
}

impl ClientServerBenchmark {
    fn make_structures(&self) -> (AuthorityState, Vec<Bytes>) {
        info!("Preparing accounts.");
        let mut keys = Vec::new();
        for _ in 0..self.committee_size {
            keys.push(get_key_pair());
        }
        let committee = Committee {
            voting_rights: keys.iter().map(|(k, _)| (*k, 1)).collect(),
            total_votes: self.committee_size,
        };

        // Pick an authority and create state.
        let (public_auth0, secret_auth0) = keys.pop().unwrap();

        let mut state = AuthorityState::new(committee.clone(), public_auth0, secret_auth0.copy());

        // Seed user accounts.
        let mut account_objects = Vec::new();
        for _ in 0..self.num_accounts {
            let keypair = get_key_pair();
            let object_id: ObjectID = ObjectID::random();

            let mut client = Object::with_id_for_testing(object_id);
            client.transfer(keypair.0);
            state.init_order_lock(client.to_object_reference());
            state.insert_object(client);
            account_objects.push((keypair.0, object_id, keypair.1));
        }

        info!("Preparing transactions.");
        // Make one transaction per account (transfer order + confirmation).
        let mut orders: Vec<Bytes> = Vec::new();
        let mut next_recipient = get_key_pair().0;
        for (pubx, object_id, secx) in account_objects.iter() {
            let transfer = Transfer {
                object_id: *object_id,
                sender: *pubx,
                recipient: Address::FastPay(next_recipient),
                sequence_number: SequenceNumber::from(0),
                user_data: UserData::default(),
            };
            next_recipient = *pubx;
            let order = Order::new_transfer(transfer.clone(), secx);

            // Serialize order
            let bufx = serialize_order(&order);
            assert!(!bufx.is_empty());

            // Make certificate
            let mut certificate = CertifiedOrder {
                order,
                signatures: Vec::new(),
            };
            for i in 0..committee.quorum_threshold() {
                let (pubx, secx) = keys.get(i).unwrap();
                let sig = Signature::new(&certificate.order.kind, secx);
                certificate.signatures.push((*pubx, sig));
            }

            let bufx2 = serialize_cert(&certificate);
            assert!(!bufx2.is_empty());

            orders.push(bufx2.into());
            orders.push(bufx.into());
        }

        (state, orders)
    }

    async fn spawn_server(&self, state: AuthorityState) -> transport::SpawnedServer {
        let server = network::Server::new(
            self.protocol,
            self.host.clone(),
            self.port,
            state,
            self.buffer_size,
        );
        server.spawn().await.unwrap()
    }

    async fn launch_client(&self, mut orders: Vec<Bytes>) {
        time::delay_for(Duration::from_millis(1000)).await;

        let items_number = orders.len() / 2;
        let time_start = Instant::now();

        let max_in_flight = (self.max_in_flight as usize) as usize;
        info!("Set max_in_flight to {}", max_in_flight);

        info!("Sending requests.");
        if self.max_in_flight > 0 {
            let mass_client = network::MassClient::new(
                self.protocol,
                self.host.clone(),
                self.port,
                self.buffer_size,
                Duration::from_micros(self.send_timeout_us),
                Duration::from_micros(self.recv_timeout_us),
                max_in_flight as u64,
            );

            let responses = mass_client.run(orders).concat().await;
            info!("Received {} responses.", responses.len(),);
        } else {
            // Use actual client core
            let client = network::Client::new(
                self.protocol,
                self.host.clone(),
                self.port,
                self.buffer_size,
                Duration::from_micros(self.send_timeout_us),
                Duration::from_micros(self.recv_timeout_us),
            );

            while !orders.is_empty() {
                if orders.len() % 1000 == 0 {
                    info!("Process message {}...", orders.len());
                }
                let order = orders.pop().unwrap();
                let status = client.send_recv_bytes(order.to_vec()).await;
                match status {
                    Ok(info) => {
                        debug!("Query response: {:?}", info);
                    }
                    Err(error) => {
                        error!("Failed to execute order: {}", error);
                    }
                }
            }
        }

        let time_total = time_start.elapsed().as_micros();
        warn!(
            "Total time: {}us, items: {}, tx/sec: {}",
            time_total,
            items_number,
            1_000_000.0 * (items_number as f64) / (time_total as f64)
        );
    }
}
