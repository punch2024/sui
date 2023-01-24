// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! CheckpointExecutor is a Node component that executes all checkpoints for the
//! given epoch. It acts as a Consumer to StateSync
//! for newly synced checkpoints, taking these checkpoints and
//! scheduling and monitoring their execution. Its primary goal is to allow
//! for catching up to the current checkpoint sequence number of the network
//! as quickly as possible so that a newly joined, or recovering Node can
//! participate in a timely manner. To that end, CheckpointExecutor attempts
//! to saturate the CPU with executor tasks (one per checkpoint), each of which
//! handle scheduling and awaiting checkpoint transaction execution.
//!
//! CheckpointExecutor is made recoverable in the event of Node shutdown by way of a watermark,
//! highest_executed_checkpoint, which is guaranteed to be updated sequentially in order,
//! despite checkpoints themselves potentially being executed nonsequentially and in parallel.
//! CheckpointExecutor parallelizes checkpoints of the same epoch as much as possible.
//! CheckpointExecutor enforces the invariant that if `run` returns successfully, we have reached the
//! end of epoch. This allows us to use it as a signal for reconfig.

use std::{collections::HashMap, sync::Arc, time::Duration};

use futures::stream::FuturesOrdered;
use mysten_metrics::spawn_monitored_task;
use prometheus::Registry;
use sui_config::node::CheckpointExecutorConfig;
use sui_types::committee::{Committee, EpochId};
use sui_types::{
    base_types::{ExecutionDigests, TransactionDigest, TransactionEffectsDigest},
    error::SuiResult,
    messages::{TransactionEffects, VerifiedCertificate},
    messages_checkpoint::{CheckpointSequenceNumber, VerifiedCheckpoint},
};
use tokio::{
    sync::broadcast::{self, error::RecvError},
    task::JoinHandle,
    time::timeout,
};
use tokio_stream::StreamExt;
use tracing::{debug, error, info, instrument, warn};
use typed_store::Map;

use crate::authority::AuthorityStore;
use crate::authority::{
    authority_per_epoch_store::AuthorityPerEpochStore, authority_store::EffectsStore,
};
use crate::transaction_manager::TransactionManager;
use crate::{authority::EffectsNotifyRead, checkpoints::CheckpointStore};

use self::metrics::CheckpointExecutorMetrics;

mod metrics;
#[cfg(test)]
pub(crate) mod tests;

type CheckpointExecutionBuffer = FuturesOrdered<JoinHandle<VerifiedCheckpoint>>;

pub struct CheckpointExecutor {
    mailbox: broadcast::Receiver<VerifiedCheckpoint>,
    checkpoint_store: Arc<CheckpointStore>,
    authority_store: Arc<AuthorityStore>,
    tx_manager: Arc<TransactionManager>,
    config: CheckpointExecutorConfig,
    metrics: Arc<CheckpointExecutorMetrics>,
}

impl CheckpointExecutor {
    pub fn new(
        mailbox: broadcast::Receiver<VerifiedCheckpoint>,
        checkpoint_store: Arc<CheckpointStore>,
        authority_store: Arc<AuthorityStore>,
        tx_manager: Arc<TransactionManager>,
        config: CheckpointExecutorConfig,
        prometheus_registry: &Registry,
    ) -> Self {
        Self {
            mailbox,
            checkpoint_store,
            authority_store,
            tx_manager,
            config,
            metrics: CheckpointExecutorMetrics::new(prometheus_registry),
        }
    }

    pub fn new_for_tests(
        mailbox: broadcast::Receiver<VerifiedCheckpoint>,
        checkpoint_store: Arc<CheckpointStore>,
        authority_store: Arc<AuthorityStore>,
        tx_manager: Arc<TransactionManager>,
    ) -> Self {
        Self {
            mailbox,
            checkpoint_store,
            authority_store,
            tx_manager,
            config: Default::default(),
            metrics: CheckpointExecutorMetrics::new_for_tests(),
        }
    }

    pub async fn run_epoch(&mut self, epoch_store: Arc<AuthorityPerEpochStore>) -> Committee {
        self.metrics
            .checkpoint_exec_epoch
            .set(epoch_store.epoch() as i64);

        // Decide the first checkpoint to schedule for execution.
        // If we haven't executed anything in the past, we schedule checkpoint 0.
        // Otherwise we schedule the one after highest executed.
        let mut highest_executed = self
            .checkpoint_store
            .get_highest_executed_checkpoint()
            .unwrap();
        let mut next_to_schedule = highest_executed
            .as_ref()
            .map(|c| c.sequence_number() + 1)
            .unwrap_or_default();
        let mut pending: CheckpointExecutionBuffer = FuturesOrdered::new();
        // Indicates whether we have scheduled all checkpoints in the epoch. If so, we stop
        // scheduling more.
        let mut no_more_scheduling = false;
        loop {
            // If we have executed the last checkpoint of the current epoch, stop.
            if let Some(next_epoch_committee) =
                check_epoch_last_checkpoint(epoch_store.epoch(), &highest_executed)
            {
                // be extra careful to ensure we don't have orphans
                assert!(
                    pending.is_empty(),
                    "Pending checkpoint execution buffer should be empty after processing last checkpoint of epoch",
                );
                return next_epoch_committee;
            }
            if !no_more_scheduling {
                no_more_scheduling = self.schedule_synced_checkpoints(
                    &mut pending,
                    // next_to_schedule will be updated to the next checkpoint to schedule.
                    // This makes sure we don't re-schedule the same checkpoint multiple times.
                    &mut next_to_schedule,
                    epoch_store.clone(),
                );
            }
            tokio::select! {
                // Check for completed workers and ratchet the highest_checkpoint_executed
                // watermark accordingly. Note that given that checkpoints are guaranteed to
                // be processed (added to FuturesOrdered) in seq_number order, using FuturesOrdered
                // guarantees that we will also ratchet the watermarks in order.
                Some(Ok(checkpoint)) = pending.next() => {
                    self.finished_executing_checkpoint(&checkpoint);
                    highest_executed = Some(checkpoint);
                }
                // Check for newly synced checkpoints from StateSync.
                received = self.mailbox.recv() => self.checkpoint_received(received),
            }
        }
    }

    fn finished_executing_checkpoint(&self, checkpoint: &VerifiedCheckpoint) {
        // Ensure that we are not skipping checkpoints at any point
        let seq = checkpoint.sequence_number();
        if let Some(prev_highest) = self
            .checkpoint_store
            .get_highest_executed_checkpoint_seq_number()
            .unwrap()
        {
            assert_eq!(prev_highest + 1, seq);
        } else {
            assert_eq!(seq, 0);
        }
        debug!("Bumping highest_executed_checkpoint watermark to {:?}", seq,);

        self.checkpoint_store
            .update_highest_executed_checkpoint(checkpoint)
            .unwrap();
        self.metrics.last_executed_checkpoint.set(seq as i64);
    }

    fn checkpoint_received(&self, received: Result<VerifiedCheckpoint, RecvError>) {
        match received {
            Ok(checkpoint) => {
                debug!(
                    "Received new synced checkpoint message for checkpoint {:?}",
                    checkpoint.sequence_number(),
                );
            }
            // In this case, messages in the mailbox have been overwritten
            // as a result of lagging too far behind.
            Err(RecvError::Lagged(num_skipped)) => {
                debug!(
                    "Checkpoint Execution Recv channel overflowed {:?} messages",
                    num_skipped,
                );
                self.metrics
                    .checkpoint_exec_recv_channel_overflow
                    .inc_by(num_skipped);
            }
            Err(RecvError::Closed) => {
                panic!("Checkpoint Execution Sender (StateSync) closed channel unexpectedly");
            }
        }
    }

    /// Returns whether we have scheduled the last checkpoint of the epoch.
    fn schedule_synced_checkpoints(
        &mut self,
        pending: &mut CheckpointExecutionBuffer,
        next_to_schedule: &mut CheckpointSequenceNumber,
        epoch_store: Arc<AuthorityPerEpochStore>,
    ) -> bool {
        let Some(latest_synced_checkpoint) = self
            .checkpoint_store
            .get_highest_synced_checkpoint()
            .expect("Failed to read highest synced checkpoint") else {
            return false;
        };

        while *next_to_schedule <= latest_synced_checkpoint.sequence_number()
            && pending.len() < self.config.checkpoint_execution_max_concurrency
        {
            let checkpoint = self
                .checkpoint_store
                .get_checkpoint_by_sequence_number(*next_to_schedule)
                .unwrap()
                .unwrap_or_else(|| {
                    panic!(
                        "Checkpoint sequence number {:?} does not exist in checkpoint store",
                        *next_to_schedule
                    )
                });
            if checkpoint.epoch() > epoch_store.epoch() {
                return true;
            }

            self.schedule_checkpoint(checkpoint, pending, epoch_store.clone());
            *next_to_schedule += 1;
        }

        false
    }

    fn schedule_checkpoint(
        &mut self,
        checkpoint: VerifiedCheckpoint,
        pending: &mut CheckpointExecutionBuffer,
        epoch_store: Arc<AuthorityPerEpochStore>,
    ) {
        debug!(
            "Scheduling checkpoint {:?} for execution",
            checkpoint.sequence_number()
        );
        // Mismatch between node epoch and checkpoint epoch after startup
        // crash recovery is invalid
        let checkpoint_epoch = checkpoint.epoch();
        assert_eq!(
            checkpoint_epoch,
            epoch_store.epoch(),
            "Epoch mismatch after startup recovery. checkpoint epoch: {:?}, node epoch: {:?}",
            checkpoint_epoch,
            epoch_store.epoch(),
        );

        // Record checkpoint participation for tallying rule.
        epoch_store
            .record_certified_checkpoint_signatures(checkpoint.inner())
            .unwrap();

        let metrics = self.metrics.clone();
        let local_execution_timeout_sec = self.config.local_execution_timeout_sec;
        let authority_store = self.authority_store.clone();
        let checkpoint_store = self.checkpoint_store.clone();
        let tx_manager = self.tx_manager.clone();

        pending.push_back(spawn_monitored_task!(async move {
            while let Err(err) = execute_checkpoint(
                checkpoint.clone(),
                authority_store.clone(),
                checkpoint_store.clone(),
                epoch_store.clone(),
                tx_manager.clone(),
                local_execution_timeout_sec,
                &metrics,
            )
            .await
            {
                error!(
                    "Error while executing checkpoint, will retry in 1s: {:?}",
                    err
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                metrics.checkpoint_exec_errors.inc();
            }

            checkpoint
        }));
    }
}

fn check_epoch_last_checkpoint(
    cur_epoch: EpochId,
    checkpoint: &Option<VerifiedCheckpoint>,
) -> Option<Committee> {
    if let Some(checkpoint) = checkpoint {
        if checkpoint.epoch() == cur_epoch {
            if let Some(next_committee) = checkpoint.summary.next_epoch_committee.clone() {
                info!(
                    ended_epoch = cur_epoch,
                    last_checkpoint = checkpoint.sequence_number(),
                    "Reached end of epoch",
                );
                let next_epoch = cur_epoch + 1;
                return Some(
                    Committee::new(next_epoch, next_committee.into_iter().collect())
                        .expect("Creating new committee object cannot fail"),
                );
            }
        }
    }
    None
}

#[instrument(level = "error", skip_all, fields(seq = ?checkpoint.sequence_number(), epoch = ?epoch_store.epoch()))]
pub async fn execute_checkpoint(
    checkpoint: VerifiedCheckpoint,
    authority_store: Arc<AuthorityStore>,
    checkpoint_store: Arc<CheckpointStore>,
    epoch_store: Arc<AuthorityPerEpochStore>,
    transaction_manager: Arc<TransactionManager>,
    local_execution_timeout_sec: u64,
    metrics: &Arc<CheckpointExecutorMetrics>,
) -> SuiResult {
    debug!(
        "Scheduling checkpoint {:?} for execution",
        checkpoint.sequence_number(),
    );
    let txes = checkpoint_store
        .get_checkpoint_contents(&checkpoint.content_digest())?
        .unwrap_or_else(|| {
            panic!(
                "Checkpoint contents for digest {:?} does not exist",
                checkpoint.content_digest()
            )
        })
        .into_inner();

    let tx_count = txes.len();
    debug!(
        epoch=?epoch_store.epoch(),
        checkpoint_sequence=?checkpoint.sequence_number(),
        "Number of transactions in the checkpoint: {:?}",
        tx_count
    );
    metrics.checkpoint_transaction_count.report(tx_count as u64);

    execute_transactions(
        txes,
        authority_store,
        epoch_store,
        transaction_manager,
        local_execution_timeout_sec,
        checkpoint.sequence_number(),
    )
    .await
}

async fn execute_transactions(
    execution_digests: Vec<ExecutionDigests>,
    authority_store: Arc<AuthorityStore>,
    epoch_store: Arc<AuthorityPerEpochStore>,
    transaction_manager: Arc<TransactionManager>,
    log_timeout_sec: u64,
    checkpoint_sequence: CheckpointSequenceNumber,
) -> SuiResult {
    let all_tx_digests: Vec<TransactionDigest> =
        execution_digests.iter().map(|tx| tx.transaction).collect();

    let synced_txns: Vec<VerifiedCertificate> = authority_store
        .perpetual_tables
        .synced_transactions
        .multi_get(&all_tx_digests)?
        .into_iter()
        .flatten()
        .map(|tx| tx.into())
        .collect();

    let effects_digests: Vec<TransactionEffectsDigest> = execution_digests
        .iter()
        .map(|digest| digest.effects)
        .collect();
    let digest_to_effects: HashMap<TransactionDigest, TransactionEffects> = authority_store
        .perpetual_tables
        .effects
        .multi_get(effects_digests)?
        .into_iter()
        .map(|fx| {
            if fx.is_none() {
                panic!("Transaction effects do not exist in effects table");
            }
            let fx = fx.unwrap();
            (fx.transaction_digest, fx)
        })
        .collect();

    for tx in synced_txns.clone() {
        if tx.contains_shared_object() {
            epoch_store
                .acquire_shared_locks_from_effects(
                    &tx,
                    digest_to_effects.get(tx.digest()).unwrap(),
                    &authority_store,
                )
                .await?;
        }
    }
    epoch_store.insert_pending_certificates(&synced_txns)?;

    transaction_manager.enqueue(synced_txns, &epoch_store)?;

    // Once synced_txns have been awaited, all txns should have effects committed.
    let mut periods = 1;
    let log_timeout_sec = Duration::from_secs(log_timeout_sec);

    loop {
        let effects_future = authority_store.notify_read_effects(all_tx_digests.clone());

        match timeout(log_timeout_sec, effects_future).await {
            Err(_elapsed) => {
                let missing_digests: Vec<TransactionDigest> =
                    EffectsStore::get_effects(&authority_store, all_tx_digests.clone().iter())
                        .expect("Failed to get effects")
                        .iter()
                        .zip(all_tx_digests.clone())
                        .filter_map(
                            |(fx, digest)| {
                                if fx.is_none() {
                                    Some(digest)
                                } else {
                                    None
                                }
                            },
                        )
                        .collect();

                warn!(
                    "Transaction effects for tx digests {:?} checkpoint not present within {:?}. ",
                    missing_digests,
                    log_timeout_sec * periods,
                );
                periods += 1;
            }
            Ok(Err(err)) => return Err(err),
            Ok(Ok(_)) => {
                authority_store.insert_executed_transactions(
                    &all_tx_digests,
                    epoch_store.epoch(),
                    checkpoint_sequence,
                )?;
                return Ok(());
            }
        }
    }
}
