// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use move_binary_format::CompiledModule;
use move_bytecode_utils::module_cache::GetModule;
use std::sync::Arc;

use sui_types::base_types::{ObjectID, SequenceNumber};
use sui_types::object::ObjectRead;

use crate::errors::IndexerError;
use crate::handlers::{EpochToCommit, TransactionObjectChangesToCommit};
use crate::metrics::IndexerMetrics;

use crate::types_v2::{
    IndexedCheckpoint, IndexedEvent, IndexedPackage, IndexedTransaction, TxIndex,
};

#[async_trait]
pub trait IndexerStoreV2 {
    type ModuleCache: GetModule<Item = Arc<CompiledModule>, Error = anyhow::Error>
        + Send
        + Sync
        + 'static;

    async fn get_latest_tx_checkpoint_sequence_number(&self) -> Result<Option<u64>, IndexerError>;

    async fn get_object_read(
        &self,
        object_id: ObjectID,
        version: Option<SequenceNumber>,
    ) -> Result<ObjectRead, IndexerError>;

    async fn persist_objects(
        &self,
        object_changes: Vec<TransactionObjectChangesToCommit>,
        metrics: IndexerMetrics,
    ) -> Result<(), IndexerError>;

    async fn persist_checkpoints(
        &self,
        checkpoints: Vec<IndexedCheckpoint>,
        metrics: IndexerMetrics,
    ) -> Result<(), IndexerError>;

    async fn persist_transactions(
        &self,
        transactions: Vec<IndexedTransaction>,
        metrics: IndexerMetrics,
    ) -> Result<(), IndexerError>;

    async fn persist_tx_indices(
        &self,
        indices: Vec<TxIndex>,
        metrics: IndexerMetrics,
    ) -> Result<(), IndexerError>;

    async fn persist_events(
        &self,
        events: Vec<IndexedEvent>,
        metrics: IndexerMetrics,
    ) -> Result<(), IndexerError>;

    async fn persist_packages(
        &self,
        packages: Vec<IndexedPackage>,
        metrics: IndexerMetrics,
    ) -> Result<(), IndexerError>;

    async fn persist_epoch(
        &self,
        data: Vec<EpochToCommit>,
        metrics: IndexerMetrics,
    ) -> Result<(), IndexerError>;

    async fn get_network_total_transactions_by_end_of_epoch(
        &self,
        epoch: u64,
    ) -> Result<u64, IndexerError>;

    fn module_cache(&self) -> Arc<Self::ModuleCache>;
}
