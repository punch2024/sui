// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use move_binary_format::CompiledModule;
use move_bytecode_utils::module_cache::GetModule;
use move_core_types::{language_storage::ModuleId, resolver::ModuleResolver};
use simulacrum::Simulacrum;
use std::num::NonZeroUsize;
use sui_config::genesis;
use sui_protocol_config::ProtocolVersion;
use sui_swarm_config::genesis_config::AccountConfig;
use sui_swarm_config::network_config_builder::ConfigBuilder;
use sui_types::{
    base_types::{ObjectID, SequenceNumber, SuiAddress},
    committee::{Committee, EpochId},
    digests::{ObjectDigest, TransactionDigest, TransactionEventsDigest},
    effects::{TransactionEffects, TransactionEffectsAPI, TransactionEvents},
    error::SuiError,
    messages_checkpoint::{
        CheckpointContents, CheckpointContentsDigest, CheckpointDigest, CheckpointSequenceNumber,
        VerifiedCheckpoint,
    },
    object::{Object, Owner},
    storage::{
        load_package_object_from_object_store, BackingPackageStore, ChildObjectResolver,
        ObjectStore, PackageObjectArc, ParentSync,
    },
    transaction::VerifiedTransaction,
};
use tempfile::tempdir;
use typed_store::traits::TableSummary;
use typed_store::traits::TypedStoreDebug;
use typed_store::Map;
use typed_store::{
    metrics::SamplingInterval,
    rocks::{DBMap, MetricConf},
};
use typed_store_derive::DBMapUtils;

use super::SimulatorStore;

#[derive(Debug, DBMapUtils)]
pub struct PersistedStore {
    // Checkpoint data
    checkpoints: DBMap<CheckpointSequenceNumber, sui_types::messages_checkpoint::TrustedCheckpoint>,
    checkpoint_digest_to_sequence_number: DBMap<CheckpointDigest, CheckpointSequenceNumber>,
    checkpoint_contents: DBMap<CheckpointContentsDigest, CheckpointContents>,

    // Transaction data
    transactions: DBMap<TransactionDigest, sui_types::transaction::TrustedTransaction>,
    effects: DBMap<TransactionDigest, TransactionEffects>,
    events: DBMap<TransactionEventsDigest, TransactionEvents>,
    events_tx_digest_index: DBMap<TransactionDigest, TransactionEventsDigest>,

    // Committee data
    epoch_to_committee: DBMap<(), Vec<Committee>>,

    // Object data
    live_objects: DBMap<ObjectID, SequenceNumber>,
    objects: DBMap<ObjectID, BTreeMap<SequenceNumber, Object>>,
}

impl PersistedStore {
    pub fn _new(genesis: &genesis::Genesis, path: Option<PathBuf>) -> Self {
        let path = path.unwrap_or(tempdir().unwrap().into_path());

        let mut store = Self::open_tables_read_write(
            path,
            MetricConf::with_sampling(SamplingInterval::new(Duration::from_secs(60), 0)),
            None,
            None,
        );

        store.init_with_genesis(genesis);
        store
    }

    pub fn _new_sim_with_protocol_version_and_accounts<R>(
        mut rng: R,
        chain_start_timestamp_ms: u64,
        protocol_version: ProtocolVersion,
        account_configs: Vec<AccountConfig>,
        path: Option<PathBuf>,
    ) -> Simulacrum<R, PersistedStore>
    where
        R: rand::RngCore + rand::CryptoRng,
    {
        let config = ConfigBuilder::new_with_temp_dir()
            .rng(&mut rng)
            .with_chain_start_timestamp_ms(chain_start_timestamp_ms)
            .deterministic_committee_size(NonZeroUsize::new(1).unwrap())
            .with_protocol_version(protocol_version)
            .with_accounts(account_configs)
            .build();
        let genesis = &config.genesis;
        let store = PersistedStore::_new(genesis, path);

        Simulacrum::new_with_network_config_store(&config, rng, store)
    }
}

impl SimulatorStore for PersistedStore {
    fn insert_to_live_objects(&mut self, objects: &[Object]) {
        for object in objects {
            let object_id = object.id();
            let version = object.version();
            self.live_objects
                .insert(&object_id, &version)
                .expect("Fatal: DB write failed");

            let mut o = if let Some(q) = self
                .objects
                .get(&object_id)
                .expect("Fatal: DB write failed")
            {
                q
            } else {
                BTreeMap::new()
            };
            o.insert(version, object.clone());
            self.objects
                .insert(&object_id, &o)
                .expect("Fatal: DB write failed");
        }
    }

    fn get_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Option<VerifiedCheckpoint> {
        self.checkpoints
            .get(&sequence_number)
            .expect("Fatal: DB read failed")
            .map(|checkpoint| checkpoint.into())
    }

    fn get_checkpoint_by_digest(&self, digest: &CheckpointDigest) -> Option<VerifiedCheckpoint> {
        self.checkpoint_digest_to_sequence_number
            .get(digest)
            .expect("Fatal: DB read failed")
            .and_then(|sequence_number| self.get_checkpoint_by_sequence_number(sequence_number))
    }

    fn get_highest_checkpint(&self) -> Option<VerifiedCheckpoint> {
        self.checkpoints
            .unbounded_iter()
            .skip_to_last()
            .next()
            .map(|(_, checkpoint)| checkpoint.into())
    }

    fn get_checkpoint_contents(
        &self,
        digest: &CheckpointContentsDigest,
    ) -> Option<CheckpointContents> {
        self.checkpoint_contents
            .get(digest)
            .expect("Fatal: DB read failed")
    }

    fn get_committee_by_epoch(&self, epoch: EpochId) -> Option<Committee> {
        self.epoch_to_committee
            .get(&())
            .expect("Fatal: DB read failed")
            .and_then(|committees| committees.get(epoch as usize).cloned())
    }

    fn get_transaction(&self, digest: &TransactionDigest) -> Option<VerifiedTransaction> {
        self.transactions
            .get(digest)
            .expect("Fatal: DB read failed")
            .map(|transaction| transaction.into())
    }

    fn get_transaction_effects(&self, digest: &TransactionDigest) -> Option<TransactionEffects> {
        self.effects.get(digest).expect("Fatal: DB read failed")
    }

    fn get_transaction_events(
        &self,
        digest: &TransactionEventsDigest,
    ) -> Option<TransactionEvents> {
        self.events.get(digest).expect("Fatal: DB read failed")
    }

    fn get_transaction_events_by_tx_digest(
        &self,
        tx_digest: &TransactionDigest,
    ) -> Option<TransactionEvents> {
        self.events_tx_digest_index
            .get(tx_digest)
            .expect("Fatal: DB read failed")
            .and_then(|x| self.events.get(&x).expect("Fatal: DB read failed"))
    }

    fn get_object(&self, id: &ObjectID) -> Option<Object> {
        let version = self.live_objects.get(id).expect("Fatal: DB read failed")?;
        self.get_object_at_version(id, version)
    }

    fn get_object_at_version(&self, id: &ObjectID, version: SequenceNumber) -> Option<Object> {
        self.objects
            .get(id)
            .expect("Fatal: DB read failed")
            .and_then(|versions| versions.get(&version).cloned())
    }

    fn get_system_state(&self) -> sui_types::sui_system_state::SuiSystemState {
        sui_types::sui_system_state::get_sui_system_state(self).expect("system state must exist")
    }

    fn get_clock(&self) -> sui_types::clock::Clock {
        SimulatorStore::get_object(self, &sui_types::SUI_CLOCK_OBJECT_ID)
            .expect("clock should exist")
            .to_rust()
            .expect("clock object should deserialize")
    }

    fn owned_objects(&self, owner: SuiAddress) -> Box<dyn Iterator<Item = Object> + '_> {
        Box::new(self.live_objects
            .unbounded_iter()
            .flat_map(|(id, version)| self.get_object_at_version(&id, version))
            .filter(
                move |object| matches!(object.owner, Owner::AddressOwner(addr) if addr == owner),
            ))
    }

    fn insert_checkpoint(&mut self, checkpoint: VerifiedCheckpoint) {
        self.checkpoint_digest_to_sequence_number
            .insert(checkpoint.digest(), checkpoint.sequence_number())
            .expect("Fatal: DB write failed");
        self.checkpoints
            .insert(checkpoint.sequence_number(), checkpoint.serializable_ref())
            .expect("Fatal: DB write failed");
    }

    fn insert_checkpoint_contents(&mut self, contents: CheckpointContents) {
        self.checkpoint_contents
            .insert(contents.digest(), &contents)
            .expect("Fatal: DB write failed");
    }

    fn insert_committee(&mut self, committee: Committee) {
        let epoch = committee.epoch as usize;

        let mut committees = if let Some(c) = self
            .epoch_to_committee
            .get(&())
            .expect("Fatal: DB read failed")
        {
            c
        } else {
            vec![]
        };

        if committees.get(epoch).is_some() {
            return;
        }

        if committees.len() == epoch {
            committees.push(committee);
        } else {
            panic!("committee was inserted into EpochCommitteeMap out of order");
        }
        self.epoch_to_committee
            .insert(&(), &committees)
            .expect("Fatal: DB write failed");
    }

    fn insert_executed_transaction(
        &mut self,
        transaction: VerifiedTransaction,
        effects: TransactionEffects,
        events: TransactionEvents,
        written_objects: BTreeMap<ObjectID, Object>,
    ) {
        let deleted_objects = effects.deleted();
        let tx_digest = *effects.transaction_digest();
        self.insert_transaction(transaction);
        self.insert_transaction_effects(effects);
        self.insert_events(&tx_digest, events);
        self.update_objects(written_objects, deleted_objects);
    }

    fn insert_transaction(&mut self, transaction: VerifiedTransaction) {
        self.transactions
            .insert(transaction.digest(), transaction.serializable_ref())
            .expect("Fatal: DB write failed");
    }

    fn insert_transaction_effects(&mut self, effects: TransactionEffects) {
        self.effects
            .insert(effects.transaction_digest(), &effects)
            .expect("Fatal: DB write failed");
    }

    fn insert_events(&mut self, tx_digest: &TransactionDigest, events: TransactionEvents) {
        self.events_tx_digest_index
            .insert(tx_digest, &events.digest())
            .expect("Fatal: DB write failed");
        self.events
            .insert(&events.digest(), &events)
            .expect("Fatal: DB write failed");
    }

    fn update_objects(
        &mut self,
        written_objects: BTreeMap<ObjectID, Object>,
        deleted_objects: Vec<(ObjectID, SequenceNumber, ObjectDigest)>,
    ) {
        for (object_id, _, _) in deleted_objects {
            self.live_objects
                .remove(&object_id)
                .expect("Fatal: DB write failed");
        }

        for (object_id, object) in written_objects {
            let version = object.version();
            self.live_objects
                .insert(&object_id, &version)
                .expect("Fatal: DB write failed");
            let mut q =
                if let Some(x) = self.objects.get(&object_id).expect("Fatal: DB read failed") {
                    x
                } else {
                    BTreeMap::new()
                };
            q.insert(version, object);
            self.objects
                .insert(&object_id, &q)
                .expect("Fatal: DB write failed");
        }
    }

    fn backing_store(&self) -> &dyn sui_types::storage::BackingStore {
        self
    }
}

impl BackingPackageStore for PersistedStore {
    fn get_package_object(
        &self,
        package_id: &ObjectID,
    ) -> sui_types::error::SuiResult<Option<PackageObjectArc>> {
        load_package_object_from_object_store(self, package_id)
    }
}

impl ChildObjectResolver for PersistedStore {
    fn read_child_object(
        &self,
        parent: &ObjectID,
        child: &ObjectID,
        child_version_upper_bound: SequenceNumber,
    ) -> sui_types::error::SuiResult<Option<Object>> {
        let child_object = match SimulatorStore::get_object(self, child) {
            None => return Ok(None),
            Some(obj) => obj,
        };

        let parent = *parent;
        if child_object.owner != Owner::ObjectOwner(parent.into()) {
            return Err(SuiError::InvalidChildObjectAccess {
                object: *child,
                given_parent: parent,
                actual_owner: child_object.owner,
            });
        }

        if child_object.version() > child_version_upper_bound {
            return Err(SuiError::UnsupportedFeatureError {
                error: "TODO InMemoryStorage::read_child_object does not yet support bounded reads"
                    .to_owned(),
            });
        }

        Ok(Some(child_object))
    }

    fn get_object_received_at_version(
        &self,
        owner: &ObjectID,
        receiving_object_id: &ObjectID,
        receive_object_at_version: SequenceNumber,
        _epoch_id: EpochId,
    ) -> sui_types::error::SuiResult<Option<Object>> {
        let recv_object = match SimulatorStore::get_object(self, receiving_object_id) {
            None => return Ok(None),
            Some(obj) => obj,
        };
        if recv_object.owner != Owner::AddressOwner((*owner).into()) {
            return Ok(None);
        }

        if recv_object.version() != receive_object_at_version {
            return Ok(None);
        }
        Ok(Some(recv_object))
    }
}

impl GetModule for PersistedStore {
    type Error = SuiError;
    type Item = CompiledModule;

    fn get_module_by_id(&self, id: &ModuleId) -> Result<Option<Self::Item>, Self::Error> {
        Ok(self
            .get_module(id)?
            .map(|bytes| CompiledModule::deserialize_with_defaults(&bytes).unwrap()))
    }
}

impl ModuleResolver for PersistedStore {
    type Error = SuiError;

    fn get_module(&self, module_id: &ModuleId) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self
            .get_package_object(&ObjectID::from(*module_id.address()))?
            .and_then(|package| {
                package
                    .move_package()
                    .serialized_module_map()
                    .get(module_id.name().as_str())
                    .cloned()
            }))
    }
}

impl ObjectStore for PersistedStore {
    fn get_object(
        &self,
        object_id: &ObjectID,
    ) -> Result<Option<Object>, sui_types::error::SuiError> {
        Ok(SimulatorStore::get_object(self, object_id))
    }

    fn get_object_by_key(
        &self,
        object_id: &ObjectID,
        version: sui_types::base_types::VersionNumber,
    ) -> Result<Option<Object>, sui_types::error::SuiError> {
        Ok(self.get_object_at_version(object_id, version))
    }
}

impl ParentSync for PersistedStore {
    fn get_latest_parent_entry_ref_deprecated(
        &self,
        _object_id: ObjectID,
    ) -> sui_types::error::SuiResult<Option<sui_types::base_types::ObjectRef>> {
        panic!("Never called in newer protocol versions")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[tokio::test]
    async fn deterministic_genesis() {
        let rng = StdRng::from_seed([9; 32]);
        let chain1 = PersistedStore::_new_sim_with_protocol_version_and_accounts(
            rng,
            0,
            ProtocolVersion::MAX,
            vec![],
            None,
        );
        let genesis_checkpoint_digest1 = *chain1
            .store()
            .get_checkpoint_by_sequence_number(0)
            .unwrap()
            .digest();

        let rng = StdRng::from_seed([9; 32]);
        let chain2 = PersistedStore::_new_sim_with_protocol_version_and_accounts(
            rng,
            0,
            ProtocolVersion::MAX,
            vec![],
            None,
        );
        let genesis_checkpoint_digest2 = *chain2
            .store()
            .get_checkpoint_by_sequence_number(0)
            .unwrap()
            .digest();

        assert_eq!(genesis_checkpoint_digest1, genesis_checkpoint_digest2);

        // Ensure the committees are different when using different seeds
        let rng = StdRng::from_seed([0; 32]);
        let chain3 = PersistedStore::_new_sim_with_protocol_version_and_accounts(
            rng,
            0,
            ProtocolVersion::MAX,
            vec![],
            None,
        );

        assert_ne!(
            chain1.store().get_committee_by_epoch(0),
            chain3.store().get_committee_by_epoch(0),
        );
    }
}
