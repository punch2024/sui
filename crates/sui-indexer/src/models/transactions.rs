// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use diesel::prelude::*;

use sui_json_rpc_types::{
<<<<<<< HEAD
    OwnedObjectRef, SuiObjectRef, SuiTransactionBlockDataAPI, SuiTransactionBlockEffectsAPI,
=======
    OwnedObjectRef, SuiObjectRef, SuiTransactionBlock, SuiTransactionBlockDataAPI,
    SuiTransactionBlockEffects, SuiTransactionBlockEffectsAPI,
>>>>>>> fork/testnet
};

use crate::errors::IndexerError;
use crate::schema::transactions;
<<<<<<< HEAD
use crate::types::TemporaryTransactionBlockResponseStore;
=======
use crate::schema::transactions::transaction_digest;
use crate::types::SuiTransactionBlockFullResponse;
use crate::PgPoolConnection;
>>>>>>> fork/testnet

#[derive(Clone, Debug, Queryable, Insertable)]
#[diesel(table_name = transactions)]
pub struct Transaction {
    #[diesel(deserialize_as = i64)]
    pub id: Option<i64>,
    pub transaction_digest: String,
    pub sender: String,
    pub recipients: Vec<Option<String>>,
    pub checkpoint_sequence_number: Option<i64>,
    pub timestamp_ms: Option<i64>,
    pub transaction_kind: String,
    pub transaction_count: i64,
    pub created: Vec<Option<String>>,
    pub mutated: Vec<Option<String>>,
    pub deleted: Vec<Option<String>>,
    pub unwrapped: Vec<Option<String>>,
    pub wrapped: Vec<Option<String>>,
    pub move_calls: Vec<Option<String>>,
    pub gas_object_id: String,
    pub gas_object_sequence: i64,
    pub gas_object_digest: String,
    pub gas_budget: i64,
    pub total_gas_cost: i64,
    pub computation_cost: i64,
    pub storage_cost: i64,
    pub storage_rebate: i64,
    pub non_refundable_storage_fee: i64,
    pub gas_price: i64,
    // BCS bytes of SenderSignedData
    pub raw_transaction: Vec<u8>,
    pub transaction_content: String,
    pub transaction_effects_content: String,
    pub confirmed_local_execution: Option<bool>,
}

<<<<<<< HEAD
impl TryFrom<TemporaryTransactionBlockResponseStore> for Transaction {
    type Error = IndexerError;

    fn try_from(tx_resp: TemporaryTransactionBlockResponseStore) -> Result<Self, Self::Error> {
        let TemporaryTransactionBlockResponseStore {
            digest,
            transaction,
            raw_transaction,
            effects,
            events: _,
            object_changes: _,
            balance_changes: _,
            timestamp_ms,
            confirmed_local_execution,
            checkpoint,
        } = tx_resp;

        let tx_json = serde_json::to_string(&transaction).map_err(|err| {
=======
pub fn commit_transactions(
    pg_pool_conn: &mut PgPoolConnection,
    tx_resps: Vec<SuiTransactionBlockFullResponse>,
) -> Result<usize, IndexerError> {
    let new_txs: Vec<Transaction> = tx_resps
        .into_iter()
        .map(|tx| tx.try_into())
        .collect::<Result<Vec<_>, _>>()?;

    let tx_commit_result: Result<usize, Error> = pg_pool_conn
        .build_transaction()
        .read_write()
        .run::<_, Error, _>(|conn| {
            diesel::insert_into(transactions::table)
                .values(&new_txs)
                .on_conflict(transaction_digest)
                .do_nothing()
                .execute(conn)
        });

    tx_commit_result.map_err(|e| {
        IndexerError::PostgresWriteError(format!(
            "Failed writing transactions to PostgresDB with transactions {:?} and error: {:?}",
            new_txs, e
        ))
    })
}

impl TryFrom<SuiTransactionBlockFullResponse> for Transaction {
    type Error = IndexerError;

    fn try_from(tx_resp: SuiTransactionBlockFullResponse) -> Result<Self, Self::Error> {
        let tx_json = serde_json::to_string(&tx_resp.transaction).map_err(|err| {
>>>>>>> fork/testnet
            IndexerError::InsertableParsingError(format!(
                "Failed converting transaction block {:?} to JSON with error: {:?}",
                transaction, err
            ))
        })?;
        let tx_effect_json = serde_json::to_string(&effects).map_err(|err| {
            IndexerError::InsertableParsingError(format!(
                "Failed converting transaction block effects {:?} to JSON with error: {:?}",
                effects.clone(),
                err
            ))
        })?;
<<<<<<< HEAD
=======

        let effects = tx_resp.effects;
        let transaction_data = tx_resp.transaction.data;
        // canonical tx digest string is Base58 encoded
        let tx_digest = effects.transaction_digest().base58_encode();
        let gas_budget = transaction_data.gas_data().budget;
        let gas_price = transaction_data.gas_data().price;
        let sender = transaction_data.sender().to_string();
        let checkpoint_seq_number = tx_resp.checkpoint as i64;
        let tx_kind = transaction_data.transaction().name().to_string();
        let transaction_count = transaction_data.transaction().transaction_count() as i64;

>>>>>>> fork/testnet
        let recipients: Vec<String> = effects
            .mutated()
            .iter()
            .cloned()
            .chain(effects.created().iter().cloned())
            .chain(effects.unwrapped().iter().cloned())
            .map(|owned_obj_ref| owned_obj_ref.owner.to_string())
            .collect();
        let created: Vec<String> = effects
            .created()
            .iter()
            .map(owned_obj_ref_to_obj_id)
            .collect();
        let mutated: Vec<String> = effects
            .mutated()
            .iter()
            .map(owned_obj_ref_to_obj_id)
            .collect();
        let unwrapped: Vec<String> = effects
            .unwrapped()
            .iter()
            .map(owned_obj_ref_to_obj_id)
            .collect();
        let deleted: Vec<String> = effects.deleted().iter().map(obj_ref_to_obj_id).collect();
        let wrapped: Vec<String> = effects.wrapped().iter().map(obj_ref_to_obj_id).collect();
        let move_call_strs: Vec<String> = transaction
            .data
            .move_calls()
            .into_iter()
            .map(|move_call| {
                let package = move_call.package.to_string();
                let module = move_call.module.to_string();
                let function = move_call.function.to_string();
                format!("{}::{}::{}", package, module, function)
            })
            .collect();

        let gas_summary = effects.gas_cost_summary();
        let computation_cost = gas_summary.computation_cost;
        let storage_cost = gas_summary.storage_cost;
        let storage_rebate = gas_summary.storage_rebate;
        let non_refundable_storage_fee = gas_summary.non_refundable_storage_fee;
        Ok(Transaction {
            id: None,
<<<<<<< HEAD
            transaction_digest: digest.base58_encode(),
            sender: transaction.data.sender().to_string(),
            recipients: vec_string_to_vec_opt(recipients),
            checkpoint_sequence_number: checkpoint.map(|seq| seq as i64),
            transaction_kind: transaction.data.transaction().name().to_string(),
            transaction_count: transaction.data.transaction().transaction_count() as i64,
            timestamp_ms: timestamp_ms.map(|ts| ts as i64),
            created: vec_string_to_vec_opt(created),
            mutated: vec_string_to_vec_opt(mutated),
            unwrapped: vec_string_to_vec_opt(unwrapped),
            deleted: vec_string_to_vec_opt(deleted),
            wrapped: vec_string_to_vec_opt(wrapped),
            move_calls: vec_string_to_vec_opt(move_call_strs),
            gas_object_id: effects.gas_object().reference.object_id.to_string(),
            gas_object_sequence: effects.gas_object().reference.version.value() as i64,
            gas_object_digest: effects.gas_object().reference.digest.base58_encode(),
=======
            transaction_digest: tx_digest,
            sender,
            recipients: vec_string_to_vec_opt_string(recipients),
            checkpoint_sequence_number: checkpoint_seq_number,
            transaction_kind: tx_kind,
            transaction_count,
            timestamp_ms: tx_resp.timestamp_ms as i64,
            created: vec_string_to_vec_opt_string(created),
            mutated: vec_string_to_vec_opt_string(mutated),
            unwrapped: vec_string_to_vec_opt_string(unwrapped),
            deleted: vec_string_to_vec_opt_string(deleted),
            wrapped: vec_string_to_vec_opt_string(wrapped),
            move_calls: vec_string_to_vec_opt_string(move_call_strs),
            gas_object_id,
            gas_object_sequence: gas_object_seq.value() as i64,
            gas_object_digest,
>>>>>>> fork/testnet
            // NOTE: cast u64 to i64 here is safe because
            // max value of i64 is 9223372036854775807 MISTs, which is 9223372036.85 SUI, which is way bigger than budget or cost constant already.
            gas_budget: transaction.data.gas_data().budget as i64,
            gas_price: transaction.data.gas_data().price as i64,
            total_gas_cost: (computation_cost + storage_cost) as i64 - (storage_rebate as i64),
            computation_cost: computation_cost as i64,
            storage_cost: storage_cost as i64,
            storage_rebate: storage_rebate as i64,
            non_refundable_storage_fee: non_refundable_storage_fee as i64,
            raw_transaction,
            transaction_content: tx_json,
            transaction_effects_content: tx_effect_json,
<<<<<<< HEAD
            confirmed_local_execution,
=======
            confirmed_local_execution: tx_resp.confirmed_local_execution,
        })
    }
}

impl TryInto<SuiTransactionBlockFullResponse> for Transaction {
    type Error = IndexerError;

    fn try_into(self) -> Result<SuiTransactionBlockFullResponse, Self::Error> {
        let transaction: SuiTransactionBlock =
            serde_json::from_str(&self.transaction_content).map_err(|err| {
                IndexerError::InsertableParsingError(format!(
                    "Failed converting transaction JSON {:?} to SuiTransactionBlock with error: {:?}",
                    self.transaction_content, err
                ))
            })?;
        let effects: SuiTransactionBlockEffects = serde_json::from_str(&self.transaction_effects_content).map_err(|err| {
            IndexerError::InsertableParsingError(format!(
                "Failed converting transaction effect JSON {:?} to SuiTransactionBlockEffects with error: {:?}",
                self.transaction_effects_content, err
            ))
        })?;

        Ok(SuiTransactionBlockFullResponse {
            digest: self.transaction_digest.parse().map_err(|e| {
                IndexerError::InsertableParsingError(format!(
                    "Failed to parse transaction digest {} : {:?}",
                    self.transaction_digest, e
                ))
            })?,
            transaction,
            raw_transaction: self.raw_transaction,
            effects,
            confirmed_local_execution: self.confirmed_local_execution,
            timestamp_ms: self.timestamp_ms as u64,
            checkpoint: self.checkpoint_sequence_number as u64,
            // TODO: read events, object_changes and balance_changes from db
            events: Default::default(),
            object_changes: Some(vec![]),
            balance_changes: Some(vec![]),
>>>>>>> fork/testnet
        })
    }
}

fn owned_obj_ref_to_obj_id(owned_obj_ref: &OwnedObjectRef) -> String {
    owned_obj_ref.reference.object_id.to_string()
}

fn obj_ref_to_obj_id(obj_ref: &SuiObjectRef) -> String {
    obj_ref.object_id.to_string()
}

fn vec_string_to_vec_opt(v: Vec<String>) -> Vec<Option<String>> {
    v.into_iter().map(Some).collect::<Vec<Option<String>>>()
}
