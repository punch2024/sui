// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::{DEFAULT_REQUEST_TIMEOUT_MS, DEFAULT_SERVER_DB_POOL_SIZE},
    error::Error,
    types::{address::Address, sui_address::SuiAddress, validator::Validator},
};
use diesel::PgConnection;
use std::{collections::BTreeMap, time::Duration};
use sui_indexer::db::ConnectionPoolConfig;
use sui_indexer::{apis::GovernanceReadApi, indexer_reader::IndexerReader};
use sui_json_rpc::governance_api::{calculate_apys, ValidatorExchangeRates};
use sui_json_rpc_types::Stake as RpcStakedSui;
use sui_types::{
    base_types::SuiAddress as NativeSuiAddress,
    governance::StakedSui as NativeStakedSui,
    sui_system_state::sui_system_state_summary::{
        SuiSystemStateSummary as NativeSuiSystemStateSummary, SuiValidatorSummary,
    },
};

use sui_indexer::apis::governance_api::exchange_rates;

pub(crate) struct PgManager {
    pub inner: IndexerReader<PgConnection>,
}

impl PgManager {
    pub(crate) fn new(inner: IndexerReader<PgConnection>) -> Self {
        Self { inner }
    }

    /// Create a new underlying reader, which is used by this type as well as other data providers.
    pub(crate) fn reader(db_url: impl Into<String>) -> Result<IndexerReader<PgConnection>, Error> {
        Self::reader_with_config(
            db_url,
            DEFAULT_SERVER_DB_POOL_SIZE,
            DEFAULT_REQUEST_TIMEOUT_MS,
        )
    }

    pub(crate) fn reader_with_config(
        db_url: impl Into<String>,
        pool_size: u32,
        timeout_ms: u64,
    ) -> Result<IndexerReader<PgConnection>, Error> {
        let mut config = ConnectionPoolConfig::default();
        config.set_pool_size(pool_size);
        config.set_statement_timeout(Duration::from_millis(timeout_ms));
        IndexerReader::<PgConnection>::new_with_config(db_url, config)
            .map_err(|e| Error::Internal(format!("Failed to create reader: {e}")))
    }
}

/// Implement methods to be used by graphql resolvers
impl PgManager {
    /// Retrieve the validator APYs
    pub(crate) async fn fetch_validator_apys(
        &self,
        latest_sui_system_state: &NativeSuiSystemStateSummary,
        epoch_id: Option<u64>,
        address: &NativeSuiAddress,
    ) -> Result<Option<f64>, Error> {
        let stake_subsidy_start_epoch = latest_sui_system_state.stake_subsidy_start_epoch;
        let exchange_rates = self.fetch_exchange_rates(latest_sui_system_state).await?;
        let validator_exchange_rates = exchange_rates.iter().find(|x| x.address == *address);
        if let Some(validator_exchange_rates) = validator_exchange_rates {
            // find the rates up to that epoch, if the epoch is specified
            let mut rates_to_use = validator_exchange_rates.rates.clone();
            if let Some(epoch) = epoch_id {
                rates_to_use.retain(|x| x.0 <= epoch);
            }
            // build the ValidatorExchangeRates type needed to pass to calculate_apys function
            let validator_exchange_rates_to_use = ValidatorExchangeRates {
                address: *address,
                pool_id: validator_exchange_rates.pool_id,
                active: true,
                rates: rates_to_use,
            };
            let apys = calculate_apys(
                stake_subsidy_start_epoch,
                vec![validator_exchange_rates_to_use],
            );
            Ok(apys.iter().find(|x| x.address == *address).map(|x| x.apy))
        } else {
            Ok(None)
        }
    }

    pub(crate) async fn fetch_exchange_rates(
        &self,
        system_state: &NativeSuiSystemStateSummary,
    ) -> Result<Vec<ValidatorExchangeRates>, Error> {
        let governance_api = GovernanceReadApi::new(self.inner.clone());
        exchange_rates(&governance_api, system_state)
            .await
            .map_err(|e| Error::Internal(format!("Error fetching exchange rates. {e}")))
    }

    /// If no epoch was requested or if the epoch requested is in progress,
    /// returns the latest sui system state.
    pub(crate) async fn fetch_sui_system_state(
        &self,
        epoch_id: Option<u64>,
    ) -> Result<NativeSuiSystemStateSummary, Error> {
        let latest_sui_system_state = self
            .inner
            .spawn_blocking(move |this| this.get_latest_sui_system_state())
            .await?;

        match epoch_id {
            Some(epoch_id) if epoch_id == latest_sui_system_state.epoch => {
                Ok(latest_sui_system_state)
            }
            Some(epoch_id) => Ok(self
                .inner
                .spawn_blocking(move |this| this.get_epoch_sui_system_state(Some(epoch_id)))
                .await?),
            None => Ok(latest_sui_system_state),
        }
    }

    /// Make a request to the RPC for its representations of the staked sui we parsed out of the
    /// object.  Used to implement fields that are implemented in JSON-RPC but not GraphQL (yet).
    pub(crate) async fn fetch_rpc_staked_sui(
        &self,
        stake: NativeStakedSui,
    ) -> Result<RpcStakedSui, Error> {
        let governance_api = GovernanceReadApi::new(self.inner.clone());

        let mut delegated_stakes = governance_api
            .get_delegated_stakes(vec![stake])
            .await
            .map_err(|e| Error::Internal(format!("Error fetching delegated stake. {e}")))?;

        let Some(mut delegated_stake) = delegated_stakes.pop() else {
            return Err(Error::Internal(
                "Error fetching delegated stake. No pools returned.".to_string(),
            ));
        };

        let Some(stake) = delegated_stake.stakes.pop() else {
            return Err(Error::Internal(
                "Error fetching delegated stake. No stake in pool.".to_string(),
            ));
        };

        Ok(stake)
    }
}

/// `checkpoint_viewed_at` represents the checkpoint sequence number at which the set of
/// `SuiValidatorSummary` was queried for. Each `Validator` will inherit this checkpoint, so that
/// when viewing the `Validator`'s state, it will be as if it was read at the same checkpoint.
pub(crate) fn convert_to_validators(
    validators: Vec<SuiValidatorSummary>,
    // we need this for exchange rates call to governance api in indexer
    latest_sui_system_state: NativeSuiSystemStateSummary,
    system_state_at_requested_epoch: Option<NativeSuiSystemStateSummary>,
    checkpoint_viewed_at: u64,
    requested_for_epoch: Option<u64>,
) -> Vec<Validator> {
    let (at_risk, reports) = if let Some(NativeSuiSystemStateSummary {
        at_risk_validators,
        validator_report_records,
        ..
    }) = system_state_at_requested_epoch
    {
        (
            BTreeMap::from_iter(at_risk_validators),
            BTreeMap::from_iter(validator_report_records),
        )
    } else {
        Default::default()
    };

    validators
        .into_iter()
        .map(move |validator_summary| {
            let at_risk = at_risk.get(&validator_summary.sui_address).copied();
            let report_records = reports.get(&validator_summary.sui_address).map(|addrs| {
                addrs
                    .iter()
                    .cloned()
                    .map(|a| Address {
                        address: SuiAddress::from(a),
                        checkpoint_viewed_at,
                    })
                    .collect()
            });

            Validator {
                validator_summary,
                at_risk,
                report_records,
                checkpoint_viewed_at,
                requested_for_epoch,
                latest_sui_system_state: latest_sui_system_state.clone(),
            }
        })
        .collect()
}
