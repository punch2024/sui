// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//! This module implements the [Rosetta Account API](https://www.rosetta-api.org/docs/AccountApi.html)

use std::thread;

use axum::extract::State;
use axum::{Extension, Json};
use axum_extra::extract::WithRejection;
use futures::StreamExt;

use sui_sdk::rpc_types::StakeStatus;
use sui_sdk::{SuiClient, SUI_COIN_TYPE};
use sui_types::base_types::SuiAddress;
use tracing::info;

use crate::errors::Error;
use crate::types::{
    AccountBalanceRequest, AccountBalanceResponse, AccountCoinsRequest, AccountCoinsResponse,
    Amount, BlockIdentifier, Coin, SubAccount, SubAccountType, SubBalance,
};
use crate::{OnlineServerContext, SuiEnv};
use std::time::Duration;

/// Get an array of all AccountBalances for an AccountIdentifier and the BlockIdentifier
/// at which the balance lookup was performed.
/// [Rosetta API Spec](https://www.rosetta-api.org/docs/AccountApi.html#accountbalance)
pub async fn balance(
    State(ctx): State<OnlineServerContext>,
    Extension(env): Extension<SuiEnv>,
    WithRejection(Json(request), _): WithRejection<Json<AccountBalanceRequest>, Error>,
) -> Result<AccountBalanceResponse, Error> {
    env.check_network_identifier(&request.network_identifier)?;
    let address = request.account_identifier.address;
    if let Some(SubAccount { account_type }) = request.account_identifier.sub_account {
        let balances = get_sub_account_balances(account_type, &ctx.client, address).await?;
        Ok(AccountBalanceResponse {
            block_identifier: ctx.blocks().current_block_identifier().await?,
            balances,
        })
    } else {
        let block_identifier = if let Some(index) = request.block_identifier.index {
            let response = ctx.blocks().get_block_by_index(index).await?;
            response.block.block_identifier
        } else if let Some(hash) = request.block_identifier.hash {
            let response = ctx.blocks().get_block_by_hash(hash).await?;
            response.block.block_identifier
        } else {
            ctx.blocks().current_block_identifier().await?
        };

        ctx.blocks()
            .get_balance_at_block(address, block_identifier.index)
            .await
            .map(|balance| AccountBalanceResponse {
                block_identifier,
                balances: vec![Amount::new(balance)],
            })
    }
}

pub async fn balance_new(
    State(ctx): State<OnlineServerContext>,
    Extension(env): Extension<SuiEnv>,
    WithRejection(Json(request), _): WithRejection<Json<AccountBalanceRequest>, Error>,
) -> Result<AccountBalanceResponse, Error> {
    env.check_network_identifier(&request.network_identifier)?;
    let address = request.account_identifier.address;
    if let Some(SubAccount { account_type }) = request.account_identifier.sub_account {
        let balances_first =
            get_sub_account_balances(account_type.clone(), &ctx.client, address).await?;
        let checkpoint1 = ctx
            .client
            .read_api()
            .get_latest_checkpoint_sequence_number()
            .await?;
        // Get another checkpoint which is greater than current
        let mut checkpoint2 = ctx
            .client
            .read_api()
            .get_latest_checkpoint_sequence_number()
            .await?;

        while checkpoint2 <= checkpoint1 {
            checkpoint2 = ctx
                .client
                .read_api()
                .get_latest_checkpoint_sequence_number()
                .await?;
            thread::sleep(Duration::from_secs(1))
        }
        let balances_second = get_sub_account_balances(account_type, &ctx.client, address).await?;
        if balances_first.eq(&balances_second) {
            Ok(AccountBalanceResponse {
                block_identifier: ctx.blocks().create_block_identifier(checkpoint2).await?,
                balances: balances_first,
            })
        } else {
            // retry logic needs to be aaded
            Ok(AccountBalanceResponse {
                block_identifier: ctx.blocks().create_block_identifier(checkpoint2).await?,
                balances: balances_first,
            })
        }
    } else {
        // Get current live balance
        let balances_first = ctx
            .client
            .coin_read_api()
            .get_balance(address, Some(SUI_COIN_TYPE.to_string()))
            .await?
            .total_balance as i128;

        // Get current latest checkpoint
        let checkpoint1 = ctx
            .client
            .read_api()
            .get_latest_checkpoint_sequence_number()
            .await?;

        // Get another checkpoint which is greater than current
        let mut checkpoint2 = ctx
            .client
            .read_api()
            .get_latest_checkpoint_sequence_number()
            .await?;

        while checkpoint2 <= checkpoint1 {
            checkpoint2 = ctx
                .client
                .read_api()
                .get_latest_checkpoint_sequence_number()
                .await?;
            thread::sleep(Duration::from_secs(1))
        }

        // Get live balance again
        let balances_second = ctx
            .client
            .coin_read_api()
            .get_balance(address, Some(SUI_COIN_TYPE.to_string()))
            .await?
            .total_balance as i128;

        // if those two live balances are equal then that is the current balance for checkpoint2
        if balances_first.eq(&balances_second) {
            info!(
                "same balance for account {} at checkpoint {}",
                address, checkpoint2
            );
            Ok(AccountBalanceResponse {
                block_identifier: ctx.blocks().create_block_identifier(checkpoint2).await?,
                balances: vec![Amount::new(balances_first)],
            })
        } else {
            // balances are different so we need to try again.
            info!(
                "different balance for account {} at checkpoint {}",
                address, checkpoint2
            );
            // retry logic needs to be aaded
            Ok(AccountBalanceResponse {
                block_identifier: ctx.blocks().create_block_identifier(checkpoint2).await?,
                balances: vec![Amount::new(balances_first)],
            })
        }
    }
}

async fn get_sub_account_balances(
    account_type: SubAccountType,
    client: &SuiClient,
    address: SuiAddress,
) -> Result<Vec<Amount>, Error> {
    let amounts = match account_type {
        SubAccountType::Stake => {
            let delegations = client.governance_api().get_stakes(address).await?;
            delegations.into_iter().fold(vec![], |mut amounts, stakes| {
                for stake in &stakes.stakes {
                    if let StakeStatus::Active { .. } = stake.status {
                        amounts.push(SubBalance {
                            stake_id: stake.staked_sui_id,
                            validator: stakes.validator_address,
                            value: stake.principal as i128,
                        });
                    }
                }
                amounts
            })
        }
        SubAccountType::PendingStake => {
            let delegations = client.governance_api().get_stakes(address).await?;
            delegations.into_iter().fold(vec![], |mut amounts, stakes| {
                for stake in &stakes.stakes {
                    if let StakeStatus::Pending = stake.status {
                        amounts.push(SubBalance {
                            stake_id: stake.staked_sui_id,
                            validator: stakes.validator_address,
                            value: stake.principal as i128,
                        });
                    }
                }
                amounts
            })
        }

        SubAccountType::EstimatedReward => {
            let delegations = client.governance_api().get_stakes(address).await?;
            delegations.into_iter().fold(vec![], |mut amounts, stakes| {
                for stake in &stakes.stakes {
                    if let StakeStatus::Active { estimated_reward } = stake.status {
                        amounts.push(SubBalance {
                            stake_id: stake.staked_sui_id,
                            validator: stakes.validator_address,
                            value: estimated_reward as i128,
                        });
                    }
                }
                amounts
            })
        }
    };

    // Make sure there are always one amount returned
    Ok(if amounts.is_empty() {
        vec![Amount::new(0)]
    } else {
        vec![Amount::new_from_sub_balances(amounts)]
    })
}

/// Get an array of all unspent coins for an AccountIdentifier and the BlockIdentifier at which the lookup was performed. .
/// [Rosetta API Spec](https://www.rosetta-api.org/docs/AccountApi.html#accountcoins)
pub async fn coins(
    State(context): State<OnlineServerContext>,
    Extension(env): Extension<SuiEnv>,
    WithRejection(Json(request), _): WithRejection<Json<AccountCoinsRequest>, Error>,
) -> Result<AccountCoinsResponse, Error> {
    env.check_network_identifier(&request.network_identifier)?;
    let coins = context
        .client
        .coin_read_api()
        .get_coins_stream(
            request.account_identifier.address,
            Some(SUI_COIN_TYPE.to_string()),
        )
        .map(Coin::from)
        .collect()
        .await;

    Ok(AccountCoinsResponse {
        block_identifier: context.blocks().current_block_identifier().await?,
        coins,
    })
}
