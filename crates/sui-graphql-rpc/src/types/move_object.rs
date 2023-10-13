// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::big_int::BigInt;
use super::move_value::MoveValue;
use super::{coin::Coin, object::Object};
use crate::context_data::db_data_provider::PgManager;
use crate::types::stake::Stake;
use async_graphql::Error;
use async_graphql::*;
use move_bytecode_utils::layout::TypeLayoutBuilder;
use move_core_types::language_storage::TypeTag;
use sui_types::governance::StakedSui;
use sui_types::object::Object as NativeSuiObject;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MoveObject {
    pub native_object: NativeSuiObject,
}

#[allow(unreachable_code)]
#[allow(unused_variables)]
#[Object]
impl MoveObject {
    // TODO: This depends on having a module resolver so make more efficient
    async fn contents(&self, ctx: &Context<'_>) -> Result<Option<MoveValue>, Error> {
        let resolver = ctx.data_unchecked::<PgManager>();

        if let Some(struct_tag) = self.native_object.data.struct_tag() {
            let type_tag = TypeTag::Struct(Box::new(struct_tag));
            let type_layout = TypeLayoutBuilder::build_with_types(&type_tag, &resolver.inner)
                .map_err(|e| Error::new(e.to_string()))?;

            return Ok(Some(MoveValue::new(
                type_layout,
                self.native_object
                    .data
                    .try_as_move()
                    .unwrap()
                    .contents()
                    .into(),
            )));
        }

        Ok(None)
    }

    async fn has_public_transfer(&self) -> Option<bool> {
        self.native_object
            .data
            .try_as_move()
            .map(|x| x.has_public_transfer())
    }

    async fn as_object(&self) -> Option<Object> {
        Some(Object::from(&self.native_object))
    }

    async fn as_coin(&self) -> Option<Coin> {
        self.native_object.data.try_as_move().and_then(|x| {
            if x.is_coin() {
                Some(Coin {
                    id: ID::from(self.native_object.id().to_string()),
                    move_obj: self.clone(),
                    balance: None, // Defer to resolver
                })
            } else {
                None
            }
        })
    }

    // TODO implement this properly, it is missing status
    async fn as_stake(&self) -> Option<Stake> {
        let stake_object = StakedSui::try_from(&self.native_object);

        if let Ok(stake) = stake_object {
            Some(Stake {
                active_epoch_id: Some(stake.activation_epoch()),
                estimated_reward: None,
                principal: Some(BigInt::from(stake.principal())),
                request_epoch_id: Some(stake.activation_epoch() - 1),
                status: None,
                staked_sui_id: stake.id(),
            })
        } else {
            None
        }
    }
}
