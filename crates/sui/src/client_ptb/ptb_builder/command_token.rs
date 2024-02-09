// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::bail;
use std::{
    fmt::{self, Display},
    str::FromStr,
};

#[derive(Eq, PartialEq, Debug, Clone, Copy, Hash)]
pub enum CommandToken {
    TransferObjects,
    SplitCoins,
    MergeCoins,
    MakeMoveVec,
    MoveCall,
    Publish,
    Upgrade,
    Assign,
    File,
    WarnShadows,
    Preview,
    PickGasBudget,
    GasBudget,
    FileStart,
    FileEnd,
}

pub const TRANSFER_OBJECTS: &str = "transfer_objects";
pub const SPLIT_COINS: &str = "split_coins";
pub const MERGE_COINS: &str = "merge_coins";
pub const MAKE_MOVE_VEC: &str = "make_move_vec";
pub const MOVE_CALL: &str = "move_call";
pub const PUBLISH: &str = "publish";
pub const UPGRADE: &str = "upgrade";
pub const ASSIGN: &str = "assign";
pub const FILE: &str = "file";
pub const PREVIEW: &str = "preview";
pub const WARN_SHADOWS: &str = "warn_shadows";
pub const PICK_GAS_BUDGET: &str = "pick_gas_budget";
pub const GAS_BUDGET: &str = "gas_budget";
pub const FILE_START: &str = "file-include-start";
pub const FILE_END: &str = "file-include-end";

impl Display for CommandToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            CommandToken::TransferObjects => TRANSFER_OBJECTS,
            CommandToken::SplitCoins => SPLIT_COINS,
            CommandToken::MergeCoins => MERGE_COINS,
            CommandToken::MakeMoveVec => MAKE_MOVE_VEC,
            CommandToken::MoveCall => MOVE_CALL,
            CommandToken::Publish => PUBLISH,
            CommandToken::Upgrade => UPGRADE,
            CommandToken::Assign => ASSIGN,
            CommandToken::File => FILE,
            CommandToken::Preview => PREVIEW,
            CommandToken::WarnShadows => WARN_SHADOWS,
            CommandToken::PickGasBudget => PICK_GAS_BUDGET,
            CommandToken::GasBudget => GAS_BUDGET,
            CommandToken::FileStart => FILE_START,
            CommandToken::FileEnd => FILE_END,
        };
        fmt::Display::fmt(s, f)
    }
}

impl FromStr for CommandToken {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            TRANSFER_OBJECTS => Ok(CommandToken::TransferObjects),
            SPLIT_COINS => Ok(CommandToken::SplitCoins),
            MERGE_COINS => Ok(CommandToken::MergeCoins),
            MAKE_MOVE_VEC => Ok(CommandToken::MakeMoveVec),
            MOVE_CALL => Ok(CommandToken::MoveCall),
            PUBLISH => Ok(CommandToken::Publish),
            UPGRADE => Ok(CommandToken::Upgrade),
            ASSIGN => Ok(CommandToken::Assign),
            FILE => Ok(CommandToken::File),
            PREVIEW => Ok(CommandToken::Preview),
            WARN_SHADOWS => Ok(CommandToken::WarnShadows),
            PICK_GAS_BUDGET => Ok(CommandToken::PickGasBudget),
            GAS_BUDGET => Ok(CommandToken::GasBudget),
            FILE_START => Ok(CommandToken::FileStart),
            FILE_END => Ok(CommandToken::FileEnd),
            _ => bail!("Invalid command token: {}", s),
        }
    }
}

pub const ALL_PUBLIC_COMMAND_TOKENS: &[&str] = &[
    TRANSFER_OBJECTS,
    SPLIT_COINS,
    MERGE_COINS,
    MAKE_MOVE_VEC,
    MOVE_CALL,
    PUBLISH,
    UPGRADE,
    ASSIGN,
    FILE,
    PREVIEW,
    WARN_SHADOWS,
    PICK_GAS_BUDGET,
    GAS_BUDGET,
];

#[cfg(test)]
mod tests {
    use crate::client_ptb::ptb_builder::command_token::*;

    #[test]
    fn round_trip() {
        let command_strs = vec![
            TRANSFER_OBJECTS,
            SPLIT_COINS,
            MERGE_COINS,
            MAKE_MOVE_VEC,
            MOVE_CALL,
            PUBLISH,
            UPGRADE,
            ASSIGN,
            FILE,
            PREVIEW,
            WARN_SHADOWS,
            PICK_GAS_BUDGET,
            GAS_BUDGET,
            FILE_START,
            FILE_END,
        ];

        for s in &command_strs {
            let token = CommandToken::from_str(s).unwrap();
            assert_eq!(token.to_string(), *s);
        }
    }
}
