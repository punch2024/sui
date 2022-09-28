// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Coin<SUI> is the token used to pay for gas in Sui
module sui::sui {
    use sui::tx_context::TxContext;
    use sui::balance::Supply;
    use sui::transfer;
    use sui::coin;

    friend sui::genesis;

    /// Name of the coin
    struct SUI has drop {}

    /// Register the token to acquire its `TreasuryCap`.
    /// This should be called only once during genesis creation.
    public(friend) fun new(ctx: &mut TxContext): Supply<SUI> {
        coin::treasury_into_supply(
            coin::create_currency(SUI {}, 6, ctx)
        )
    }

    public entry fun transfer(c: coin::Coin<SUI>, recipient: address) {
        transfer::transfer(c, recipient)
    }
}
