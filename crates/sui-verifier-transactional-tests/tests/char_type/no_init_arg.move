// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// invalid, no char type parameter in init

//# init --addresses test=0x0

//# publish
module test::m {

    struct M has drop { value: bool }

    fun init(_: &mut sui::tx_context::TxContext) {
    }
}
