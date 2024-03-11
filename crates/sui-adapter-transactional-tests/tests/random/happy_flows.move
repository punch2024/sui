// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//# init --accounts A B --addresses test=0x0

//# publish --sender A
module test::random {
    use sui::clock::Clock;
    use sui::random::Random;
    use sui::transfer;
    use sui::object;
    use sui::tx_context:: TxContext;

    public struct Obj has key, store {
        id: object::UID,
    }

    public entry fun create(ctx: &mut TxContext) {
        transfer::public_share_object(Obj { id: object::new(ctx) })
    }

    public fun use_clock(_clock: &Clock) {}
    public fun use_random(_random: &Random) {}
    public fun use_value(_value: u64) {}
}

// Good tx - use Random
//# programmable --sender A --inputs immshared(8)
//> test::random::use_random(Input(0));

// Good tx - use Clock and then Random
//# programmable --sender A --inputs immshared(6) immshared(8) @A
//> test::random::use_clock(Input(0));
//> test::random::use_random(Input(1));

// Good tx - use value and then Random
//# programmable --sender A --inputs 10 immshared(8) @A
//> test::random::use_value(Input(0));
//> test::random::use_random(Input(1));

// Good tx - use Clock, then Random, then transfer
//# programmable --sender A --inputs 10 immshared(6) immshared(8) @B
//> SplitCoins(Gas, [Input(0)]);
//> test::random::use_clock(Input(1));
//> test::random::use_random(Input(2));
//> TransferObjects([Result(0)], Input(3));

// Good tx - use Clock, then Random, then merge
//# programmable --sender A --inputs 10 immshared(6) immshared(8) @B
//> SplitCoins(Gas, [Input(0)]);
//> test::random::use_clock(Input(1));
//> test::random::use_random(Input(2));
//> MergeCoins(Gas, [Result(0)]);
