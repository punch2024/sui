// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module sui_system::voting_power_tests {
    use sui_system::governance_test_utils as gtu;
    use sui_system::voting_power;
    use sui::test_scenario;
    use sui::test_utils;
    use sui::tx_context::TxContext;
    use std::vector;
    use sui_system::validator::{Self, Validator};

    const TOTAL_VOTING_POWER: u64 = 10_000;
    const MAX_VOTING_POWER: u64 = 1_000;

    fun check(stakes: vector<u64>, voting_power: vector<u64>, ctx: &mut TxContext) {
        let validators = gtu::create_validators_with_stakes(stakes, ctx);
        voting_power::set_voting_power(&mut validators);
        test_utils::assert_eq(get_voting_power(&validators), voting_power);
        test_utils::destroy(validators);
    }

    #[test]
    fun test_small_validator_sets() {
        let scenario = test_scenario::begin(@0x0);
        let ctx = test_scenario::ctx(&mut scenario);
        check(vector[1], vector[TOTAL_VOTING_POWER], ctx);
        check(vector[77], vector[TOTAL_VOTING_POWER], ctx);
        check(vector[TOTAL_VOTING_POWER * 93], vector[TOTAL_VOTING_POWER], ctx);
        check(vector[1, 1], vector[5_000, 5_000], ctx);
        check(vector[1, 2], vector[5_000, 5_000], ctx);
        check(vector[1, 1, 1], vector[3_333, 3_333, 3_334], ctx);
        check(vector[1, 1, 2], vector[3_333, 3_333, 3_334], ctx);
        check(vector[1, 1, 1, 1], vector[2_500, 2_500, 2_500, 2_500], ctx);
        check(vector[1, 1, 1, 1, 1, 1], vector[1666, 1666, 1667, 1667, 1667, 1667], ctx);
        check(vector[1, 1, 1, 1, 1, 1, 1], vector[1428, 1428, 1428, 1429, 1429, 1429, 1429], ctx);
        check(vector[1, 1, 1, 1, 1, 1, 1, 1, 1], vector[1111, 1111, 1111, 1111, 1111, 1111, 1111, 1111, 1112], ctx);
        // different stake distributions that all lead to 10 validators, all with max voting power
        check(vector[1, 1, 1, 1, 1, 1, 1, 1, 1, 1], vector[1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000], ctx);
        check(vector[2, 1, 1, 1, 1, 1, 1, 1, 1, 1], vector[1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000], ctx);
        check(vector[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], vector[1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000], ctx);
        test_scenario::end(scenario);
    }

    #[test]
    fun test_medium_validator_sets() {
        let scenario = test_scenario::begin(@0x0);
        let ctx = test_scenario::ctx(&mut scenario);
        // >10 validators. now things get a bit more interesting because we can redistribute stake away from the max validators
        check(vector[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], vector[909, 909, 909, 909, 909, 909, 909, 909, 909, 909, 910], ctx);
        check(vector[2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], vector[1000, 900, 900, 900, 900, 900, 900, 900, 900, 900, 900], ctx);
        check(vector[2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1], vector[1000, 1000, 888, 889, 889, 889, 889, 889, 889, 889, 889], ctx);
        check(vector[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], vector[522, 674, 826, 978, 1000, 1000, 1000, 1000, 1000, 1000, 1000], ctx);
        test_scenario::end(scenario);
    }

    #[test]
    fun test_medium_validator_sets_2() {
        let scenario = test_scenario::begin(@0x0);
        let ctx = test_scenario::ctx(&mut scenario);

        // more validators, harder to reach max
        check(vector[2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], vector[953, 953, 476, 476, 476, 476, 476, 476, 476, 476, 476, 476, 476, 476, 476, 476, 476, 477, 477], ctx);
        check(vector[4, 3, 3, 3, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], vector[1000, 951, 951, 951, 639, 639, 639, 325, 325, 325, 325, 325, 325, 325, 325, 326, 326, 326, 326, 326], ctx);
        test_scenario::end(scenario);
    }

    #[test]
    fun test_inc_236() {
        let scenario = test_scenario::begin(@0x0);
        let ctx = test_scenario::ctx(&mut scenario);
        check(vector[10000, 10001, 10000], vector[3334, 3333, 3333], ctx);
        test_scenario::end(scenario);
    }

    fun get_voting_power(validators: &vector<Validator>): vector<u64> {
        let result = vector[];
        let i = 0;
        let len = vector::length(validators);
        while (i < len) {
            let voting_power = validator::voting_power(vector::borrow(validators, i));
            vector::push_back(&mut result, voting_power);
            i = i + 1;
        };
        result
    }
}
