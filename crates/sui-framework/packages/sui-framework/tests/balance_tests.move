// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module sui::coin_balance_tests {
    use sui::test_scenario;
    use sui::pay;
    use sui::coin;
    use sui::balance;
    use sui::sui::SUI;

    #[test]
    fun type_morphing() {
        let mut scenario = test_scenario::begin(@0x1);

        let balance = balance::zero<SUI>();
        let coin = coin::from_balance(balance, scenario.ctx());
        let balance = coin::into_balance(coin);

        balance::destroy_zero(balance);

        let mut coin = coin::mint_for_testing<SUI>(100, scenario.ctx());
        let balance_mut = coin::balance_mut(&mut coin);
        let sub_balance = balance_mut.split(50);

        assert!(sub_balance.value() == 50, 0);
        assert!(coin.value() == 50, 0);

        let mut balance = coin::into_balance(coin);
        balance.join(sub_balance);

        assert!(balance.value() == 100, 0);

        let coin = coin::from_balance(balance, scenario.ctx());
        pay::keep(coin, scenario.ctx());
        scenario.end();
    }
}
