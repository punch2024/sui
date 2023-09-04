// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module first_package::example {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    struct Sword has key, store {
        id: UID,
        magic: u64,
        strength: u64,
    }

    struct Forge has key {
        id: UID,
        swords_created: u64,
    }

    /// Module initializer to be executed when this module is published
    fun init(ctx: &mut TxContext) {
        let admin = Forge {
            id: object::new(ctx),
            swords_created: 0,
        };

        // transfer the forge object to the module/package publisher
        transfer::transfer(admin, tx_context::sender(ctx));
    }

    // === Accessors ===

    public fun magic(self: &Sword): u64 {
        self.magic
    }

    public fun strength(self: &Sword): u64 {
        self.strength
    }

    public fun swords_created(self: &Forge): u64 {
        self.swords_created
    }

    /// Constructor for creating swords
    public entry fun new_sword(
        forge: &mut Forge,
        magic: u64,
        strength: u64,
        ctx: &mut TxContext,
    ): Sword {
        forge.swords_created = forge.swords_created + 1;
        Sword {
            id: object::new(ctx),
            magic: magic,
            strength: strength,
        }
    }

    // === Tests ===
    use sui::test_scenario as ts;

    #[test]
    public fun test_module_init() {
        let ts = ts::begin(@0x0);

        // first transaction to emulate module initialization.  @0xAD will stand
        // for the admin address.
        {
            ts::next_tx(&mut ts, @0xAD);
            init(ts::ctx(&mut ts));
        };

        // second transaction to check if the forge has been created
        // and has initial value of zero swords created
        {
            ts::next_tx(&mut ts, @0xAD);

            // extract the Forge object
            let forge: Forge = ts::take_from_sender(&mut ts);

            // verify number of created swords
            assert!(swords_created(&forge) == 0, 1);

            // return the Forge object to the object pool
            ts::return_to_sender(&mut ts, forge);
        };

        ts::end(ts);
    }

    #[test]
    fun test_sword_transactions() {
        let ts = ts::begin(@0x0);

        // first transaction to emulate module initialization
        {
            ts::next_tx(&mut ts, @0xAD);
            init(ts::ctx(&mut ts));
        };

        // second transaction executed by admin to create the sword
        {
            ts::next_tx(&mut ts, @0xAD);
            let forge: Forge = ts::take_from_sender(&mut ts);
            // create the sword and transfer it to the initial owner
            let sword = new_sword(&mut forge, 42, 7, ts::ctx(&mut ts));
            transfer::public_transfer(sword, @0xA);
            ts::return_to_sender(&mut ts, forge);
        };

        // third transaction executed by the initial sword owner
        {
            ts::next_tx(&mut ts, @0xA);
            // extract the sword owned by the initial owner
            let sword: Sword = ts::take_from_sender(&mut ts);
            // transfer the sword to the final owner
            transfer::public_transfer(sword, @0xB);
        };

        // fourth transaction executed by the final sword owner
        {
            ts::next_tx(&mut ts, @0xB);
            // extract the sword owned by the final owner
            let sword: Sword = ts::take_from_sender(&mut ts);
            // verify that the sword has expected properties
            assert!(magic(&sword) == 42 && strength(&sword) == 7, 1);
            // return the sword to the object pool (it cannot be dropped)
            ts::return_to_sender(&mut ts, sword)
        };

        ts::end(ts);
    }
}
