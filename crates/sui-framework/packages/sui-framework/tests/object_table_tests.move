// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module sui::object_table_tests {
    use sui::object_table::{Self, add};
    use sui::object::{Self, UID};
    use sui::test_scenario as ts;

    public struct Counter has key, store {
        id: UID,
        count: u64,
    }

    #[test]
    fun simple_all_functions() {
        let sender = @0x0;
        let mut scenario = ts::begin(sender);
        let mut table = object_table::new(ts::ctx(&mut scenario));
        let counter1 = new(&mut scenario);
        let id1 = object::id(&counter1);
        let counter2 = new(&mut scenario);
        let id2 = object::id(&counter2);
        // add fields
        table.add(b"hello", counter1);
        table.add(b"goodbye", counter2);
        // check they exist
        assert!(table.contains(b"hello"), 0);
        assert!(table.contains(b"goodbye"), 0);
        // check the IDs
        assert!(table.value_id(b"hello").borrow() == &id1, 0);
        assert!(table.value_id(b"goodbye").borrow() == &id2, 0);
        // check the values
        assert!(count(&table[b"hello"]) == 0, 0);
        assert!(count(&table[b"goodbye"]) == 0, 0);
        // mutate them
        bump(&mut table[b"hello"]);
        bump(bump(&mut table[b"goodbye"]));
        // check the new value
        assert!(count(&table[b"hello"]) == 1, 0);
        assert!(count(&table[b"goodbye"]) == 2, 0);
        // remove the value and check it
        assert!(table.remove(b"hello").destroy() == 1, 0);
        assert!(table.remove(b"goodbye").destroy() == 2, 0);
        // verify that they are not there
        assert!(!table.contains(b"hello"), 0);
        assert!(!table.contains(b"goodbye"), 0);
        ts::end(scenario);
        table.destroy_empty();
    }

    #[test]
    #[expected_failure(abort_code = sui::dynamic_field::EFieldAlreadyExists)]
    fun add_duplicate() {
        let sender = @0x0;
        let mut scenario = ts::begin(sender);
        let mut table = object_table::new(ts::ctx(&mut scenario));
        table.add(b"hello", new(&mut scenario));
        table.add(b"hello", new(&mut scenario));
        abort 42
    }

    #[test]
    #[expected_failure(abort_code = sui::dynamic_field::EFieldDoesNotExist)]
    fun borrow_missing() {
        let sender = @0x0;
        let mut scenario = ts::begin(sender);
        let table = object_table::new<u64, Counter>(ts::ctx(&mut scenario));
        &table[0];
        abort 42
    }

    #[test]
    #[expected_failure(abort_code = sui::dynamic_field::EFieldDoesNotExist)]
    fun borrow_mut_missing() {
        let sender = @0x0;
        let mut scenario = ts::begin(sender);
        let mut table = object_table::new<u64, Counter>(ts::ctx(&mut scenario));
        &mut table[0];
        abort 42
    }

    #[test]
    #[expected_failure(abort_code = sui::dynamic_field::EFieldDoesNotExist)]
    fun remove_missing() {
        let sender = @0x0;
        let mut scenario = ts::begin(sender);
        let mut table = object_table::new<u64, Counter>(ts::ctx(&mut scenario));
        table.remove(0).destroy();
        abort 42
    }

    #[test]
    #[expected_failure(abort_code = sui::object_table::ETableNotEmpty)]
    fun destroy_non_empty() {
        let sender = @0x0;
        let mut scenario = ts::begin(sender);
        let mut table = object_table::new(ts::ctx(&mut scenario));
        table.add(0, new(&mut scenario));
        table.destroy_empty();
        ts::end(scenario);
    }

    #[test]
    fun sanity_check_contains() {
        let sender = @0x0;
        let mut scenario = ts::begin(sender);
        let mut table = object_table::new(ts::ctx(&mut scenario));
        assert!(!table.contains(0), 0);
        table.add(0, new(&mut scenario));
        assert!(table.contains(0), 0);
        assert!(!table.contains(1), 0);
        ts::end(scenario);
        table.remove(0).destroy();
        table.destroy_empty()
    }

    #[test]
    fun sanity_check_size() {
        let sender = @0x0;
        let mut scenario = ts::begin(sender);
        let mut table = object_table::new(ts::ctx(&mut scenario));
        assert!(table.is_empty(), 0);
        assert!(table.length() == 0, 0);
        table.add(0, new(&mut scenario));
        assert!(!table.is_empty(), 0);
        assert!(table.length() == 1, 0);
        table.add(1, new(&mut scenario));
        assert!(!table.is_empty(), 0);
        assert!(table.length() == 2, 0);
        ts::end(scenario);
        table.remove(0).destroy();
        table.remove(1).destroy();
        table.destroy_empty();
    }

    // transfer an object field from one "parent" to another
    #[test]
    fun transfer_object() {
        let sender = @0x0;
        let mut scenario = ts::begin(sender);
        let mut table1 = object_table::new<u64, Counter>(ts::ctx(&mut scenario));
        let mut table2 = object_table::new<u64, Counter>(ts::ctx(&mut scenario));
        table1.add(0, new(&mut scenario));
        assert!(table1.contains(0), 0);
        assert!(!table2.contains(0), 0);
        bump(&mut table1[0]);
        let c = table1.remove(0);
        table2.add(0, c);
        assert!(!table1.contains(0), 0);
        assert!(table2.contains(0), 0);
        bump(&mut table2[0]);
        assert!(&table2[0].count() == 2, 0);
        ts::end(scenario);
        table2.remove(0).destroy();
        table1.destroy_empty();
        table2.destroy_empty();
    }

    fun new(scenario: &mut ts::Scenario): Counter {
        Counter { id: ts::new_object(scenario), count: 0 }
    }

    fun count(counter: &Counter): u64 {
        counter.count
    }

    fun bump(counter: &mut Counter): &mut Counter {
        counter.count = counter.count + 1;
        counter
    }

    fun destroy(counter: Counter): u64 {
        let Counter { id, count } = counter;
        id.delete();
        count
    }
}
