// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use once_cell::sync::Lazy;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

/// The minimum and maximum protocol versions supported by this build.
pub const MIN_PROTOCOL_VERSION: u64 = 1;
pub const MAX_PROTOCOL_VERSION: u64 = 1;

#[derive(Copy, Clone, Debug, Hash, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub struct ProtocolVersion(u64);

impl ProtocolVersion {
    // The minimum and maximum protocol version supported by this binary. Counterintuitively, this constant may
    // change over time as support for old protocol versions is removed from the source. This
    // ensures that when a new network (such as a testnet) is created, its genesis committee will
    // use a protocol version that is actually supported by the binary.
    pub const MIN: Self = Self(MIN_PROTOCOL_VERSION);
    pub const MAX: Self = Self(MAX_PROTOCOL_VERSION);

    pub fn new(v: u64) -> Self {
        assert!(v >= MIN_PROTOCOL_VERSION, "{:?}", v);
        assert!(v <= MAX_PROTOCOL_VERSION, "{:?}", v);
        Self(v)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Constants that change the behavior of the protocol.
///
/// The value of each constant here must be fixed for a given protocol version. To change the value
/// of a constant, advance the protocol version, and add support for it in `get_for_version` under
/// the new version number.
/// (below).
///
/// To add a new field to this struct, use the following procedure:
/// - Advance the protocol version.
/// - Add the field as a private Option<T> to the struct.
/// - Initialize the field to None in prior protocol versions.
/// - Initialize the field to Some(val) for your new protocol version.
/// - Add a public getter that simply unwraps the field.
///
/// This way, if the constant is accessed in a protocol version in which it is not defined, the
/// validator will crash. (Crashing is necessary because this type of error would almost always
/// result in forking if not prevented here).
#[derive(Clone)]
pub struct ProtocolConfig {
    // ==== Move VM, Move bytecode verifier, and execution limits ===
    /// Maximum Move bytecode version the VM understands. All older versions are accepted.
    move_binary_format_version: Option<u32>,

    /// Maximum size of the `contents` part of an object, in bytes. Enforced by the Sui adapter when effects are produced.
    max_move_object_size: Option<u64>,

    // TODO: Option<increase to 500 KB. currently, publishing a package > 500 KB exceeds the max computation gas cost
    /// Maximum size of a Move package object, in bytes. Enforced by the Sui adapter at the end of a publish transaction.
    max_move_package_size: Option<u64>,

    /// Maximum number of gas units that a single MoveCall transaction can use. Enforced by the Sui adapter.
    max_tx_gas: Option<u64>,

    /// Maximum number of nested loops. Enforced by the Move bytecode verifier.
    max_loop_depth: Option<usize>,

    /// Maximum number of type arguments that can be bound to generic type parameters. Enforced by the Move bytecode verifier.
    max_generic_instantiation_length: Option<usize>,

    /// Maximum number of parameters that a Move function can have. Enforced by the Move bytecode verifier.
    max_function_parameters: Option<usize>,

    /// Maximum number of basic blocks that a Move function can have. Enforced by the Move bytecode verifier.
    max_basic_blocks: Option<usize>,

    /// Maximum stack size value. Enforced by the Move bytecode verifier.
    max_value_stack_size: Option<usize>,

    /// Maximum number of "type nodes", a metric for how big a SignatureToken will be when expanded into a fully qualified type. Enforced by the Move bytecode verifier.
    max_type_nodes: Option<usize>,

    /// Maximum number of push instructions in one function. Enforced by the Move bytecode verifier.
    max_push_size: Option<usize>,

    /// Maximum number of struct definitions in a module. Enforced by the Move bytecode verifier.
    max_struct_definitions: Option<usize>,

    /// Maximum number of function definitions in a module. Enforced by the Move bytecode verifier.
    max_function_definitions: Option<usize>,

    /// Maximum number of fields allowed in a struct definition. Enforced by the Move bytecode verifier.
    max_fields_in_struct: Option<usize>,

    /// Maximum dependency depth. Enforced by the Move linker when loading dependent modules.
    max_dependency_depth: Option<usize>,

    /// Maximum number of Move events that a single transaction can emit. Enforced by the VM during execution.
    max_num_event_emit: Option<u64>,

    /// Maximum number of new IDs that a single transaction can create. Enforced by the VM during execution.
    max_num_new_move_object_ids: Option<usize>,

    /// Maximum number of IDs that a single transaction can delete. Enforced by the VM during execution.
    max_num_deleted_move_object_ids: Option<usize>,

    /// Maximum number of IDs that a single transaction can transfer. Enforced by the VM during execution.
    max_num_transfered_move_object_ids: Option<usize>,

    // === Execution gas costs ====
    // note: Option<per-instruction and native function gas costs live in the sui-cost-tables crate
    /// Base cost for any Sui transaction
    base_tx_cost_fixed: Option<u64>,

    /// Additional cost for a transaction that publishes a package
    /// i.e., the base cost of such a transaction is base_tx_cost_fixed + package_publish_cost_fixed
    package_publish_cost_fixed: Option<u64>,

    /// Cost per byte of a Move call transaction
    /// i.e., the cost of such a transaction is base_cost + (base_tx_cost_per_byte * size)
    base_tx_cost_per_byte: Option<u64>,

    /// Cost per byte for a transaction that publishes a package
    package_publish_cost_per_byte: Option<u64>,

    // Per-byte cost of reading an object during transaction execution
    obj_access_cost_read_per_byte: Option<u64>,

    // Per-byte cost of writing an object during transaction execution
    obj_access_cost_mutate_per_byte: Option<u64>,

    // Per-byte cost of deleting an object during transaction execution
    obj_access_cost_delete_per_byte: Option<u64>,

    /// Per-byte cost charged for each input object to a transaction.
    /// Meant to approximate the cost of checking locks for each object
    // TODO: Option<I'm not sure that this cost makes sense. Checking locks is "free"
    // in the sense that an invalid tx that can never be committed/pay gas can
    // force validators to check an arbitrary number of locks. If those checks are
    // "free" for invalid transactions, why charge for them in valid transactions
    // TODO: Option<if we keep this, I think we probably want it to be a fixed cost rather
    // than a per-byte cost. checking an object lock should not require loading an
    // entire object, just consulting an ID -> tx digest map
    obj_access_cost_verify_per_byte: Option<u64>,

    /// === Storage gas costs ===

    /// Per-byte cost of storing an object in the Sui global object store. Some of this cost may be refundable if the object is later freed
    obj_data_cost_refundable: Option<u64>,

    // Per-byte cost of storing an object in the Sui transaction log (e.g., in CertifiedTransactionEffects)
    // This depends on the size of various fields including the effects
    // TODO: Option<I don't fully understand this^ and more details would be useful
    obj_metadata_cost_non_refundable: Option<u64>,

    /// === Tokenomics ===

    // TODO: Option<this should be changed to u64.
    /// Sender of a txn that touches an object will get this percent of the storage rebate back.
    /// In basis point.
    storage_rebate_rate: Option<u64>,

    /// 5% of the storage fund's share of rewards are reinvested into the storage fund.
    /// In basis point.
    storage_fund_reinvest_rate: Option<u64>,

    /// The share of rewards that will be slashed and redistributed is 50%.
    /// In basis point.
    reward_slashing_rate: Option<u64>,

    /// The stake subsidy we mint each epoch is 0.01% of the total stake.
    /// In basis point.
    stake_subsidy_rate: Option<u64>,

    /// Unit gas price, Mist per internal gas unit.
    storage_gas_price: Option<u64>,

    /// === Core Protocol ===

    /// Max number of transactions per checkpoint.
    /// Note that this is constant and not a config as validators must have this set to the same value, otherwise they *will* fork
    max_transactions_per_checkpoint: Option<usize>,
}

const CONSTANT_ERR_MSG: &str = "protocol constant not present in current protocol version";

// getters
impl ProtocolConfig {
    pub fn move_binary_format_version(&self) -> u32 {
        self.move_binary_format_version.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_move_object_size(&self) -> u64 {
        self.max_move_object_size.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_move_package_size(&self) -> u64 {
        self.max_move_package_size.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_tx_gas(&self) -> u64 {
        self.max_tx_gas.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_loop_depth(&self) -> usize {
        self.max_loop_depth.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_generic_instantiation_length(&self) -> usize {
        self.max_generic_instantiation_length
            .expect(CONSTANT_ERR_MSG)
    }
    pub fn max_function_parameters(&self) -> usize {
        self.max_function_parameters.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_basic_blocks(&self) -> usize {
        self.max_basic_blocks.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_value_stack_size(&self) -> usize {
        self.max_value_stack_size.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_type_nodes(&self) -> usize {
        self.max_type_nodes.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_push_size(&self) -> usize {
        self.max_push_size.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_struct_definitions(&self) -> usize {
        self.max_struct_definitions.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_function_definitions(&self) -> usize {
        self.max_function_definitions.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_fields_in_struct(&self) -> usize {
        self.max_fields_in_struct.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_dependency_depth(&self) -> usize {
        self.max_dependency_depth.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_num_event_emit(&self) -> u64 {
        self.max_num_event_emit.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_num_new_move_object_ids(&self) -> usize {
        self.max_num_new_move_object_ids.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_num_deleted_move_object_ids(&self) -> usize {
        self.max_num_deleted_move_object_ids
            .expect(CONSTANT_ERR_MSG)
    }
    pub fn max_num_transfered_move_object_ids(&self) -> usize {
        self.max_num_transfered_move_object_ids
            .expect(CONSTANT_ERR_MSG)
    }
    pub fn base_tx_cost_fixed(&self) -> u64 {
        self.base_tx_cost_fixed.expect(CONSTANT_ERR_MSG)
    }
    pub fn package_publish_cost_fixed(&self) -> u64 {
        self.package_publish_cost_fixed.expect(CONSTANT_ERR_MSG)
    }
    pub fn base_tx_cost_per_byte(&self) -> u64 {
        self.base_tx_cost_per_byte.expect(CONSTANT_ERR_MSG)
    }
    pub fn package_publish_cost_per_byte(&self) -> u64 {
        self.package_publish_cost_per_byte.expect(CONSTANT_ERR_MSG)
    }
    pub fn obj_access_cost_read_per_byte(&self) -> u64 {
        self.obj_access_cost_read_per_byte.expect(CONSTANT_ERR_MSG)
    }
    pub fn obj_access_cost_mutate_per_byte(&self) -> u64 {
        self.obj_access_cost_mutate_per_byte
            .expect(CONSTANT_ERR_MSG)
    }
    pub fn obj_access_cost_delete_per_byte(&self) -> u64 {
        self.obj_access_cost_delete_per_byte
            .expect(CONSTANT_ERR_MSG)
    }
    pub fn obj_access_cost_verify_per_byte(&self) -> u64 {
        self.obj_access_cost_verify_per_byte
            .expect(CONSTANT_ERR_MSG)
    }
    pub fn obj_data_cost_refundable(&self) -> u64 {
        self.obj_data_cost_refundable.expect(CONSTANT_ERR_MSG)
    }
    pub fn obj_metadata_cost_non_refundable(&self) -> u64 {
        self.obj_metadata_cost_non_refundable
            .expect(CONSTANT_ERR_MSG)
    }
    pub fn storage_rebate_rate(&self) -> f64 {
        self.storage_rebate_rate.expect(CONSTANT_ERR_MSG)
    }
    pub fn storage_fund_reinvest_rate(&self) -> u64 {
        self.storage_fund_reinvest_rate.expect(CONSTANT_ERR_MSG)
    }
    pub fn reward_slashing_rate(&self) -> u64 {
        self.reward_slashing_rate.expect(CONSTANT_ERR_MSG)
    }
    pub fn stake_subsidy_rate(&self) -> u64 {
        self.stake_subsidy_rate.expect(CONSTANT_ERR_MSG)
    }
    pub fn storage_gas_price(&self) -> u64 {
        self.storage_gas_price.expect(CONSTANT_ERR_MSG)
    }
    pub fn max_transactions_per_checkpoint(&self) -> usize {
        self.max_transactions_per_checkpoint
            .expect(CONSTANT_ERR_MSG)
    }

    // When adding a new constant, create a new getter for it as follows, so that the validator
    // will crash if the constant is accessed before the protocol in which it is defined.
    //
    // pub fn new_constant(&self) -> usize {
    //     self.new_constant.expect(CONSTANT_ERR_MSG)
    // }
}

static POISON_VERSION_METHODS: AtomicBool = AtomicBool::new(false);

// Instantiations for each protocol version.
impl ProtocolConfig {
    /// Get the value ProtocolConfig that are in effect during the given protocol version.
    pub fn get_for_version(version: ProtocolVersion) -> Self {
        // ProtocolVersion can be deserialized so we need to check it here as well.
        assert!(version.0 >= MIN_PROTOCOL_VERSION, "{:?}", version);
        assert!(version.0 <= MAX_PROTOCOL_VERSION, "{:?}", version);

        Self::get_for_version_impl(version)
    }

    pub fn poison_get_for_min_version() {
        POISON_VERSION_METHODS.store(true, Ordering::Relaxed);
    }

    /// Convenience to get the constants at the current minimum supported version.
    /// Mainly used by client code that may not yet be protocol-version aware.
    pub fn get_for_min_version() -> &'static Self {
        if POISON_VERSION_METHODS.load(Ordering::Relaxed) {
            panic!("get_for_min_version called on validator");
        }

        static CONSTANTS: Lazy<ProtocolConfig> =
            Lazy::new(|| ProtocolConfig::get_for_version(ProtocolVersion::MIN));

        &CONSTANTS
    }

    /// Convenience to get the constants at the current maximum supported version.
    /// Mainly used by genesis.
    pub fn get_for_max_version() -> &'static Self {
        if POISON_VERSION_METHODS.load(Ordering::Relaxed) {
            panic!("get_for_max_version called on validator");
        }

        static CONSTANTS: Lazy<ProtocolConfig> =
            Lazy::new(|| ProtocolConfig::get_for_version(ProtocolVersion::MAX));

        &CONSTANTS
    }

    fn get_for_version_impl(version: ProtocolVersion) -> Self {
        // IMPORTANT: Never modify the value of any constant for a pre-existing protocol version.
        // To change the values here you must create a new protocol version with the new values!
        match version.0 {
            1 => Self {
                move_binary_format_version: Some(6),
                max_move_object_size: Some(250 * 1024),
                max_move_package_size: Some(100 * 1024),
                max_tx_gas: Some(1_000_000_000),
                max_loop_depth: Some(5),
                max_generic_instantiation_length: Some(32),
                max_function_parameters: Some(128),
                max_basic_blocks: Some(1024),
                max_value_stack_size: Some(1024),
                max_type_nodes: Some(256),
                max_push_size: Some(10000),
                max_struct_definitions: Some(200),
                max_function_definitions: Some(1000),
                max_fields_in_struct: Some(32),
                max_dependency_depth: Some(100),
                max_num_event_emit: Some(256),
                max_num_new_move_object_ids: Some(2048),
                max_num_deleted_move_object_ids: Some(2048),
                max_num_transfered_move_object_ids: Some(2048),
                base_tx_cost_fixed: Some(110_000),
                package_publish_cost_fixed: Some(1_000),
                base_tx_cost_per_byte: Some(0),
                package_publish_cost_per_byte: Some(80),
                obj_access_cost_read_per_byte: Some(15),
                obj_access_cost_mutate_per_byte: Some(40),
                obj_access_cost_delete_per_byte: Some(40),
                obj_access_cost_verify_per_byte: Some(200),
                obj_data_cost_refundable: Some(100),
                obj_metadata_cost_non_refundable: Some(50),
                storage_rebate_rate: Some(9900),
                storage_fund_reinvest_rate: Some(500),
                reward_slashing_rate: Some(5000),
                stake_subsidy_rate: Some(1),
                storage_gas_price: Some(1),
                max_transactions_per_checkpoint: Some(1000),
                // When adding a new constant, set it to None in the earliest version, like this:
                // new_constant: None,
            },

            // Use this template when making changes:
            //
            // NEW_VERSION => Self {
            //     // modify an existing constant.
            //     move_binary_format_version: Some(7),
            //
            //     // Add a new constant (which is set to None in prior versions).
            //     new_constant: Some(new_value),
            //
            //     // Remove a constant (ensure that it is never accessed during this version).
            //     max_move_object_size: None,
            //
            //     // Pull in everything else from the previous version to avoid unintentional
            //     // changes.
            //     ..get_for_version_impl(version - 1)
            // },
            _ => panic!("unsupported version {:?}", version),
        }
    }
}
