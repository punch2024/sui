// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/** A parsed result of all aux inputs. */
export interface AuxInputs {
	addr_seed: string;
	eph_public_key: string[];
	jwt_sha2_hash: string[];
	jwt_signature: string;
	key_claim_name: string;
	masked_content: number[];
	max_epoch: string;
	num_sha2_blocks: number;
	payload_len: number;
	payload_start_index: number;
}
export interface Balance {
	coinObjectCount: number;
	coinType: string;
	lockedBalance: {
		[key: string]: string;
	};
	totalBalance: string;
}
export interface BalanceChange {
	/**
	 * The amount indicate the balance value changes, negative amount means spending coin value and
	 * positive means receiving coin value.
	 */
	amount: string;
	coinType: string;
	/** Owner of the balance change */
	owner: ObjectOwner;
}
export interface Checkpoint {
	/** Commitments to checkpoint state */
	checkpointCommitments: CheckpointCommitment[];
	/** Checkpoint digest */
	digest: string;
	/** Present only on the final checkpoint of the epoch. */
	endOfEpochData?: EndOfEpochData | null;
	/** Checkpoint's epoch ID */
	epoch: string;
	/**
	 * The running total gas costs of all transactions included in the current epoch so far until this
	 * checkpoint.
	 */
	epochRollingGasCostSummary: GasCostSummary;
	/** Total number of transactions committed since genesis, including those in this checkpoint. */
	networkTotalTransactions: string;
	/** Digest of the previous checkpoint */
	previousDigest?: string | null;
	/** Checkpoint sequence number */
	sequenceNumber: string;
	/**
	 * Timestamp of the checkpoint - number of milliseconds from the Unix epoch Checkpoint timestamps are
	 * monotonic, but not strongly monotonic - subsequent checkpoints can have same timestamp if they
	 * originate from the same underlining consensus commit
	 */
	timestampMs: string;
	/** Transaction digests */
	transactions: string[];
	/** Validator Signature */
	validatorSignature: string;
}
export type CheckpointCommitment = {
	ECMHLiveObjectSetDigest: ECMHLiveObjectSetDigest;
};
export type CheckpointId = string | string;
export interface CoinStruct {
	balance: string;
	coinObjectId: string;
	coinType: string;
	digest: string;
	previousTransaction: string;
	version: string;
}
/** RPC representation of the [Committee] type. */
export interface CommitteeInfo {
	epoch: string;
	validators: [string, string][];
}
/** Unlike [enum Signature], [enum CompressedSignature] does not contain public key. */
export type CompressedSignature =
	| {
			Ed25519: string;
	  }
	| {
			Secp256k1: string;
	  }
	| {
			Secp256r1: string;
	  };
export type SuiParsedData =
	| {
			dataType: 'moveObject';
			fields: MoveStruct;
			hasPublicTransfer: boolean;
			type: string;
	  }
	| {
			dataType: 'package';
			disassembled: {
				[key: string]: unknown;
			};
	  };
export interface DelegatedStake {
	stakes: StakeObject[];
	/** Staking pool object id. */
	stakingPool: string;
	/** Validator's Address. */
	validatorAddress: string;
}
/** The response from processing a dev inspect transaction */
export interface DevInspectResults {
	/**
	 * Summary of effects that likely would be generated if the transaction is actually run. Note however,
	 * that not all dev-inspect transactions are actually usable as transactions so it might not be
	 * possible actually generate these effects from a normal transaction.
	 */
	effects: TransactionEffects;
	/** Execution error from executing the transactions */
	error?: string | null;
	/** Events that likely would be generated if the transaction is actually run. */
	events: SuiEvent[];
	/** Execution results (including return values) from executing the transactions */
	results?: SuiExecutionResult[] | null;
}
export interface DisplayFieldsResponse {
	data?: {
		[key: string]: string;
	} | null;
	error?: ObjectResponseError | null;
}
export interface DryRunTransactionBlockResponse {
	balanceChanges: BalanceChange[];
	effects: TransactionEffects;
	events: SuiEvent[];
	input: TransactionBlockData;
	objectChanges: SuiObjectChange[];
}
export interface DynamicFieldInfo {
	bcsName: string;
	digest: string;
	name: DynamicFieldName;
	objectId: string;
	objectType: string;
	type: DynamicFieldType;
	version: string;
}
export interface DynamicFieldName {
	type: string;
	value: unknown;
}
export type DynamicFieldType = 'DynamicField' | 'DynamicObject';
/** The Sha256 digest of an EllipticCurveMultisetHash committing to the live object set. */
export interface ECMHLiveObjectSetDigest {
	digest: number[];
}
export interface EndOfEpochData {
	/** Commitments to epoch specific state (e.g. live object set) */
	epochCommitments: CheckpointCommitment[];
	/**
	 * next_epoch_committee is `Some` if and only if the current checkpoint is the last checkpoint of an
	 * epoch. Therefore next_epoch_committee can be used to pick the last checkpoint of an epoch, which is
	 * often useful to get epoch level summary stats like total gas cost of an epoch, or the total number
	 * of transactions from genesis to the end of an epoch. The committee is stored as a vector of
	 * validator pub key and stake pairs. The vector should be sorted based on the Committee data
	 * structure.
	 */
	nextEpochCommittee: [string, string][];
	/**
	 * The protocol version that is in effect during the epoch that starts immediately after this
	 * checkpoint.
	 */
	nextEpochProtocolVersion: string;
}
export interface SuiEvent {
	/** Base 58 encoded bcs bytes of the move event */
	bcs: string;
	/**
	 * Sequential event ID, ie (transaction seq number, event seq number). 1) Serves as a unique event ID
	 * for each fullnode 2) Also serves to sequence events for the purposes of pagination and querying. A
	 * higher id is an event seen later by that fullnode. This ID is the "cursor" for event querying.
	 */
	id: EventId;
	/** Move package where this event was emitted. */
	packageId: string;
	/** Parsed json value of the event */
	parsedJson: unknown;
	/** Sender's Sui address. */
	sender: string;
	/** UTC timestamp in milliseconds since epoch (1/1/1970) */
	timestampMs?: string | null;
	/** Move module where this event was emitted. */
	transactionModule: string;
	/** Move event type. */
	type: string;
}
export type SuiEventFilter =
	/** Query by sender address. */
	| {
			Sender: string;
	  } /** Return events emitted by the given transaction. */
	| {
			Transaction: string;
	  } /** Return events emitted in a specified Package. */
	| {
			Package: string;
	  } /** Return events emitted in a specified Move module. */
	| {
			MoveModule: {
				/** the module name */
				module: string;
				/** the Move package ID */
				package: string;
			};
	  } /** Return events with the given move event struct name */
	| {
			MoveEventType: string;
	  } /** Return events with the given move event module name */
	| {
			MoveEventModule: {
				/** the module name */
				module: string;
				/** the Move package ID */
				package: string;
			};
	  }
	| {
			MoveEventField: {
				path: string;
				value: unknown;
			};
	  } /** Return events emitted in [start_time, end_time] interval */
	| {
			TimeRange: {
				/** right endpoint of time interval, milliseconds since epoch, exclusive */
				endTime: string;
				/** left endpoint of time interval, milliseconds since epoch, inclusive */
				startTime: string;
			};
	  }
	| {
			All: SuiEventFilter[];
	  }
	| {
			Any: SuiEventFilter[];
	  }
	| {
			And: [SuiEventFilter, SuiEventFilter];
	  }
	| {
			Or: [SuiEventFilter, SuiEventFilter];
	  };
/**
 * Unique ID of a Sui Event, the ID is a combination of tx seq number and event seq number, the ID is
 * local to this particular fullnode and will be different from other fullnode.
 */
export interface EventId {
	eventSeq: string;
	txDigest: string;
}
export type ExecuteTransactionRequestType = 'WaitForEffectsCert' | 'WaitForLocalExecution';
export type ExecutionStatus = {
	status: 'success' | 'failure';
	error?: string;
};
/**
 * Summary of the charges in a transaction. Storage is charged independently of computation. There are
 * 3 parts to the storage charges: `storage_cost`: it is the charge of storage at the time the
 * transaction is executed. The cost of storage is the number of bytes of the objects being mutated
 * multiplied by a variable storage cost per byte `storage_rebate`: this is the amount a user gets back
 * when manipulating an object. The `storage_rebate` is the `storage_cost` for an object minus fees.
 * `non_refundable_storage_fee`: not all the value of the object storage cost is given back to user and
 * there is a small fraction that is kept by the system. This value tracks that charge.
 *
 * When looking at a gas cost summary the amount charged to the user is
 * `computation_cost + storage_cost - storage_rebate` and that is the amount that is deducted from the
 * gas coins. `non_refundable_storage_fee` is collected from the objects being mutated/deleted and it
 * is tracked by the system in storage funds.
 *
 * Objects deleted, including the older versions of objects mutated, have the storage field on the
 * objects added up to a pool of "potential rebate". This rebate then is reduced by the "nonrefundable
 * rate" such that:
 * `potential_rebate(storage cost of deleted/mutated objects) = storage_rebate + non_refundable_storage_fee`
 */
export interface GasCostSummary {
	/** Cost of computation/execution */
	computationCost: string;
	/** The fee for the rebate. The portion of the storage rebate kept by the system. */
	nonRefundableStorageFee: string;
	/** Storage cost, it's the sum of all storage cost for all objects created or mutated. */
	storageCost: string;
	/**
	 * The amount of storage cost refunded to the user for all objects deleted or mutated in the
	 * transaction.
	 */
	storageRebate: string;
}
export interface SuiGasData {
	budget: string;
	owner: string;
	payment: SuiObjectRef[];
	price: string;
}
export interface GetPastObjectRequest {
	/** the ID of the queried object */
	objectId: string;
	/** the version of the queried object. */
	version: string;
}
export type InputObjectKind =
	| {
			MovePackage: string;
	  }
	| {
			ImmOrOwnedMoveObject: SuiObjectRef;
	  }
	| {
			SharedMoveObject: {
				id: string;
				initial_shared_version: string;
				mutable?: boolean;
			};
	  };
export interface LoadedChildObject {
	objectId: string;
	sequenceNumber: string;
}
export interface LoadedChildObjectsResponse {
	loadedChildObjects: LoadedChildObject[];
}
export interface MoveCallParams {
	arguments: unknown[];
	function: string;
	module: string;
	packageObjectId: string;
	typeArguments?: string[];
}
export type SuiMoveFunctionArgType =
	| 'Pure'
	| {
			Object: ObjectValueKind;
	  };
export type MoveStruct =
	| MoveValue[]
	| {
			fields: {
				[key: string]: MoveValue;
			};
			type: string;
	  }
	| {
			[key: string]: MoveValue;
	  };
export type MoveValue =
	| number
	| boolean
	| string
	| MoveValue[]
	| string
	| {
			id: string;
	  }
	| MoveStruct
	| null;
/** The struct that contains signatures and public keys necessary for authenticating a MultiSig. */
export interface MultiSig {
	/** A bitmap that indicates the position of which public key the signature should be authenticated with. */
	bitmap: number;
	/**
	 * The public key encoded with each public key with its signature scheme used along with the
	 * corresponding weight.
	 */
	multisig_pk: MultiSigPublicKey;
	/** The plain signature encoded with signature scheme. */
	sigs: CompressedSignature[];
}
/**
 * Deprecated, use [struct MultiSig] instead. The struct that contains signatures and public keys
 * necessary for authenticating a MultiSigLegacy.
 */
export interface MultiSigLegacy {
	/** A bitmap that indicates the position of which public key the signature should be authenticated with. */
	bitmap: string;
	/**
	 * The public key encoded with each public key with its signature scheme used along with the
	 * corresponding weight.
	 */
	multisig_pk: MultiSigPublicKeyLegacy;
	/** The plain signature encoded with signature scheme. */
	sigs: CompressedSignature[];
}
/** The struct that contains the public key used for authenticating a MultiSig. */
export interface MultiSigPublicKey {
	/** A list of public key and its corresponding weight. */
	pk_map: [PublicKey, number][];
	/**
	 * If the total weight of the public keys corresponding to verified signatures is larger than
	 * threshold, the MultiSig is verified.
	 */
	threshold: number;
}
/**
 * Deprecated, use [struct MultiSigPublicKey] instead. The struct that contains the public key used for
 * authenticating a MultiSig.
 */
export interface MultiSigPublicKeyLegacy {
	/** A list of public key and its corresponding weight. */
	pk_map: [PublicKey, number][];
	/**
	 * If the total weight of the public keys corresponding to verified signatures is larger than
	 * threshold, the MultiSig is verified.
	 */
	threshold: number;
}
/**
 * ObjectChange are derived from the object mutations in the TransactionEffect to provide richer object
 * information.
 */
export type SuiObjectChange =
	/** Module published */
	| {
			digest: string;
			modules: string[];
			packageId: string;
			type: 'published';
			version: string;
	  } /** Transfer objects to new address / wrap in another object */
	| {
			digest: string;
			objectId: string;
			objectType: string;
			recipient: ObjectOwner;
			sender: string;
			type: 'transferred';
			version: string;
	  } /** Object mutated. */
	| {
			digest: string;
			objectId: string;
			objectType: string;
			owner: ObjectOwner;
			previousVersion: string;
			sender: string;
			type: 'mutated';
			version: string;
	  } /** Delete object */
	| {
			objectId: string;
			objectType: string;
			sender: string;
			type: 'deleted';
			version: string;
	  } /** Wrapped object */
	| {
			objectId: string;
			objectType: string;
			sender: string;
			type: 'wrapped';
			version: string;
	  } /** New object creation */
	| {
			digest: string;
			objectId: string;
			objectType: string;
			owner: ObjectOwner;
			sender: string;
			type: 'created';
			version: string;
	  };
export interface SuiObjectData {
	/**
	 * Move object content or package content in BCS, default to be None unless
	 * SuiObjectDataOptions.showBcs is set to true
	 */
	bcs?: RawData | null;
	/**
	 * Move object content or package content, default to be None unless SuiObjectDataOptions.showContent
	 * is set to true
	 */
	content?: SuiParsedData | null;
	/** Base64 string representing the object digest */
	digest: string;
	/**
	 * The Display metadata for frontend UI rendering, default to be None unless
	 * SuiObjectDataOptions.showContent is set to true This can also be None if the struct type does not
	 * have Display defined See more details in <https://forums.sui.io/t/nft-object-display-proposal/4872>
	 */
	display?: DisplayFieldsResponse | null;
	objectId: string;
	/** The owner of this object. Default to be None unless SuiObjectDataOptions.showOwner is set to true */
	owner?: ObjectOwner | null;
	/**
	 * The digest of the transaction that created or last mutated this object. Default to be None unless
	 * SuiObjectDataOptions.showPreviousTransaction is set to true
	 */
	previousTransaction?: string | null;
	/**
	 * The amount of SUI we would rebate if this object gets deleted. This number is re-calculated each
	 * time the object is mutated based on the present storage gas price.
	 */
	storageRebate?: string | null;
	/** The type of the object. Default to be None unless SuiObjectDataOptions.showType is set to true */
	type?: string | null;
	/** Object version. */
	version: string;
}
export interface SuiObjectDataOptions {
	/** Whether to show the content in BCS format. Default to be False */
	showBcs?: boolean;
	/**
	 * Whether to show the content(i.e., package content or Move struct content) of the object. Default to
	 * be False
	 */
	showContent?: boolean;
	/** Whether to show the Display metadata of the object for frontend rendering. Default to be False */
	showDisplay?: boolean;
	/** Whether to show the owner of the object. Default to be False */
	showOwner?: boolean;
	/** Whether to show the previous transaction digest of the object. Default to be False */
	showPreviousTransaction?: boolean;
	/** Whether to show the storage rebate of the object. Default to be False */
	showStorageRebate?: boolean;
	/** Whether to show the type of the object. Default to be False */
	showType?: boolean;
}
export type ObjectRead =
	/** The object exists and is found with this version */
	| {
			details: SuiObjectData;
			status: 'VersionFound';
	  } /** The object does not exist */
	| {
			details: string;
			status: 'ObjectNotExists';
	  } /** The object is found to be deleted with this version */
	| {
			details: SuiObjectRef;
			status: 'ObjectDeleted';
	  } /** The object exists but not found with this version */
	| {
			details: [string, string];
			status: 'VersionNotFound';
	  } /** The asked object version is higher than the latest */
	| {
			details: {
				asked_version: string;
				latest_version: string;
				object_id: string;
			};
			status: 'VersionTooHigh';
	  };
export interface SuiObjectRef {
	/** Base64 string representing the object digest */
	digest: string;
	/** Hex code as string representing the object id */
	objectId: string;
	/** Object version. */
	version: string;
}
export type ObjectResponseError =
	| {
			code: 'notExists';
			object_id: string;
	  }
	| {
			code: 'dynamicFieldNotFound';
			parent_object_id: string;
	  }
	| {
			code: 'deleted';
			/** Base64 string representing the object digest */
			digest: string;
			object_id: string;
			/** Object version. */
			version: string;
	  }
	| {
			code: 'unknown';
	  }
	| {
			code: 'displayError';
			error: string;
	  };
export interface SuiObjectResponseQuery {
	/** If None, no filter will be applied */
	filter?: SuiObjectDataFilter | null;
	/** config which fields to include in the response, by default only digest is included */
	options?: SuiObjectDataOptions | null;
}
export type ObjectValueKind = 'ByImmutableReference' | 'ByMutableReference' | 'ByValue';
export interface OwnedObjectRef {
	owner: ObjectOwner;
	reference: SuiObjectRef;
}
export type ObjectOwner =
	/** Object is exclusively owned by a single address, and is mutable. */
	| {
			AddressOwner: string;
	  } /**
	 * Object is exclusively owned by a single object, and is mutable. The object ID is converted to
	 * SuiAddress as SuiAddress is universal.
	 */
	| {
			ObjectOwner: string;
	  } /** Object is shared, can be used by any address, and is mutable. */
	| {
			Shared: {
				/** The version at which the object became shared */
				initial_shared_version: string;
			};
	  }
	| 'Immutable';
/**
 * `next_cursor` points to the last item in the page; Reading with `next_cursor` will start from the
 * next item after `next_cursor` if `next_cursor` is `Some`, otherwise it will start from the first
 * item.
 */
export interface PaginatedCheckpoints {
	data: Checkpoint[];
	hasNextPage: boolean;
	nextCursor?: string | null;
}
/**
 * `next_cursor` points to the last item in the page; Reading with `next_cursor` will start from the
 * next item after `next_cursor` if `next_cursor` is `Some`, otherwise it will start from the first
 * item.
 */
export interface PaginatedCoins {
	data: CoinStruct[];
	hasNextPage: boolean;
	nextCursor?: string | null;
}
/**
 * `next_cursor` points to the last item in the page; Reading with `next_cursor` will start from the
 * next item after `next_cursor` if `next_cursor` is `Some`, otherwise it will start from the first
 * item.
 */
export interface PaginatedDynamicFieldInfos {
	data: DynamicFieldInfo[];
	hasNextPage: boolean;
	nextCursor?: string | null;
}
/**
 * `next_cursor` points to the last item in the page; Reading with `next_cursor` will start from the
 * next item after `next_cursor` if `next_cursor` is `Some`, otherwise it will start from the first
 * item.
 */
export interface PaginatedEvents {
	data: SuiEvent[];
	hasNextPage: boolean;
	nextCursor?: EventId | null;
}
/**
 * `next_cursor` points to the last item in the page; Reading with `next_cursor` will start from the
 * next item after `next_cursor` if `next_cursor` is `Some`, otherwise it will start from the first
 * item.
 */
export interface PaginatedStrings {
	data: string[];
	hasNextPage: boolean;
	nextCursor?: string | null;
}
/**
 * `next_cursor` points to the last item in the page; Reading with `next_cursor` will start from the
 * next item after `next_cursor` if `next_cursor` is `Some`, otherwise it will start from the first
 * item.
 */
export interface PaginatedObjectsResponse {
	data: SuiObjectResponse[];
	hasNextPage: boolean;
	nextCursor?: string | null;
}
/**
 * `next_cursor` points to the last item in the page; Reading with `next_cursor` will start from the
 * next item after `next_cursor` if `next_cursor` is `Some`, otherwise it will start from the first
 * item.
 */
export interface PaginatedTransactionResponse {
	data: SuiTransactionBlockResponse[];
	hasNextPage: boolean;
	nextCursor?: string | null;
}
export interface ProtocolConfig {
	attributes: {
		[key: string]: ProtocolConfigValue | null;
	};
	featureFlags: {
		[key: string]: boolean;
	};
	maxSupportedProtocolVersion: string;
	minSupportedProtocolVersion: string;
	protocolVersion: string;
}
export type ProtocolConfigValue =
	| {
			u32: string;
	  }
	| {
			u64: string;
	  }
	| {
			f64: string;
	  };
/** The public inputs containing an array of string that is the all inputs hash. */
export interface PublicInputs {
	inputs: string[];
}
export type PublicKey =
	| {
			Ed25519: string;
	  }
	| {
			Secp256k1: string;
	  }
	| {
			Secp256r1: string;
	  };
export type RPCTransactionRequestParams =
	| {
			transferObjectRequestParams: TransferObjectParams;
	  }
	| {
			moveCallRequestParams: MoveCallParams;
	  };
export type RawData =
	| {
			bcsBytes: string;
			dataType: 'moveObject';
			hasPublicTransfer: boolean;
			type: string;
			version: string;
	  }
	| {
			dataType: 'package';
			id: string;
			linkageTable: {
				[key: string]: UpgradeInfo;
			};
			moduleMap: {
				[key: string]: string;
			};
			typeOriginTable: TypeOrigin[];
			version: string;
	  };
export type Signature =
	| {
			Ed25519SuiSignature: string;
	  }
	| {
			Secp256k1SuiSignature: string;
	  }
	| {
			Secp256r1SuiSignature: string;
	  };
export type StakeObject =
	| {
			principal: string;
			stakeActiveEpoch: string;
			stakeRequestEpoch: string;
			/** ID of the StakedSui receipt object. */
			stakedSuiId: string;
			status: 'Pending';
	  }
	| {
			principal: string;
			stakeActiveEpoch: string;
			stakeRequestEpoch: string;
			/** ID of the StakedSui receipt object. */
			stakedSuiId: string;
			estimatedReward: string;
			status: 'Active';
	  }
	| {
			principal: string;
			stakeActiveEpoch: string;
			stakeRequestEpoch: string;
			/** ID of the StakedSui receipt object. */
			stakedSuiId: string;
			status: 'Unstaked';
	  };
/** An argument to a transaction in a programmable transaction block */
export type SuiArgument =
	| 'GasCoin' /** One of the input objects or primitive values (from `ProgrammableTransactionBlock` inputs) */
	| {
			Input: number;
	  } /** The result of another transaction (from `ProgrammableTransactionBlock` transactions) */
	| {
			Result: number;
	  } /**
	 * Like a `Result` but it accesses a nested result. Currently, the only usage of this is to access a
	 * value from a Move call with multiple return values.
	 */
	| {
			NestedResult: [number, number];
	  };
export type SuiCallArg =
	| {
			type: 'object';
			digest: string;
			objectId: string;
			objectType: 'immOrOwnedObject';
			version: string;
	  }
	| {
			type: 'object';
			initialSharedVersion: string;
			mutable: boolean;
			objectId: string;
			objectType: 'sharedObject';
	  }
	| {
			type: 'pure';
			value: unknown;
			valueType?: string | null;
	  };
export interface CoinMetadata {
	/** Number of decimal places the coin uses. */
	decimals: number;
	/** Description of the token */
	description: string;
	/** URL for the token logo */
	iconUrl?: string | null;
	/** Object id for the CoinMetadata object */
	id?: string | null;
	/** Name for the token */
	name: string;
	/** Symbol for the token */
	symbol: string;
}
export interface SuiExecutionResult {
	/** The value of any arguments that were mutably borrowed. Non-mut borrowed values are not included */
	mutableReferenceOutputs?: [SuiArgument, number[], string][];
	/** The return values from the transaction */
	returnValues?: [number[], string][];
}
export type SuiMoveAbility = 'Copy' | 'Drop' | 'Store' | 'Key';
export interface SuiMoveAbilitySet {
	abilities: SuiMoveAbility[];
}
export interface SuiMoveModuleId {
	address: string;
	name: string;
}
export interface SuiMoveNormalizedField {
	name: string;
	type: SuiMoveNormalizedType;
}
export interface SuiMoveNormalizedFunction {
	isEntry: boolean;
	parameters: SuiMoveNormalizedType[];
	return: SuiMoveNormalizedType[];
	typeParameters: SuiMoveAbilitySet[];
	visibility: SuiMoveVisibility;
}
export interface SuiMoveNormalizedModule {
	address: string;
	exposedFunctions: {
		[key: string]: SuiMoveNormalizedFunction;
	};
	fileFormatVersion: number;
	friends: SuiMoveModuleId[];
	name: string;
	structs: {
		[key: string]: SuiMoveNormalizedStruct;
	};
}
export interface SuiMoveNormalizedStruct {
	abilities: SuiMoveAbilitySet;
	fields: SuiMoveNormalizedField[];
	typeParameters: SuiMoveStructTypeParameter[];
}
export type SuiMoveNormalizedType =
	| 'Bool'
	| 'U8'
	| 'U16'
	| 'U32'
	| 'U64'
	| 'U128'
	| 'U256'
	| 'Address'
	| 'Signer'
	| {
			Struct: {
				address: string;
				module: string;
				name: string;
				typeArguments: SuiMoveNormalizedType[];
			};
	  }
	| {
			Vector: SuiMoveNormalizedType;
	  }
	| {
			TypeParameter: number;
	  }
	| {
			Reference: SuiMoveNormalizedType;
	  }
	| {
			MutableReference: SuiMoveNormalizedType;
	  };
export interface SuiMoveStructTypeParameter {
	constraints: SuiMoveAbilitySet;
	isPhantom: boolean;
}
export type SuiMoveVisibility = 'Private' | 'Public' | 'Friend';
export type SuiObjectDataFilter =
	| {
			MatchAll: SuiObjectDataFilter[];
	  }
	| {
			MatchAny: SuiObjectDataFilter[];
	  }
	| {
			MatchNone: SuiObjectDataFilter[];
	  } /** Query by type a specified Package. */
	| {
			Package: string;
	  } /** Query by type a specified Move module. */
	| {
			MoveModule: {
				/** the module name */
				module: string;
				/** the Move package ID */
				package: string;
			};
	  } /** Query by type */
	| {
			StructType: string;
	  }
	| {
			AddressOwner: string;
	  }
	| {
			ObjectOwner: string;
	  }
	| {
			ObjectId: string;
	  }
	| {
			ObjectIds: string[];
	  }
	| {
			Version: string;
	  };
export interface SuiObjectResponse {
	data?: SuiObjectData | null;
	error?: ObjectResponseError | null;
}
/**
 * The transaction for calling a Move function, either an entry function or a public function (which
 * cannot return references).
 */
export interface MoveCallSuiTransaction {
	/** The arguments to the function. */
	arguments?: SuiArgument[];
	/** The function to be called. */
	function: string;
	/** The specific module in the package containing the function. */
	module: string;
	/** The package containing the module and function. */
	package: string;
	/** The type arguments to the function. */
	type_arguments?: string[];
}
/**
 * This is the JSON-RPC type for the SUI system state object. It flattens all fields to make them
 * top-level fields such that it as minimum dependencies to the internal data structures of the SUI
 * system state type.
 */
export interface SuiSystemStateSummary {
	/** The list of active validators in the current epoch. */
	activeValidators: SuiValidatorSummary[];
	/** Map storing the number of epochs for which each validator has been below the low stake threshold. */
	atRiskValidators: [string, string][];
	/** The current epoch ID, starting from 0. */
	epoch: string;
	/** The duration of an epoch, in milliseconds. */
	epochDurationMs: string;
	/** Unix timestamp of the current epoch start */
	epochStartTimestampMs: string;
	/**
	 * ID of the object that maps from a staking pool ID to the inactive validator that has that pool as
	 * its staking pool.
	 */
	inactivePoolsId: string;
	/** Number of inactive staking pools. */
	inactivePoolsSize: string;
	/**
	 * Maximum number of active validators at any moment. We do not allow the number of validators in any
	 * epoch to go above this.
	 */
	maxValidatorCount: string;
	/** Lower-bound on the amount of stake required to become a validator. */
	minValidatorJoiningStake: string;
	/** ID of the object that contains the list of new validators that will join at the end of the epoch. */
	pendingActiveValidatorsId: string;
	/** Number of new validators that will join at the end of the epoch. */
	pendingActiveValidatorsSize: string;
	/** Removal requests from the validators. Each element is an index pointing to `active_validators`. */
	pendingRemovals: string[];
	/** The current protocol version, starting from 1. */
	protocolVersion: string;
	/** The reference gas price for the current epoch. */
	referenceGasPrice: string;
	/**
	 * Whether the system is running in a downgraded safe mode due to a non-recoverable bug. This is set
	 * whenever we failed to execute advance_epoch, and ended up executing advance_epoch_safe_mode. It can
	 * be reset once we are able to successfully execute advance_epoch.
	 */
	safeMode: boolean;
	/** Amount of computation rewards accumulated (and not yet distributed) during safe mode. */
	safeModeComputationRewards: string;
	/** Amount of non-refundable storage fee accumulated during safe mode. */
	safeModeNonRefundableStorageFee: string;
	/** Amount of storage rebates accumulated (and not yet burned) during safe mode. */
	safeModeStorageRebates: string;
	/** Amount of storage rewards accumulated (and not yet distributed) during safe mode. */
	safeModeStorageRewards: string;
	/** Balance of SUI set aside for stake subsidies that will be drawn down over time. */
	stakeSubsidyBalance: string;
	/** The amount of stake subsidy to be drawn down per epoch. This amount decays and decreases over time. */
	stakeSubsidyCurrentDistributionAmount: string;
	/**
	 * The rate at which the distribution amount decays at the end of each period. Expressed in basis
	 * points.
	 */
	stakeSubsidyDecreaseRate: number;
	/**
	 * This counter may be different from the current epoch number if in some epochs we decide to skip the
	 * subsidy.
	 */
	stakeSubsidyDistributionCounter: string;
	/** Number of distributions to occur before the distribution amount decays. */
	stakeSubsidyPeriodLength: string;
	/** The starting epoch in which stake subsidies start being paid out */
	stakeSubsidyStartEpoch: string;
	/** ID of the object that maps from staking pool's ID to the sui address of a validator. */
	stakingPoolMappingsId: string;
	/** Number of staking pool mappings. */
	stakingPoolMappingsSize: string;
	/**
	 * The non-refundable portion of the storage fund coming from storage reinvestment, non-refundable
	 * storage rebates and any leftover staking rewards.
	 */
	storageFundNonRefundableBalance: string;
	/** The storage rebates of all the objects on-chain stored in the storage fund. */
	storageFundTotalObjectStorageRebates: string;
	/** The current version of the system state data structure type. */
	systemStateVersion: string;
	/** Total amount of stake from all active validators at the beginning of the epoch. */
	totalStake: string;
	/**
	 * ID of the object that stores preactive validators, mapping their addresses to their `Validator`
	 * structs.
	 */
	validatorCandidatesId: string;
	/** Number of preactive validators. */
	validatorCandidatesSize: string;
	/**
	 * A validator can have stake below `validator_low_stake_threshold` for this many epochs before being
	 * kicked out.
	 */
	validatorLowStakeGracePeriod: string;
	/**
	 * Validators with stake amount below `validator_low_stake_threshold` are considered to have low stake
	 * and will be escorted out of the validator set after being below this threshold for more than
	 * `validator_low_stake_grace_period` number of epochs.
	 */
	validatorLowStakeThreshold: string;
	/** A map storing the records of validator reporting each other. */
	validatorReportRecords: [string, string[]][];
	/**
	 * Validators with stake below `validator_very_low_stake_threshold` will be removed immediately at
	 * epoch change, no grace period.
	 */
	validatorVeryLowStakeThreshold: string;
}
/** A single transaction in a programmable transaction block. */
export type SuiTransaction =
	/** A call to either an entry or a public Move function */
	| {
			MoveCall: MoveCallSuiTransaction;
	  } /**
	 * `(Vec<forall T:key+store. T>, address)` It sends n-objects to the specified address. These objects
	 * must have store (public transfer) and either the previous owner must be an address or the object
	 * must be newly created.
	 */
	| {
			TransferObjects: [SuiArgument[], SuiArgument];
	  } /**
	 * `(&mut Coin<T>, Vec<u64>)` -> `Vec<Coin<T>>` It splits off some amounts into a new coins with those
	 * amounts
	 */
	| {
			SplitCoins: [SuiArgument, SuiArgument[]];
	  } /** `(&mut Coin<T>, Vec<Coin<T>>)` It merges n-coins into the first coin */
	| {
			MergeCoins: [SuiArgument, SuiArgument[]];
	  } /**
	 * Publishes a Move package. It takes the package bytes and a list of the package's transitive
	 * dependencies to link against on-chain.
	 */
	| {
			Publish: string[];
	  } /** Upgrades a Move package */
	| {
			Upgrade: [string[], string, SuiArgument];
	  } /**
	 * `forall T: Vec<T> -> vector<T>` Given n-values of the same type, it constructs a vector. For non
	 * objects or an empty vector, the type tag must be specified.
	 */
	| {
			MakeMoveVec: [string | null, SuiArgument[]];
	  };
export type SuiTransactionBlockBuilderMode = 'Commit' | 'DevInspect';
/**
 * This is the JSON-RPC type for the SUI validator. It flattens all inner structures to top-level
 * fields so that they are decoupled from the internal definitions.
 */
export interface SuiValidatorSummary {
	commissionRate: string;
	description: string;
	/** ID of the exchange rate table object. */
	exchangeRatesId: string;
	/** Number of exchange rates in the table. */
	exchangeRatesSize: string;
	gasPrice: string;
	imageUrl: string;
	name: string;
	netAddress: string;
	networkPubkeyBytes: string;
	nextEpochCommissionRate: string;
	nextEpochGasPrice: string;
	nextEpochNetAddress?: string | null;
	nextEpochNetworkPubkeyBytes?: string | null;
	nextEpochP2pAddress?: string | null;
	nextEpochPrimaryAddress?: string | null;
	nextEpochProofOfPossession?: string | null;
	nextEpochProtocolPubkeyBytes?: string | null;
	nextEpochStake: string;
	nextEpochWorkerAddress?: string | null;
	nextEpochWorkerPubkeyBytes?: string | null;
	operationCapId: string;
	p2pAddress: string;
	/** Pending pool token withdrawn during the current epoch, emptied at epoch boundaries. */
	pendingPoolTokenWithdraw: string;
	/** Pending stake amount for this epoch. */
	pendingStake: string;
	/** Pending stake withdrawn during the current epoch, emptied at epoch boundaries. */
	pendingTotalSuiWithdraw: string;
	/** Total number of pool tokens issued by the pool. */
	poolTokenBalance: string;
	primaryAddress: string;
	projectUrl: string;
	proofOfPossessionBytes: string;
	protocolPubkeyBytes: string;
	/** The epoch stake rewards will be added here at the end of each epoch. */
	rewardsPool: string;
	/** The epoch at which this pool became active. */
	stakingPoolActivationEpoch?: string | null;
	/** The epoch at which this staking pool ceased to be active. `None` = {pre-active, active}, */
	stakingPoolDeactivationEpoch?: string | null;
	/** ID of the staking pool object. */
	stakingPoolId: string;
	/** The total number of SUI tokens in this pool. */
	stakingPoolSuiBalance: string;
	suiAddress: string;
	votingPower: string;
	workerAddress: string;
	workerPubkeyBytes: string;
}
export interface CoinSupply {
	value: string;
}
export interface TransactionBlock {
	data: TransactionBlockData;
	txSignatures: string[];
}
export interface TransactionBlockBytes {
	/** the gas objects to be used */
	gas: SuiObjectRef[];
	/** objects to be used in this transaction */
	inputObjects: InputObjectKind[];
	/** BCS serialized transaction data bytes without its type tag, as base-64 encoded string. */
	txBytes: string;
}
export type TransactionBlockData = {
	gasData: SuiGasData;
	messageVersion: 'v1';
	sender: string;
	transaction: SuiTransactionBlockKind;
};
export type TransactionEffects =
	/** The response from processing a transaction or a certified transaction */
	{
		/** ObjectRef and owner of new objects created. */
		created?: OwnedObjectRef[];
		/** Object Refs of objects now deleted (the old refs). */
		deleted?: SuiObjectRef[];
		/** The set of transaction digests this transaction depends on. */
		dependencies?: string[];
		/**
		 * The digest of the events emitted during execution, can be None if the transaction does not emit any
		 * event.
		 */
		eventsDigest?: string | null;
		/** The epoch when this transaction was executed. */
		executedEpoch: string;
		/**
		 * The updated gas object reference. Have a dedicated field for convenient access. It's also included
		 * in mutated.
		 */
		gasObject: OwnedObjectRef;
		gasUsed: GasCostSummary;
		messageVersion: 'v1';
		/**
		 * The version that every modified (mutated or deleted) object had before it was modified by this
		 * transaction.
		 */
		modifiedAtVersions?: TransactionBlockEffectsModifiedAtVersions[];
		/** ObjectRef and owner of mutated objects, including gas object. */
		mutated?: OwnedObjectRef[];
		/**
		 * The object references of the shared objects used in this transaction. Empty if no shared objects
		 * were used.
		 */
		sharedObjects?: SuiObjectRef[];
		/** The status of the execution */
		status: ExecutionStatus;
		/** The transaction digest */
		transactionDigest: string;
		/**
		 * ObjectRef and owner of objects that are unwrapped in this transaction. Unwrapped objects are objects
		 * that were wrapped into other objects in the past, and just got extracted out.
		 */
		unwrapped?: OwnedObjectRef[];
		/** Object refs of objects previously wrapped in other objects but now deleted. */
		unwrappedThenDeleted?: SuiObjectRef[];
		/** Object refs of objects now wrapped in other objects. */
		wrapped?: SuiObjectRef[];
	};
export interface TransactionBlockEffectsModifiedAtVersions {
	objectId: string;
	sequenceNumber: string;
}
export type SuiTransactionBlockKind =
	/** A system transaction that will update epoch information on-chain. */
	| {
			computation_charge: string;
			epoch: string;
			epoch_start_timestamp_ms: string;
			kind: 'ChangeEpoch';
			storage_charge: string;
			storage_rebate: string;
	  } /** A system transaction used for initializing the initial state of the chain. */
	| {
			kind: 'Genesis';
			objects: string[];
	  } /** A system transaction marking the start of a series of transactions scheduled as part of a checkpoint */
	| {
			commit_timestamp_ms: string;
			epoch: string;
			kind: 'ConsensusCommitPrologue';
			round: string;
	  } /** A series of transactions where the results of one transaction can be used in future transactions */
	| {
			/** Input objects or primitive values */
			inputs: SuiCallArg[];
			kind: 'ProgrammableTransaction';
			/**
			 * The transactions to be executed sequentially. A failure in any transaction will result in the
			 * failure of the entire programmable transaction block.
			 */
			transactions: SuiTransaction[];
	  };
export interface SuiTransactionBlockResponse {
	balanceChanges?: BalanceChange[] | null;
	/**
	 * The checkpoint number when this transaction was included and hence finalized. This is only returned
	 * in the read api, not in the transaction execution api.
	 */
	checkpoint?: string | null;
	confirmedLocalExecution?: boolean | null;
	digest: string;
	effects?: TransactionEffects | null;
	errors?: string[];
	events?: SuiEvent[] | null;
	objectChanges?: SuiObjectChange[] | null;
	/**
	 * BCS encoded [SenderSignedData] that includes input object references returns empty array if
	 * `show_raw_transaction` is false
	 */
	rawTransaction?: string;
	timestampMs?: string | null;
	/** Transaction input data */
	transaction?: TransactionBlock | null;
}
export interface SuiTransactionBlockResponseOptions {
	/** Whether to show balance_changes. Default to be False */
	showBalanceChanges?: boolean;
	/** Whether to show transaction effects. Default to be False */
	showEffects?: boolean;
	/** Whether to show transaction events. Default to be False */
	showEvents?: boolean;
	/** Whether to show transaction input data. Default to be False */
	showInput?: boolean;
	/** Whether to show object_changes. Default to be False */
	showObjectChanges?: boolean;
	/** Whether to show bcs-encoded transaction input data */
	showRawInput?: boolean;
}
export interface SuiTransactionBlockResponseQuery {
	/** If None, no filter will be applied */
	filter?: TransactionFilter | null;
	/** config which fields to include in the response, by default only digest is included */
	options?: SuiTransactionBlockResponseOptions | null;
}
export type TransactionFilter =
	/** Query by checkpoint. */
	| {
			Checkpoint: string;
	  } /** Query by move function. */
	| {
			MoveFunction: {
				function?: string | null;
				module?: string | null;
				package: string;
			};
	  } /** Query by input object. */
	| {
			InputObject: string;
	  } /** Query by changed object, including created, mutated and unwrapped objects. */
	| {
			ChangedObject: string;
	  } /** Query by sender address. */
	| {
			FromAddress: string;
	  } /** Query by recipient address. */
	| {
			ToAddress: string;
	  } /** Query by sender and recipient address. */
	| {
			FromAndToAddress: {
				from: string;
				to: string;
			};
	  } /** Query txs that have a given address as sender or recipient. */
	| {
			FromOrToAddress: {
				addr: string;
			};
	  } /** Query by transaction kind */
	| {
			TransactionKind: string;
	  } /** Query transactions of any given kind in the input. */
	| {
			TransactionKindIn: string[];
	  };
export interface TransferObjectParams {
	objectId: string;
	recipient: string;
}
/** Identifies a struct and the module it was defined in */
export interface TypeOrigin {
	module_name: string;
	package: string;
	struct_name: string;
}
/** Upgraded package info for the linkage table */
export interface UpgradeInfo {
	/** ID of the upgraded packages */
	upgraded_id: string;
	/** Version of the upgraded package */
	upgraded_version: string;
}
export interface ValidatorApy {
	address: string;
	apy: number;
}
export interface ValidatorsApy {
	apys: ValidatorApy[];
	epoch: string;
}
/** An zk login authenticator with all the necessary fields. */
export interface ZkLoginAuthenticator {
	aux_inputs: AuxInputs;
	proof: ZkLoginProof;
	public_inputs: PublicInputs;
	user_signature: Signature;
}
/** The zk login proof. */
export interface ZkLoginProof {
	pi_a: string[];
	pi_b: string[][];
	pi_c: string[];
	protocol: string;
}
