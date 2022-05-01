// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ObjectOwner, SuiAddress, TransactionDigest } from './common';
import { ObjectId, RawObjectRef } from './objects';

export type Transfer = {
  recipient: string;
  object_ref: RawObjectRef;
};
export type RawAuthoritySignInfo = [AuthorityName, AuthoritySignature];

export type TransactionKindName = 'Transfer' | 'Publish' | 'Call';
export type SingleTransactionKind =
  | { Transfer: Transfer }
  | { Publish: MoveModulePublish }
  | { Call: MoveCall };
export type TransactionKind =
  | { Single: SingleTransactionKind }
  | { Batch: SingleTransactionKind[] };
export type TransactionData = {
  kind: TransactionKind;
  sender: string;
  gas_payment: RawObjectRef;
  gas_budget: number;
};

// TODO: support u64
export type EpochId = number;

export type AuthorityQuorumSignInfo = {
  epoch: EpochId;
  signatures: RawAuthoritySignInfo[];
};

export type CertifiedTransaction = {
  data: TransactionData;
  tx_signature: string;
  auth_sign_info: AuthorityQuorumSignInfo;
};

export type GasCostSummary = {
  computation_cost: number;
  storage_cost: number;
  storage_rebate: number;
};

export type ExecutionStatus =
  | { Success: { gas_cost: GasCostSummary } }
  | { Failure: { gas_cost: GasCostSummary; error: string } };

// TODO: change the tuple to struct from the server end
export type OwnedObjectRef = [RawObjectRef, ObjectOwner];

export type TransactionEffects = {
  status: ExecutionStatus;
  shared_objects: RawObjectRef[];
  transaction_digest: TransactionDigest;
  created: OwnedObjectRef[];
  mutated: OwnedObjectRef[];
  unwrapped: OwnedObjectRef[];
  deleted: RawObjectRef[];
  wrapped: RawObjectRef[];
  gas_object: OwnedObjectRef;
  events: Event[];
  dependencies: TransactionDigest[];
};

export type TransactionEffectsResponse = {
  certificate: CertifiedTransaction;
  effects: TransactionEffects;
};

export type GatewayTxSeqNumber = number;

export type GetTxnDigestsResponse = [GatewayTxSeqNumber, TransactionDigest][];

export type MoveModulePublish = {
  modules: any;
};

export type Event = {
  type_: StructTag;
  contents: string;
};

export type StructTag = {
  address: SuiAddress;
  module: string;
  name: string;
  type_args: MoveTypeTag[];
};
export type MoveTypeTag =
  | 'bool'
  | 'u8'
  | 'u64'
  | 'u128'
  | 'address'
  | 'signer'
  | { vector: MoveTypeTag[] }
  | { struct: StructTag };

export type MoveCall = {
  package: RawObjectRef;
  module: string;
  function: string;
  type_arguments: MoveTypeTag[];
  arguments: MoveCallArg[];
};

export type MoveCallArg =
  // TODO: convert to Uint8Array
  | { Pure: number[] }
  | { ImmOrOwnedObject: RawObjectRef }
  | { SharedObject: ObjectId };

export type EmptySignInfo = object;
export type AuthorityName = string;
export type AuthoritySignature = string;

/* ---------------------------- Helper functions ---------------------------- */

export function getSingleTransactionKind(
  data: TransactionData
): SingleTransactionKind | undefined {
  return 'Single' in data.kind ? data.kind.Single : undefined;
}

export function getTransferTransaction(
  data: TransactionData
): Transfer | undefined {
  const tx = getSingleTransactionKind(data);
  return tx && 'Transfer' in tx ? tx.Transfer : undefined;
}

export function getPublishTransaction(
  data: TransactionData
): MoveModulePublish | undefined {
  const tx = getSingleTransactionKind(data);
  return tx && 'Publish' in tx ? tx.Publish : undefined;
}

export function getMoveCallTransaction(
  data: TransactionData
): MoveCall | undefined {
  const tx = getSingleTransactionKind(data);
  return tx && 'Call' in tx ? tx.Call : undefined;
}

export function getTransactionKind(
  data: TransactionData
): TransactionKindName | undefined {
  const tx = getSingleTransactionKind(data);
  return tx && (Object.keys(tx)[0] as TransactionKindName);
}
