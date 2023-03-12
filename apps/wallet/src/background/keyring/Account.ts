// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { type SuiAddress } from '@mysten/sui.js';

import {
    type DerivedAccount,
    type SerializedDerivedAccount,
} from './DerivedAccount';
import {
    type ImportedAccount,
    type SerializedImportedAccount,
} from './ImportedAccount';
import {
    type LedgerAccount,
    type SerializedLedgerAccount,
} from './LedgerAccount';

export enum AccountType {
    IMPORTED = 'imported',
    DERIVED = 'derived',
    LEDGER = 'ledger',
}

export type SerializedAccount =
    | SerializedImportedAccount
    | SerializedDerivedAccount
    | SerializedLedgerAccount;

export interface Account {
    type: AccountType;
    address: SuiAddress;
    toJSON(): SerializedAccount;
}

export function isImportedOrDerivedAccount(
    account: Account
): account is ImportedAccount | DerivedAccount {
    return isImportedAccount(account) || isDerivedAccount(account);
}

export function isImportedAccount(
    account: Account
): account is ImportedAccount {
    return account.type === AccountType.IMPORTED;
}

export function isDerivedAccount(account: Account): account is DerivedAccount {
    return account.type === AccountType.DERIVED;
}

export function isLedgerAccount(account: Account): account is LedgerAccount {
    return account.type === AccountType.LEDGER;
}
