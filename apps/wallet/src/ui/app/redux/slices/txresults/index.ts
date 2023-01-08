// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import {
    getTransactionDigest,
    getTransactions,
    getTransactionKindName,
    getTransferObjectTransaction,
    getExecutionStatusType,
    getTotalGasUsed,
    getExecutionStatusError,
    getMoveCallTransaction,
    getTransactionSender,
    getObjectId,
    getObjectFields,
    Coin,
    is,
    SuiObject,
} from '@mysten/sui.js';
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';

import { notEmpty, getEventsSummary, getAmount } from '_helpers';

import type {
    GetTxnDigestsResponse,
    TransactionKindName,
    ExecutionStatusType,
    TransactionEffects,
    SuiEvent,
} from '@mysten/sui.js';
import type { AppThunkConfig } from '_store/thunk-extras';

export type TxResultState = {
    to?: string;
    txId: string;
    status: ExecutionStatusType;
    txGas: number;
    kind: TransactionKindName | undefined;
    from: string;
    amount?: number;
    timestampMs?: number;
    url?: string;
    balance?: number;
    objectId?: string;
    description?: string;
    name?: string;
    isSender?: boolean;
    error?: string;
    callFunctionName?: string;
    coinSymbol?: string;
    coinType?: string;
};

interface TransactionManualState {
    loading: boolean;
    error: false | { code?: string; message?: string; name?: string };
    latestTx: TxResultState[];
    recentAddresses: string[];
}

const initialState: TransactionManualState = {
    loading: true,
    latestTx: [],
    recentAddresses: [],
    error: false,
};
type TxResultByAddress = TxResultState[];

// Remove duplicate transactionsId, reduces the number of RPC calls
const deduplicate = (results: string[] | undefined) =>
    results
        ? results.filter((value, index, self) => self.indexOf(value) === index)
        : [];

const moveCallTxnName = (moveCallFunctionName?: string): string | null =>
    moveCallFunctionName ? moveCallFunctionName.replace(/_/g, ' ') : null;

// Get objectId from a transaction effects -> events where recipient is the address
const getTxnEffectsEventID = (
    txEffects: TransactionEffects,
    address: string
): string[] => {
    const events = txEffects?.events || [];
    const objectIDs = events
        ?.map((event: SuiEvent) => {
            const data = Object.values(event).find(
                (itm) => itm?.recipient?.AddressOwner === address
            );
            return data?.objectId;
        })
        .filter(notEmpty);
    return objectIDs;
};

// Rewrite using react query
export const getTransactionsByAddress = createAsyncThunk<
    TxResultByAddress,
    void,
    AppThunkConfig
>(
    'sui-transactions/get-transactions-by-address',
    async (
        _,
        { getState, dispatch, extra: { api } }
    ): Promise<TxResultByAddress> => {
        const address = getState().account.address;

        if (!address) return [];

        // Get all transactions txId for address
        const transactions: GetTxnDigestsResponse =
            await api.instance.fullNode.getTransactionsForAddress(
                address,
                true
            );

        if (!transactions || !transactions.length) {
            return [];
        }

        const txEffs =
            await api.instance.fullNode.getTransactionWithEffectsBatch(
                deduplicate(transactions)
            );

        const txResults = txEffs.map((txEff) => {
            const digest = transactions.filter(
                (transactionId) =>
                    transactionId === getTransactionDigest(txEff.certificate)
            )[0];

            const txns = getTransactions(txEff.certificate);

            // TODO handle batch transactions
            if (txns.length > 1) {
                return null;
            }

            const txn = txns[0];
            const txKind = getTransactionKindName(txn);
            const txTransferObject = getTransferObjectTransaction(txn);
            const amountByRecipient = getAmount(txn);
            const sender = getTransactionSender(txEff.certificate);
            const senderData = amountByRecipient?.find(
                ({ recipientAddress }) => recipientAddress === sender
            );
            const recipients =
                amountByRecipient &&
                amountByRecipient?.filter(
                    ({ recipientAddress }) => recipientAddress !== sender
                );

            const moveCallTxn = getMoveCallTransaction(txn);
            const metaDataObjectId = getTxnEffectsEventID(
                txEff.effects,
                address
            );

            const { coins: eventsSummary } = getEventsSummary(
                txEff.effects,
                address
            );
            const amountTransfers = eventsSummary.reduce(
                (acc, { amount }) => acc + amount,
                0
            );

            return {
                txId: digest,
                status: getExecutionStatusType(txEff),
                txGas: getTotalGasUsed(txEff),
                kind: txKind,
                callFunctionName: moveCallTxnName(moveCallTxn?.function),
                from: sender,
                isSender: sender === address,
                error: getExecutionStatusError(txEff),
                timestampMs: txEff.timestamp_ms,
                ...(recipients && { to: recipients[0].recipientAddress }),
                ...((senderData?.amount || amountTransfers) && {
                    amount: Math.abs(senderData?.amount || amountTransfers),
                }),
                ...((txTransferObject?.objectRef?.objectId ||
                    metaDataObjectId.length > 0) && {
                    objectId: txTransferObject?.objectRef?.objectId
                        ? [txTransferObject?.objectRef?.objectId]
                        : [...metaDataObjectId],
                }),
            };
        });

        const objectIds = txResults
            .map((itm) => itm?.objectId)
            .filter(notEmpty);
        const objectIDs = [...new Set(objectIds.flat())];
        const getObjectBatch = await api.instance.fullNode.getObjectBatch(
            objectIDs
        );
        const txObjects = getObjectBatch.filter(
            ({ status }) => status === 'Exists'
        );

        const txnResp = txResults.map((itm) => {
            const txnObjects =
                txObjects && itm?.objectId && Array.isArray(txObjects)
                    ? txObjects
                          .filter(({ status }) => status === 'Exists')
                          .find((obj) =>
                              itm.objectId?.includes(getObjectId(obj))
                          )
                    : null;

            const { details } = txnObjects || {};

            const coinType =
                txnObjects &&
                is(details, SuiObject) &&
                Coin.getCoinTypeArg(txnObjects);

            const fields =
                txnObjects && is(details, SuiObject)
                    ? getObjectFields(txnObjects)
                    : null;

            return {
                ...itm,
                coinType,
                coinSymbol: coinType && Coin.getCoinSymbol(coinType),
                ...(fields &&
                    fields.url && {
                        description:
                            typeof fields.description === 'string' &&
                            fields.description,
                        name: typeof fields.name === 'string' && fields.name,
                        url: fields.url,
                    }),
                ...(fields && {
                    balance: fields.balance,
                }),
            };
        });

        return txnResp as TxResultByAddress;
    }
);

const txSlice = createSlice({
    name: 'txresult',
    initialState,
    reducers: {},
    extraReducers: (builder) => {
        builder
            .addCase(getTransactionsByAddress.fulfilled, (state, action) => {
                state.loading = false;
                state.error = false;
                state.latestTx = action.payload;
                // Add recent addresses to the list
                const recentAddresses = action.payload.map((tx) => [
                    tx?.to as string,
                    tx.from as string,
                ]);
                // Remove duplicates
                state.recentAddresses = [
                    ...new Set(recentAddresses.flat().filter((itm) => itm)),
                ];
            })
            .addCase(getTransactionsByAddress.pending, (state, action) => {
                state.loading = true;
                state.latestTx = [];
                state.recentAddresses = [];
            })
            .addCase(
                getTransactionsByAddress.rejected,
                (state, { error: { code, name, message } }) => {
                    state.loading = false;
                    state.error = { code, message, name };
                    state.latestTx = [];
                    state.recentAddresses = [];
                }
            );
    },
});

export default txSlice.reducer;
