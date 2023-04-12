// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useRpcClient } from '@mysten/core';
import { useInfiniteQuery } from '@tanstack/react-query';

import type { SuiAddress } from '@mysten/sui.js';

const MAX_TRANSACTIONS_PER_REQUEST = 100;

// Fetch all coins for an address, this will keep calling the API until all coins are fetched
export function useGetTransactionBlocks(address: SuiAddress, isFrom?: boolean) {
    const rpc = useRpcClient();
    const filter = isFrom ? { FromAddress: address } : { ToAddress: address }

    return useInfiniteQuery(
        ['get-transaction-blocks', address],
        async ({ pageParam }) =>
            await rpc.queryTransactionBlocks(
                {
                    cursor: pageParam ? pageParam.cursor : null,
                    filter,
                    order: 'descending',
                    limit: MAX_TRANSACTIONS_PER_REQUEST,
                    options: {
                        showEffects: true,
                        showBalanceChanges: true,
                        showInput: true,
                    },
                }
            ),
        {
            getNextPageParam: (lastPage) =>
                lastPage?.hasNextPage
                    ? {
                        cursor: lastPage.nextCursor,
                    }
                    : false,
            enabled: !!address,
        }
    );
}
