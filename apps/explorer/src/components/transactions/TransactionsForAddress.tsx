// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useSuiClient } from '@mysten/dapp-kit';
import { type SuiTransactionBlockResponse } from '@mysten/sui.js/client';
import { LoadingIndicator } from '@mysten/ui';
import { useQuery } from '@tanstack/react-query';

import { genTableDataFromTxData } from './TxCardUtils';
import { AddressResultEmptyState } from '~/pages/address-result/AddressResultEmptyState';
import { Banner } from '~/ui/Banner';
import { TableCard } from '~/ui/TableCard';

interface Props {
	address: string;
	type: 'object' | 'address';
}

export function TransactionsForAddress({ address, type }: Props) {
	const client = useSuiClient();

	const { data, isLoading, isError } = useQuery({
		queryKey: ['transactions-for-address', address, type],
		queryFn: async () => {
			const filters =
				type === 'object'
					? [{ InputObject: address }, { ChangedObject: address }]
					: [{ ToAddress: address }, { FromAddress: address }];

			const results = await Promise.all(
				filters.map((filter) =>
					client.queryTransactionBlocks({
						filter,
						order: 'descending',
						limit: 100,
						options: {
							showEffects: true,
							showInput: true,
						},
					}),
				),
			);

			const inserted = new Map();
			const uniqueList: SuiTransactionBlockResponse[] = [];

			[...results[0].data, ...results[1].data]
				.sort((a, b) => Number(b.timestampMs ?? 0) - Number(a.timestampMs ?? 0))
				.forEach((txb) => {
					if (inserted.get(txb.digest)) return;
					uniqueList.push(txb);
					inserted.set(txb.digest, true);
				});

			return uniqueList;
		},
	});

	if (isLoading) {
		return (
			<div>
				<LoadingIndicator />
			</div>
		);
	}

	if (isError) {
		return (
			<Banner variant="error" fullWidth>
				Transactions could not be extracted on the following specified address: {address}
			</Banner>
		);
	}

	const tableData = genTableDataFromTxData(data);
	const hasTxns = data?.length > 0;

	if (!hasTxns) {
		return <AddressResultEmptyState copy="No transactions found" />;
	}

	return <TableCard noBorderBottom data={tableData.data} columns={tableData.columns} />;
}
