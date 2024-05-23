// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { bcs } from '@mysten/sui.js/bcs';
import type { SuiClient } from '@mysten/sui.js/client';
import { SuiGraphQLClient } from '@mysten/sui.js/graphql';
import { graphql } from '@mysten/sui.js/graphql/schemas/2024.4';
import { fromB64, normalizeSuiAddress } from '@mysten/sui.js/utils';

import { ZkSendLink } from './claim.js';
import type { ZkBagContractOptions } from './zk-bag.js';
import { MAINNET_CONTRACT_IDS } from './zk-bag.js';

const ListCreatedLinksQuery = graphql(`
	query listCreatedLinks($address: SuiAddress!, $function: String!, $cursor: String) {
		transactionBlocks(
			last: 10
			before: $cursor
			filter: { signAddress: $address, function: $function, kind: PROGRAMMABLE_TX }
		) {
			pageInfo {
				startCursor
				hasPreviousPage
			}
			nodes {
				effects {
					timestamp
				}
				digest
				bcs
			}
		}
	}
`);

export async function listCreatedLinks({
	address,
	cursor,
	network,
	contract = MAINNET_CONTRACT_IDS,
	fetch: fetchFn,
	...linkOptions
}: {
	address: string;
	contract?: ZkBagContractOptions;
	cursor?: string;
	network?: 'mainnet' | 'testnet';

	// Link options:
	host?: string;
	path?: string;
	claimApi?: string;
	client?: SuiClient;
	fetch?: typeof fetch;
}) {
	const gqlClient = new SuiGraphQLClient({
		url:
			network === 'testnet'
				? 'https://sui-testnet.mystenlabs.com/graphql'
				: 'https://sui-mainnet.mystenlabs.com/graphql',
		fetch: fetchFn,
	});

	const packageId = normalizeSuiAddress(contract.packageId);

	const page = await gqlClient.query({
		query: ListCreatedLinksQuery,
		variables: {
			address,
			cursor,
			function: `${packageId}::zk_bag::new`,
		},
	});

	const transactionBlocks = page.data?.transactionBlocks;

	if (!transactionBlocks || page.errors?.length) {
		throw new Error('Failed to load created links');
	}

	const links = (
		await Promise.all(
			transactionBlocks.nodes.map(async (node) => {
				if (!node.bcs) {
					return null;
				}

				const kind = bcs.SenderSignedData.parse(fromB64(node.bcs))?.[0]?.intentMessage.value.V1
					.kind;

				if (!kind || !('ProgrammableTransaction' in kind)) {
					return null;
				}

				const { inputs, transactions: commands } = kind.ProgrammableTransaction;

				const fn = commands.find(
					(command) =>
						command.kind === 'MoveCall' && command.target !== `${packageId}::zk_bag::new`,
				);

				if (fn?.kind !== 'MoveCall') {
					return null;
				}

				const addressArg = fn.arguments[1];

				if (addressArg.kind !== 'Input') {
					throw new Error('Invalid address argument');
				}

				const input = inputs[addressArg.index];

				if (!('Pure' in input)) {
					throw new Error('Expected Address input to be a Pure value');
				}

				const address = bcs.Address.parse(Uint8Array.from(input.Pure));

				const link = new ZkSendLink({
					network,
					address,
					contract,
					isContractLink: true,
					...linkOptions,
				});

				await link.loadAssets();

				return {
					link,
					claimed: !!link.claimed,
					assets: link.assets!,
					digest: node.digest,
					createdAt: node.effects?.timestamp!,
				};
			}),
		)
	).reverse();

	return {
		cursor: transactionBlocks.pageInfo.startCursor,
		hasNextPage: transactionBlocks.pageInfo.hasPreviousPage,
		links: links.filter((link): link is NonNullable<typeof link> => link !== null),
	};
}
