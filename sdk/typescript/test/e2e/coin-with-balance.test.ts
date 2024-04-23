// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromHEX, toB64 } from '@mysten/bcs';
import { beforeEach, describe, expect, it } from 'vitest';

import { bcs } from '../../src/bcs';
import { Ed25519Keypair } from '../../src/keypairs/ed25519';
import { TransactionBlock } from '../../src/transactions';
import { coinWithBalance } from '../../src/transactions/intents/CoinWithBalance';
import { publishPackage, setup, TestToolbox } from './utils/setup';

describe('coinWithBalance', () => {
	let toolbox: TestToolbox;
	let publishToolbox: TestToolbox;
	let packageId: string;
	let testType: string;

	beforeEach(async () => {
		[toolbox, publishToolbox] = await Promise.all([setup(), setup()]);
		const packagePath = __dirname + '/./data/coin_metadata';
		({ packageId } = await publishPackage(packagePath, publishToolbox));
		testType = packageId + '::test::TEST';
	});

	it('works with sui', async () => {
		const txb = new TransactionBlock();
		const receiver = new Ed25519Keypair();

		txb.transferObjects([coinWithBalance('0x2::sui::SUI', 12345n)], receiver.toSuiAddress());
		txb.setSender(publishToolbox.keypair.toSuiAddress());

		expect(
			JSON.parse(
				await txb.toJSON({
					supportedIntents: ['CoinWithBalance'],
				}),
			),
		).toEqual({
			expiration: null,
			gasData: {
				budget: null,
				owner: null,
				payment: null,
				price: null,
			},
			inputs: [
				{
					Pure: {
						bytes: toB64(fromHEX(receiver.toSuiAddress())),
					},
				},
			],
			sender: publishToolbox.keypair.toSuiAddress(),
			transactions: [
				{
					Intent: {
						data: {
							balance: '12345',
							type: '0x2::sui::SUI',
						},
						inputs: {},
						name: 'CoinWithBalance',
					},
				},
				{
					TransferObjects: {
						objects: [
							{
								Result: 0,
							},
						],
						address: {
							Input: 0,
						},
					},
				},
			],
			version: 2,
		});

		expect(
			JSON.parse(
				await txb.toJSON({
					supportedIntents: [],
					client: toolbox.client,
				}),
			),
		).toEqual({
			expiration: null,
			gasData: {
				budget: null,
				owner: null,
				payment: null,
				price: null,
			},
			inputs: [
				{
					Pure: {
						bytes: toB64(fromHEX(receiver.toSuiAddress())),
					},
				},
				{
					Pure: {
						bytes: toB64(bcs.u64().serialize(12345).toBytes()),
					},
				},
			],
			sender: publishToolbox.keypair.toSuiAddress(),
			transactions: [
				{
					SplitCoins: {
						coin: {
							GasCoin: true,
						},
						amounts: [
							{
								Input: 1,
							},
						],
					},
				},
				{
					TransferObjects: {
						objects: [
							{
								NestedResult: [0, 0],
							},
						],
						address: {
							Input: 0,
						},
					},
				},
			],
			version: 2,
		});

		const result = await toolbox.client.signAndExecuteTransactionBlock({
			transactionBlock: txb,
			signer: publishToolbox.keypair,
			options: {
				showEffects: true,
				showBalanceChanges: true,
			},
		});

		expect(result.effects?.status.status).toBe('success');
		expect(
			result.balanceChanges?.find(
				(change) =>
					typeof change.owner === 'object' &&
					'AddressOwner' in change.owner &&
					change.owner.AddressOwner === receiver.toSuiAddress(),
			),
		).toEqual({
			amount: '12345',
			coinType: '0x2::sui::SUI',
			owner: {
				AddressOwner: receiver.toSuiAddress(),
			},
		});
	});

	it('works with custom coin', async () => {
		const txb = new TransactionBlock();
		const receiver = new Ed25519Keypair();

		txb.transferObjects([coinWithBalance(testType, 1n)], receiver.toSuiAddress());
		txb.setSender(publishToolbox.keypair.toSuiAddress());

		expect(
			JSON.parse(
				await txb.toJSON({
					supportedIntents: ['CoinWithBalance'],
				}),
			),
		).toEqual({
			expiration: null,
			gasData: {
				budget: null,
				owner: null,
				payment: null,
				price: null,
			},
			inputs: [
				{
					Pure: {
						bytes: toB64(fromHEX(receiver.toSuiAddress())),
					},
				},
			],
			sender: publishToolbox.keypair.toSuiAddress(),
			transactions: [
				{
					Intent: {
						data: {
							balance: '1',
							type: testType,
						},
						inputs: {},
						name: 'CoinWithBalance',
					},
				},
				{
					TransferObjects: {
						objects: [
							{
								Result: 0,
							},
						],
						address: {
							Input: 0,
						},
					},
				},
			],
			version: 2,
		});

		expect(
			JSON.parse(
				await txb.toJSON({
					supportedIntents: [],
					client: publishToolbox.client,
				}),
			),
		).toEqual({
			expiration: null,
			gasData: {
				budget: null,
				owner: null,
				payment: null,
				price: null,
			},
			inputs: [
				{
					Pure: {
						bytes: toB64(fromHEX(receiver.toSuiAddress())),
					},
				},
				{
					Object: {
						ImmOrOwnedObject: expect.anything(),
					},
				},
				{
					Object: {
						ImmOrOwnedObject: expect.anything(),
					},
				},
				{
					Pure: {
						bytes: toB64(bcs.u64().serialize(1).toBytes()),
					},
				},
			],
			sender: publishToolbox.keypair.toSuiAddress(),
			transactions: [
				{
					MergeCoins: {
						destination: {
							Input: 1,
						},
						sources: [
							{
								Input: 2,
							},
						],
					},
				},
				{
					SplitCoins: {
						coin: {
							Input: 1,
						},
						amounts: [
							{
								Input: 3,
							},
						],
					},
				},
				{
					TransferObjects: {
						objects: [{ NestedResult: [1, 0] }],
						address: {
							Input: 0,
						},
					},
				},
			],
			version: 2,
		});

		const result = await toolbox.client.signAndExecuteTransactionBlock({
			transactionBlock: txb,
			signer: publishToolbox.keypair,
			options: {
				showEffects: true,
				showBalanceChanges: true,
			},
		});

		expect(result.effects?.status.status).toBe('success');
		expect(
			result.balanceChanges?.find(
				(change) =>
					typeof change.owner === 'object' &&
					'AddressOwner' in change.owner &&
					change.owner.AddressOwner === receiver.toSuiAddress(),
			),
		).toEqual({
			amount: '1',
			coinType: testType,
			owner: {
				AddressOwner: receiver.toSuiAddress(),
			},
		});
	});

	it('works with multiple coins', async () => {
		const txb = new TransactionBlock();
		const receiver = new Ed25519Keypair();

		txb.transferObjects(
			[
				coinWithBalance(testType, 1n),
				coinWithBalance(testType, 2n),
				coinWithBalance('0x2::sui::SUI', 3n),
				coinWithBalance('0x2::sui::SUI', 4n),
			],
			receiver.toSuiAddress(),
		);

		txb.setSender(publishToolbox.keypair.toSuiAddress());

		expect(
			JSON.parse(
				await txb.toJSON({
					supportedIntents: ['CoinWithBalance'],
				}),
			),
		).toEqual({
			expiration: null,
			gasData: {
				budget: null,
				owner: null,
				payment: null,
				price: null,
			},
			inputs: [
				{
					Pure: {
						bytes: toB64(fromHEX(receiver.toSuiAddress())),
					},
				},
			],
			sender: publishToolbox.keypair.toSuiAddress(),
			transactions: [
				{
					Intent: {
						data: {
							balance: '1',
							type: testType,
						},
						inputs: {},
						name: 'CoinWithBalance',
					},
				},
				{
					Intent: {
						data: {
							balance: '2',
							type: testType,
						},
						inputs: {},
						name: 'CoinWithBalance',
					},
				},
				{
					Intent: {
						data: {
							balance: '3',
							type: '0x2::sui::SUI',
						},
						inputs: {},
						name: 'CoinWithBalance',
					},
				},
				{
					Intent: {
						data: {
							balance: '4',
							type: '0x2::sui::SUI',
						},
						inputs: {},
						name: 'CoinWithBalance',
					},
				},
				{
					TransferObjects: {
						objects: [
							{
								Result: 0,
							},
							{
								Result: 1,
							},
							{
								Result: 2,
							},
							{
								Result: 3,
							},
						],
						address: {
							Input: 0,
						},
					},
				},
			],
			version: 2,
		});

		expect(
			JSON.parse(
				await txb.toJSON({
					supportedIntents: [],
					client: publishToolbox.client,
				}),
			),
		).toEqual({
			expiration: null,
			gasData: {
				budget: null,
				owner: null,
				payment: null,
				price: null,
			},
			inputs: [
				{
					Pure: {
						bytes: toB64(fromHEX(receiver.toSuiAddress())),
					},
				},
				{
					Object: {
						ImmOrOwnedObject: expect.anything(),
					},
				},
				{
					Object: {
						ImmOrOwnedObject: expect.anything(),
					},
				},
				{
					Pure: {
						bytes: toB64(bcs.u64().serialize(1).toBytes()),
					},
				},
				{
					Pure: {
						bytes: toB64(bcs.u64().serialize(2).toBytes()),
					},
				},
				{
					Pure: {
						bytes: toB64(bcs.u64().serialize(3).toBytes()),
					},
				},
				{
					Pure: {
						bytes: toB64(bcs.u64().serialize(4).toBytes()),
					},
				},
			],
			sender: publishToolbox.keypair.toSuiAddress(),
			transactions: [
				{
					MergeCoins: {
						destination: {
							Input: 1,
						},
						sources: [
							{
								Input: 2,
							},
						],
					},
				},
				{
					SplitCoins: {
						coin: {
							Input: 1,
						},
						amounts: [
							{
								Input: 3,
							},
						],
					},
				},
				{
					SplitCoins: {
						coin: {
							Input: 1,
						},
						amounts: [
							{
								Input: 4,
							},
						],
					},
				},
				{
					SplitCoins: {
						coin: {
							GasCoin: true,
						},
						amounts: [
							{
								Input: 5,
							},
						],
					},
				},
				{
					SplitCoins: {
						coin: {
							GasCoin: true,
						},
						amounts: [
							{
								Input: 6,
							},
						],
					},
				},
				{
					TransferObjects: {
						objects: [
							{ NestedResult: [1, 0] },
							{ NestedResult: [2, 0] },
							{ NestedResult: [3, 0] },
							{ NestedResult: [4, 0] },
						],
						address: {
							Input: 0,
						},
					},
				},
			],
			version: 2,
		});

		const result = await toolbox.client.signAndExecuteTransactionBlock({
			transactionBlock: txb,
			signer: publishToolbox.keypair,
			options: {
				showEffects: true,
				showBalanceChanges: true,
			},
		});

		expect(result.effects?.status.status).toBe('success');
		expect(
			result.balanceChanges?.filter(
				(change) =>
					typeof change.owner === 'object' &&
					'AddressOwner' in change.owner &&
					change.owner.AddressOwner === receiver.toSuiAddress(),
			),
		).toEqual([
			{
				amount: '7',
				coinType: '0x2::sui::SUI',
				owner: {
					AddressOwner: receiver.toSuiAddress(),
				},
			},
			{
				amount: '3',
				coinType: testType,
				owner: {
					AddressOwner: receiver.toSuiAddress(),
				},
			},
		]);
	});
});