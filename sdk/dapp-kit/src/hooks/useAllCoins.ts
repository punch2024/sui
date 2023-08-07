// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 *  ######################################
 *  ### DO NOT EDIT THIS FILE DIRECTLY ###
 *  ######################################
 *
 * This file is generated from:
 * /crates/sui-open-rpc/spec/openrpc.json
 */

import type { GetAllCoinsParams } from '@mysten/sui.js/client';
import type { UseSuiClientQueryOptions } from './useSuiClientQuery.js';
import { useSuiClientQuery } from './useSuiClientQuery.js';

export function useAllCoins(
	params: GetAllCoinsParams,
	options?: UseSuiClientQueryOptions<'getAllCoins'>,
) {
	return useSuiClientQuery(
		{
			method: 'getAllCoins',
			params,
		},
		options,
	);
}
