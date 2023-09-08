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

import type { GetCheckpointsParams } from '@mysten/sui.js/client';
import type { UseSuiClientQueryOptions } from '../useSuiClientQuery.js';
import type { UseSuiClientInfiniteQueryOptions } from '../useSuiClientInfiniteQuery.js';
import { useSuiClientQuery } from '../useSuiClientQuery.js';
import { useSuiClientInfiniteQuery } from '../useSuiClientInfiniteQuery.js';

export function useCheckpoints(
	params: GetCheckpointsParams,
	options?: UseSuiClientQueryOptions<'getCheckpoints'>,
) {
	return useSuiClientQuery(
		{
			method: 'getCheckpoints',
			params,
		},
		options,
	);
}

export function useCheckpointsInfinite(
	params: GetCheckpointsParams,
	options?: UseSuiClientInfiniteQueryOptions<'getCheckpoints'>,
) {
	return useSuiClientInfiniteQuery(
		{
			method: 'getCheckpoints',
			params,
		},
		options,
	);
}
