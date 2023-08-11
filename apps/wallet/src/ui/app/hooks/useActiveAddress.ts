// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import useAppSelector from './useAppSelector';
import { activeAddressSelector } from '../redux/slices/account';

/**
 * @deprecated use accounts-v2/useActiveAccount
 */
export function useActiveAddress() {
	return useAppSelector(activeAddressSelector);
}
