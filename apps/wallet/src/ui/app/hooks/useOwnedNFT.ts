// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { is, SuiObject, getObjectOwner, type SuiAddress } from '@mysten/sui.js';
import { useMemo } from 'react';

import { useGetObject } from './useGetObject';

export function useOwnedNFT(
    nftObjectId: string | null,
    address: SuiAddress | null
) {
    const data = useGetObject(nftObjectId!);
    const { data: objectData } = data;
    const objectDetails = useMemo(() => {
        if (!objectData || !is(objectData.details, SuiObject) || !address)
            return null;
        const objectOwner = getObjectOwner(objectData);
        return objectOwner &&
            objectOwner !== 'Immutable' &&
            'AddressOwner' in objectOwner &&
            objectOwner.AddressOwner === address
            ? objectData.details
            : null;
    }, [address, objectData]);
    return { ...data, data: objectDetails };
}
