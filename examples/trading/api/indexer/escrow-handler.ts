// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { SuiEvent } from '@mysten/sui.js/client';
import { Escrow } from '@prisma/client';

import { prisma } from '../db';

type Optional<T, K extends keyof T> = Pick<Partial<T>, K> & Omit<T, K>;

type EscrowEvent = EscrowCreated | EscrowCancelled | EscrowSwapped;

type EscrowCreated = {
	sender: string;
	recipient: string;
	escrow_id: string;
	key_id: string;
};

type EscrowSwapped = {
	escrow_id: string;
};

type EscrowCancelled = {
	escrow_id: string;
};

/** Handles all events emitted by the `lock` module. */
export const handleEscrowObjects = async (events: SuiEvent[]) => {
	const updates: Record<
		string,
		Optional<Escrow, 'id' | 'keyId' | 'cancelled' | 'sender' | 'recipient' | 'swapped'>
	> = {};

	for (const event of events) {
		const data = event.parsedJson as EscrowEvent;

		if (!Object.hasOwn(updates, data.escrow_id)) {
			updates[data.escrow_id] = {
				objectId: data.escrow_id,
			};
		}

		// Escrow cancellation case
		if (event.type.endsWith('::EscrowCancelled')) {
			const data = event.parsedJson as EscrowCancelled;
			updates[data.escrow_id].cancelled = true;
			continue;
		}

		// Escrow swap case
		if (event.type.endsWith('::EscrowSwapped')) {
			const data = event.parsedJson as EscrowSwapped;
			updates[data.escrow_id].swapped = true;
			continue;
		}

		const creationData = event.parsedJson as EscrowCreated;

		// Handle creation event
		updates[data.escrow_id].sender = creationData.sender;
		updates[data.escrow_id].recipient = creationData.recipient;
		updates[data.escrow_id].keyId = creationData.key_id;
	}

	// SQLite does not support bulk insertion & conflict handling, so we have to insert 1 by 1.
	//  Always use a single `bulkInsert` query with proper `onConflict` handling in production.
	const promises = Object.values(updates).map((update) =>
		prisma.escrow.upsert({
			where: {
				objectId: update.objectId,
			},
			create: update,
			update,
		}),
	);
	await Promise.all(promises);
};
