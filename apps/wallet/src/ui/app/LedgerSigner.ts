// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { toB64 } from '@mysten/bcs';
import {
    SignerWithProvider,
    Ed25519PublicKey,
    toSerializedSignature,
} from '@mysten/sui.js';

import type Transport from '@ledgerhq/hw-transport';
import type AppSui from 'hw-app-sui';
import type {
    Provider,
    SignaturePubkeyPair,
    SuiAddress,
    TxnDataSerializer,
    SerializedSignature,
    SignatureScheme,
} from '@mysten/sui.js';

export class LedgerSigner extends SignerWithProvider {
    readonly #appSui: Promise<AppSui>;
    readonly #derivationPath: string;
    readonly #signatureScheme: SignatureScheme = 'ED25519';

    constructor(
        appSui: Promise<AppSui>,
        derivationPath: string,
        provider?: Provider,
        serializer?: TxnDataSerializer
    ) {
        super(provider, serializer);
        this.#appSui = appSui;
        this.#derivationPath = derivationPath;
    }

    async getAddress(): Promise<string> {
        return (
            '0x' +
            new Buffer(
                (
                    await (
                        await this.#appSui
                    ).getPublicKey(this.#derivationPath)
                ).address
            ).toString('hex')
        );
    }

    async getPublicKey(): Promise<Ed25519PublicKey> {
        const { publicKey } = await (
            await this.#appSui
        ).getPublicKey(this.#derivationPath);
        return new Ed25519PublicKey(publicKey);
    }

    async signData(data: Uint8Array): Promise<SerializedSignature> {
        const { signature } = await (
            await this.#appSui
        ).signTransaction(this.#derivationPath, data);
        const pubKey = await this.getPublicKey();
        return toSerializedSignature({
            signature,
            signatureScheme: this.#signatureScheme,
            pubKey,
        });
    }

    connect(provider: Provider): SignerWithProvider {
        return new LedgerSigner(this.#appSui, this.#derivationPath, provider);
    }
}
