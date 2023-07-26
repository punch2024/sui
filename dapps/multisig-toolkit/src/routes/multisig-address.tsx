// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import {
	PubkeyWeightPair,
	publicKeyFromSerialized,
	SIGNATURE_FLAG_TO_SCHEME,
	toB64,
	toMultiSigAddress,
	SignatureScheme,
	fromB64,
} from '@mysten/sui.js';
import { AlertCircle } from 'lucide-react';
import { useState } from 'react';
import { Label } from '@/components/ui/label';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';

import { useForm, useFieldArray, Controller, useWatch, FieldValues } from 'react-hook-form';

import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';

/*
Pubkeys for playing with
ABr818VXt+6PLPRoA7QnsHBfRpKJdWZPjt7ppiTl6Fkq
ANRdB4M6Hj73R+gRM4N6zUPNidLuatB9uccOzHBc/0bP
*/

const schema = z.object({
	threshold: z
		.number({ invalid_type_error: 'Age field is required.' })
		.min(1, { message: 'threshold must be at least 3 characters.' }),
});

type FormData = z.infer<typeof schema>;

let renderCount = 0;

//function MultiSigAddress({ signature, index }: ) {
//	const suiAddress = signature.publicKey.toSuiAddress();
//
//	const pubkey_base64_sui_format = signature.publicKey.toSuiPublicKey();
//
//	const pubkey = signature.publicKey.toBase64();
//	const scheme = signature.signatureScheme.toString();
//
//	const details = [
//		{ label: 'Signature Public Key', value: pubkey },
//		{ label: 'Sui Format Public Key ( flag | pk )', value: pubkey_base64_sui_format },
//		{ label: 'Sui Address', value: suiAddress },
//		{ label: 'Signature', value: toB64(signature.signature) },
//	];
//
//	return (
//		<Card>
//			<CardHeader>
//				<CardTitle>Signature #{index}</CardTitle>
//				<CardDescription>{scheme}</CardDescription>
//			</CardHeader>
//			<CardContent>
//				<div className="flex flex-col gap-2">
//					{details.map(({ label, value }, index) => (
//						<div key={index} className="flex flex-col gap-1.5">
//							<div className="font-bold">{label}</div>
//							<div className="bg-muted rounded text-sm font-mono p-2 break-all">{value}</div>
//						</div>
//					))}
//				</div>
//			</CardContent>
//		</Card>
//	);
//}

export default function MultiSigAddressGenerator() {
	const [msAddress, setMSAddress] = useState('');
	const { register, control, handleSubmit } = useForm({
		defaultValues: {
			pubKeys: [{ pubKey: 'Sui Pubkey', weight: '' }],
		},
	});
	const { fields, append, remove } = useFieldArray({
		control,
		name: 'pubKeys',
	});

	// Perform generation of multisig address
	const onSubmit = (data: FieldValues) => {
		console.log('data', data);

		let pks: PubkeyWeightPair[] = [];
		data.pubKeys.forEach((item: any) => {
			console.log(item.pubKey);
			const pkBytes = fromB64(item.pubKey);
			const flag: number = pkBytes[0];
			console.log(flag);
			const rawPkBytes = toB64(pkBytes.slice(1));
			const schemeFlag = (SIGNATURE_FLAG_TO_SCHEME as { [key: number]: string })[flag];
			const scheme = schemeFlag as SignatureScheme;

			const pk = publicKeyFromSerialized(scheme, rawPkBytes);
			console.log(pk);
			pks.push({ pubKey: pk, weight: item.weight });
		});
		console.log('pks:', pks);
		const multisigSuiAddress = toMultiSigAddress(pks, 1);
		console.log('multisigSuiAddress', multisigSuiAddress);
		setMSAddress(multisigSuiAddress);
	};

	// if you want to control your fields with watch
	// const watchResult = watch("pubKeys");
	// console.log(watchResult);

	// The following is useWatch example
	// console.log(useWatch({ name: "pubKeys", control }));

	renderCount++;

	return (
		<div className="flex flex-col gap-4">
			<h2 className="scroll-m-20 text-4xl font-extrabold tracking-tight lg:text-5xl">
				MultiSig Address Creator
			</h2>

			<form className="flex flex-col gap-4" onSubmit={handleSubmit(onSubmit)}>
				<p>The following demo allow you to create Sui MultiSig addresses.</p>
				<ul className="grid w-full gap-1.5">
					{fields.map((item, index) => {
						return (
							<li key={item.id}>
								<input
									className="min-h-[80px] rounded-md border border-input bg-transparent px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
									{...register(`pubKeys.${index}.pubKey`, { required: true })}
								/>

								<input
									className="min-h-[80px] rounded-md border border-input bg-transparent px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
									type="number"
									{...register(`pubKeys.${index}.weight`, { required: true })}
								/>

								{/* <Controller
									render={({ field }) => (
										<input
											className="min-h-[80px] rounded-md border border-input bg-transparent px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
											{...field}
										/>
									)}
									name={`pubKeys.${index}.weight`}
									control={control}
								/> */}
								<Button
									className="min-h-[80px] rounded-md border border-input px-3 py-2 text-sm padding-2"
									type="button"
									onClick={() => remove(index)}
								>
									Delete
								</Button>
							</li>
						);
					})}
				</ul>
				<section>
					<Button
						type="button"
						onClick={() => {
							append({ pubKey: 'Sui Pubkey', weight: '' });
						}}
					>
						New PubKey
					</Button>
				</section>

				{/* <input
					{...register('threshold', { valueAsNumber: true })}
					id="threshold"
					type="number"
					className="form-control"
				/> */}

				<Button
					type="submit"
					onClick={() => {
						console.log('fields', fields);
					}}
				>
					Submit
				</Button>
			</form>
			{msAddress && <Card key={msAddress}>
				<CardHeader>
					<CardTitle>Sui MultiSig Address</CardTitle>
					<CardDescription>https://docs.sui.io/testnet/learn/cryptography/sui-multisig</CardDescription>
				</CardHeader>
				<CardContent>
					<div className="flex flex-col gap-2">
						<div className="bg-muted rounded text-sm font-mono p-2 break-all">{msAddress}</div>
					</div>
				</CardContent>
			</Card>}
		</div>
	);
}
// Add also Threshold
