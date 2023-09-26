// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import type { WalletWithRequiredFeatures } from '@mysten/wallet-standard';

import { useWallets } from '../../../hooks/wallet/useWallets.js';
import * as styles from './WalletList.css.js';
import { WalletListItem } from './WalletListItem.js';
import { SuiIcon } from '../../icons/SuiIcon.js';

type WalletListProps = {
	selectedWalletName?: string;
	onPlaceholderClick: () => void;
	onSelect: (wallet: WalletWithRequiredFeatures) => void;
};

export function WalletList({ selectedWalletName, onPlaceholderClick, onSelect }: WalletListProps) {
	const wallets = useWallets();
	return (
		<ul className={styles.container}>
			{wallets.length > 0 ? (
				wallets.map((wallet) => (
					<WalletListItem
						key={wallet.name}
						name={wallet.name}
						icon={wallet.icon}
						isSelected={wallet.name === selectedWalletName}
						onClick={() => onSelect(wallet)}
					/>
				))
			) : (
				<WalletListItem
					name="Sui Wallet"
					icon={<SuiIcon />}
					onClick={onPlaceholderClick}
					isSelected
				/>
			)}
		</ul>
	);
}
