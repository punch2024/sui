// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { X32 } from '@mysten/icons';

import { type ReactNode, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Portal } from '../../../shared/Portal';
import { ampli } from '_src/shared/analytics/ampli';
import ExternalLink from '_src/ui/app/components/external-link';
import FullBanner from '_src/ui/assets/images/quests-2-full-banner.svg';

export type InterstitialConfig = {
	enabled: boolean;
	dismissKey?: string;
	imageUrl?: string;
	bannerUrl?: string;
};

interface InterstitialProps extends InterstitialConfig {
	onClose: () => void;
}

const setInterstitialDismissed = (dismissKey: string) => console.log('dismiss me');
// localStorage.setItem(dismissKey, 'true');

function Interstitial({ enabled, dismissKey, imageUrl, bannerUrl, onClose }: InterstitialProps) {
	const navigate = useNavigate();

	useEffect(() => {
		const t = setTimeout(setInterstitialDismissed, 1000);
		return () => clearTimeout(t);
	}, []);

	const closeInterstitial = (dismissKey?: string) => {
		if (dismissKey) {
			setInterstitialDismissed(dismissKey);
		}
		onClose();
		navigate('/apps');
	};

	if (!enabled) {
		return null;
	}
	return (
		<Portal containerId="overlay-portal-container">
			<div className="flex flex-col justify-center flex-nowrap items-center rounded-lg z-50 overflow-hidden absolute top-0 bottom-0 left-0 right-0 backdrop-blur-sm">
				<img src={imageUrl} alt="interstitial-banner" />
				<button
					data-testid="bullshark-dismiss"
					className="appearance-none bg-transparent border-none cursor-pointer absolute bottom-5"
					onClick={() => closeInterstitial(dismissKey)}
				>
					<X32 className="text-black h-8 w-8" />
				</button>
			</div>
		</Portal>
	);
}

export default Interstitial;
