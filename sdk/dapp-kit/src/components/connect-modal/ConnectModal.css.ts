// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { style } from '@vanilla-extract/css';

export const overlay = style({
	backgroundColor: 'rgba(24 36 53 / 20%)',
	position: 'fixed',
	inset: 0,
	zIndex: 999999999,
});

export const content = style({
	backgroundColor: 'white',
	position: 'fixed',
	bottom: 16,
	left: 16,
	right: 16,
	zIndex: 999999999,
	display: 'flex',
	flexDirection: 'column',
	justifyContent: 'space-between',
	overflow: 'hidden',
	borderRadius: 16,
	minHeight: '50vh',
	maxHeight: '85vh',
	maxWidth: 700,

	'@media': {
		'screen and (min-width: 768px)': {
			flexDirection: 'row',
			top: '50%',
			left: '50%',
			transform: 'translate(-50%, -50%)',
		},
	},
});

export const whatIsAWalletButton = style({
	backgroundColor: '#F7F8F8',
	padding: 16,
	'@media': {
		'screen and (min-width: 768px)': {
			display: 'none',
		},
	},
});

export const viewContainer = style({
	display: 'none',
	'@media': {
		'screen and (min-width: 768px)': {
			display: 'flex',
		},
	},
});

export const selectedWalletListContainer = style({
	display: 'none',
	'@media': {
		'screen and (min-width: 768px)': {
			display: 'flex',
		},
	},
});

export const selectedViewContainer = style({
	display: 'flex',
});

export const triggerButton = style({});

export const backButton = style({
	'@media': {
		'screen and (min-width: 768px)': {
			display: 'none',
		},
	},
});

export const closeButton = style({
	position: 'absolute',
	padding: 7,
	top: 16,
	right: 16,
	borderRadius: 9999,
	backgroundColor: '#F0F1F2',
});

export const walletListContainer = style({
	padding: 20,
	minWidth: 240,
	'@media': {
		'screen and (min-width: 768px)': {
			backgroundColor: '#F7F8F8',
		},
	},
});
