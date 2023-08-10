// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import tsconfigPaths from 'vite-tsconfig-paths';
import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
	plugins: [tsconfigPaths()],
	test: {
		exclude: [...configDefaults.exclude, 'tests/**'],
		environment: 'jsdom',
		restoreMocks: true,
		globals: true,
		setupFiles: ['./test/setup.ts'],
	},
	resolve: {
		conditions: ['source'],
	},
});
