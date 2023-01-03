// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import {
  SignableTransaction,
  SuiAddress,
  SuiTransactionResponse,
} from "@mysten/sui.js";
import {
  WalletAdapterList,
  resolveAdapters,
  WalletAdapter,
  isWalletProvider,
} from "@mysten/wallet-adapter-base";

export interface WalletKitCoreOptions {
  adapters: WalletAdapterList;
}

export enum WalletKitCoreConnectionStatus {
  DISCONNECTED = "DISCONNECTED",
  CONNECTING = "CONNECTING",
  CONNECTED = "CONNECTED",
  // TODO: Figure out if this is really a separate status, or is just a piece of state alongside the `disconnected` state:
  ERROR = "ERROR",
}

export interface InternalWalletKitCoreState {
  wallets: WalletAdapter[];
  currentWallet: WalletAdapter | null;
  accounts: SuiAddress[];
  currentAccount: SuiAddress | null;
  status: WalletKitCoreConnectionStatus;
}

export interface WalletKitCoreState extends InternalWalletKitCoreState {
  isConnecting: boolean;
  isConnected: boolean;
  isError: boolean;
}

export type SubscribeHandler = (state: WalletKitCoreState) => void;
export type Unsubscribe = () => void;

// TODO: Support autoconnect.
// TODO: Support lazy loaded adapters, where we'll resolve the adapters only once we attempt to use them.
// That should allow us to have effective code-splitting practices. We should also allow lazy loading of _many_
// wallet adapters in one bag so that we can split _all_ of the adapters from the core.
export function createWalletKitCore({ adapters }: WalletKitCoreOptions) {
  const subscriptions: Set<(state: WalletKitCoreState) => void> = new Set();

  let internalState: InternalWalletKitCoreState = {
    accounts: [],
    currentAccount: null,
    wallets: resolveAdapters(adapters),
    currentWallet: null,
    status: WalletKitCoreConnectionStatus.DISCONNECTED,
  };

  const computeState = () => ({
    ...internalState,
    isConnecting:
      internalState.status === WalletKitCoreConnectionStatus.CONNECTING,
    isConnected:
      internalState.status === WalletKitCoreConnectionStatus.CONNECTED,
    isError: internalState.status === WalletKitCoreConnectionStatus.ERROR,
  });

  let state = computeState();

  function setState(nextInternalState: Partial<InternalWalletKitCoreState>) {
    internalState = {
      ...internalState,
      ...nextInternalState,
    };
    state = computeState();
    // TODO: Try-catch to make more robust
    subscriptions.forEach((handler) => handler(state));
  }

  // TODO: Defer this somehow, probably alongside the work above for lazy wallet adapters:
  const providers = adapters.filter(isWalletProvider);
  if (providers.length) {
    providers.map((provider) =>
      provider.on("changed", () => {
        setState({ wallets: resolveAdapters(adapters) });
      })
    );
  }

  return {
    getState() {
      return state;
    },

    subscribe(handler: SubscribeHandler): Unsubscribe {
      // Immediately invoke the handler with the current state to make it compatible with Svelte stores:
      handler(this.getState());
      subscriptions.add(handler);
      return () => {
        subscriptions.delete(handler);
      };
    },

    connect: async (walletName: string) => {
      const currentWallet =
        internalState.wallets.find((wallet) => wallet.name === walletName) ??
        null;

      // TODO: Should the current wallet actually be set before we successfully connect to it?
      setState({ currentWallet });

      if (currentWallet && !currentWallet.connecting) {
        try {
          setState({ status: WalletKitCoreConnectionStatus.CONNECTING });
          await currentWallet.connect();
          setState({ status: WalletKitCoreConnectionStatus.CONNECTED });
          // TODO: Rather than using this method, we should just standardize the wallet properties on the adapter itself:
          const accounts = await currentWallet.getAccounts();
          // TODO: Implement account selection:

          setState({ accounts, currentAccount: accounts[0] ?? null });
        } catch (e) {
          console.log("Wallet connection error", e);

          setState({ status: WalletKitCoreConnectionStatus.ERROR });
        }
      } else {
        setState({ status: WalletKitCoreConnectionStatus.DISCONNECTED });
      }
    },

    disconnect: () => {
      if (!internalState.currentWallet) {
        console.warn("Attempted to `disconnect` but no wallet was connected.");
        return;
      }

      internalState.currentWallet.disconnect();
      setState({
        status: WalletKitCoreConnectionStatus.DISCONNECTED,
        accounts: [],
        currentAccount: null,
        currentWallet: null,
      });
    },

    signAndExecuteTransaction: (
      transaction: SignableTransaction
    ): Promise<SuiTransactionResponse> => {
      if (!internalState.currentWallet) {
        throw new Error(
          "No wallet is currently connected, cannot call `signAndExecuteTransaction`."
        );
      }

      return internalState.currentWallet.signAndExecuteTransaction(transaction);
    },
  };
}
