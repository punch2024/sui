// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import { Transaction, Commands } from '..';
import { Inputs } from '../Inputs';

it('can construct and serialize an empty tranaction', () => {
  const tx = new Transaction();
  expect(() => tx.serialize()).not.toThrow();
});

it('can be serialized and deserialized to the same values', () => {
  const tx = new Transaction();
  tx.add(Commands.SplitCoin(tx.gas, tx.input(100)));
  const serialized = tx.serialize();
  const tx2 = Transaction.from(serialized);
  expect(serialized).toEqual(tx2.serialize());
});

it('allows transfer with the result of split commands', () => {
  const tx = new Transaction();
  const coin = tx.add(Commands.SplitCoin(tx.gas, tx.input(100)));
  tx.add(Commands.TransferObjects([coin], tx.input('0x2')));
});

it('supports nested results through either array index or destructuring', () => {
  const tx = new Transaction();
  const registerResult = tx.add(
    Commands.MoveCall({
      package: '0x2',
      function: 'game',
      module: 'register',
      arguments: [],
      typeArguments: [],
    }),
  );

  const [nft, account] = registerResult;

  // NOTE: This might seem silly but destructuring works differently than property access.
  expect(nft).toEqual(registerResult[0]);
  expect(account).toEqual(registerResult[1]);
});

describe('offline build', () => {
  function setup() {
    const tx = new Transaction();
    tx.setSender('0x2');
    tx.setGasPrice(1);
    tx.setGasBudget(1);
    return tx;
  }

  it('builds an empty transaction offline when provided sufficient data', async () => {
    const tx = setup();
    await tx.build();
  });

  it('supports epoch expiration', async () => {
    const tx = setup();
    tx.setExpiration({ Epoch: 1 });
    await tx.build();
  });

  it('builds a split command', async () => {
    const tx = setup();
    tx.add(Commands.SplitCoin(tx.gas, tx.input(Inputs.Pure('u64', 100))));
    console.log(tx.inputs);
    console.log(tx.commands);
    await tx.build();
  });

  it('infers the type of inputs', async () => {
    const tx = setup();
    tx.add(Commands.SplitCoin(tx.gas, tx.input(100)));
    console.log(tx.inputs);
    console.log(tx.commands);
    await tx.build();
  });
});
