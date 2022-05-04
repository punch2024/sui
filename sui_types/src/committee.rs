// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::base_types::*;
use ed25519_dalek::PublicKey;
use itertools::Itertools;
use rand::distributions::{Distribution, Uniform};
use rand::rngs::OsRng;
use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap};

pub type EpochId = u64;

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Committee {
    pub epoch: EpochId,
    pub voting_rights: BTreeMap<AuthorityName, usize>,
    pub total_votes: usize,
    // Note: this is a derived structure, no need to store.
    pub expanded_keys: HashMap<AuthorityName, PublicKey>,
}

impl Committee {
    pub fn new(epoch: EpochId, voting_rights: BTreeMap<AuthorityName, usize>) -> Self {
        let total_votes = voting_rights.iter().map(|(_, votes)| votes).sum();
        let expanded_keys: HashMap<_, _> = voting_rights
            .iter()
            .map(|(addr, _)| (*addr, (*addr).try_into().expect("Invalid Authority Key")))
            .collect();
        Committee {
            epoch,
            voting_rights,
            total_votes,
            expanded_keys,
        }
    }

    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    /// Samples authorities by weight
    pub fn sample(&self) -> &AuthorityName {
        // Uniform number [0, total_votes) non-inclusive of the upper bound
        let between = Uniform::from(0..self.total_votes);
        // OsRng implements CryptoRng and is secure
        let mut _random = between.sample(&mut OsRng);
        for (auth, weight) in &self.voting_rights {
            if *weight > _random {
                return auth;
            }
            _random -= *weight;
        }
        unreachable!();
    }

    pub fn weight(&self, author: &AuthorityName) -> usize {
        *self.voting_rights.get(author).unwrap_or(&0)
    }

    pub fn quorum_threshold(&self) -> usize {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (2 N + 3) / 3 = 2f + 1 + (2k + 2)/3 = 2f + 1 + k = N - f
        2 * self.total_votes / 3 + 1
    }

    pub fn validity_threshold(&self) -> usize {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (N + 2) / 3 = f + 1 + k/3 = f + 1
        (self.total_votes + 2) / 3
    }

    /// Given a sequence of (AuthorityName, value) for values that are ordered, provide the
    /// value at the particular threshold by stake. This orders all provided values and pick
    /// the appropriate value that has under it threshold stake. You may use the function
    /// `quorum_threshold` or `validity_threshold` to pick the f+1 or 2f+1 thresholds
    /// respectivelly.
    pub fn robust_value<A, V>(
        &self,
        items: impl Iterator<Item = (A, V)>,
        threshold: usize,
    ) -> (AuthorityName, V)
    where
        A: Borrow<AuthorityName> + Ord,
        V: Ord,
    {
        debug_assert!(threshold < self.total_votes);

        let vec: Vec<_> = items
            .map(|(a, v)| (v, self.voting_rights[a.borrow()], *a.borrow()))
            .sorted()
            .collect();
        let mut total = 0;
        for (v, s, a) in vec {
            total += s;
            if threshold < total {
                return (a, v);
            }
        }
        unreachable!();
    }
}
