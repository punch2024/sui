// Copyright(C) Facebook, Inc. and its affiliates.
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use consensus::consensus::LeaderSwapTable;
use fastcrypto::{
    serde_helpers::ToFromByteArray,
    traits::{KeyPair, ToFromBytes},
};
use test_utils::CommitteeFixture;

#[tokio::test]
async fn start_dkg() {
    let fixture = CommitteeFixture::builder()
        .stake_distribution(vec![2500, 2500, 2500, 2500].into())
        .build();
    let committee = fixture.committee();
    let primary = fixture.authorities().next().unwrap();
    let name = primary.id();

    let network = test_utils::test_network(primary.network_keypair(), primary.address());
    let leader_schedule = LeaderSchedule::new(committee.clone(), LeaderSwapTable::default());
    let vss_key_output = Arc::new(OnceLock::new());
    let (tx_system_messages, mut rx_system_messages) = test_utils::test_channel!(1);

    let protocol_config = test_utils::latest_protocol_version();
    let randomness_private_key = RandomnessPrivateKey::from(
        fastcrypto::groups::bls12381::Scalar::from_byte_array(
            primary
                .keypair()
                .copy()
                .private()
                .as_bytes()
                .try_into()
                .expect("key length should match"),
        )
        .expect("should work to convert BLS key to Scalar"),
    );
    let randomness_state = RandomnessState::try_new(
        &ChainIdentifier::unknown(),
        &protocol_config,
        committee,
        randomness_private_key,
        leader_schedule,
        network,
        vss_key_output,
        tx_system_messages,
    )
    .unwrap();

    randomness_state.start_dkg().await;

    let dkg_message = rx_system_messages.recv().await.unwrap();
    match dkg_message {
        SystemMessage::DkgMessage(msg) => {
            assert_eq!(msg.sender, name.0);
        }
        _ => panic!("wrong type of message sent"),
    }
}
