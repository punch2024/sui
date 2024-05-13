// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use fastcrypto::encoding::{Base64, Encoding, Hex};
use shared_crypto::intent::{Intent, IntentMessage};

use super::PasskeyAuthenticator;
use crate::{
    base_types::SuiAddress,
    crypto::{DefaultHash, PublicKey, Signature, SignatureScheme},
    signature::GenericSignature,
    signature_verification::VerifiedDigestCache,
    transaction::TransactionData,
};
use fastcrypto::traits::ToFromBytes;

// credential id (base64): pMNz4cjuOuIYuYQ3PibXxpWIqVo2klxSF1KFmK7CYC/clMKjIw8Sgr8j+bGL8i5N
// pubkey (hex): 03a4c373e1c8ee3ae218b984373e81a0944973eff8b0229882d0f0ede32f6be786
// sui address: 0x2ae10fb45d62bf72b0b8c440392b77365cd2ba765cef6af3ab1840c585d5e2f6
// tx bytes: AAAAACrhD7RdYr9ysLjEQDkrdzZc0rp2XO9q86sYQMWF1eL2AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAECAwQFBgcICQABAgMEBQYHCAkq4Q+0XWK/crC4xEA5K3c2XNK6dlzvavOrGEDFhdXi9gUAAAAAAAAAZAAAAAAAAAAA
// tx digest (hex): ad8f10d7e6d86e2943659750e0d333dac8cff22970d2003cdb22c304609af420
// authenticatorData (hex): 49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000004
// clientDataJSON: `{"type":"webauthn.get","challenge":"rY8Q1-bYbilDZZdQ4NMz2sjP8ilw0gA82yLDBGCa9CA","origin":"http://localhost:5173","crossOrigin":false}`
// signature (hex): 82439858199b14621c072732e75c5695797b6a68287a2069cb7c6088d9188226070aa4815941cbbf4cb2582dd08f9ead53a40d3293f260ffc7c5d09b0cbad76c
// encoded webauthn signature (base64): BiVJlg3liA6MaHQ0Fw9kdmBbj+SuuaKGMseZXPO6gx2XYwUAAAAEhgF7InR5cGUiOiJ3ZWJhdXRobi5nZXQiLCJjaGFsbGVuZ2UiOiJyWThRMS1iWWJpbERaWmRRNE5NejJzalA4aWx3MGdBODJ5TERCR0NhOUNBIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo1MTczIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfYJDmFgZmxRiHAcnMudcVpV5e2poKHogact8YIjZGIImBwqkgVlBy79Mslgt0I+erVOkDTKT8mD/x8XQmwy612wDpMNz4cjuOuIYuYQ3PoGglElz7/iwIpiC0PDt4y9r54Y=
// encoded webuahthn signature length: 272
// signature verified: true
#[test]
fn test_passkey_authenticator() {
    use fastcrypto::hash::HashFunction;
    let pk = PublicKey::try_from_bytes(
        SignatureScheme::Secp256r1,
        &Hex::decode("023eb39eba04d076f06ede0f2dee8fdb90e2d84c5aee3901801a4dac8afd36b732").unwrap(),
    )
    .unwrap();
    let sender = SuiAddress::from(&pk);
    println!("sender: {:?}", sender);

    let tx_data: TransactionData = bcs::from_bytes(&Base64::decode("AAAAAPt9VS19/gRwsLcba0HDkfa4ZIIqVcUx4BFedgSLoFDLASYHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD7fVUtff4EcLC3G2tBw5H2uGSCKlXFMeARXnYEi6BQywUAAAAAAAAAZAAAAAAAAAAA").unwrap()).unwrap();
    let intent_msg = IntentMessage::new(Intent::sui_transaction(), tx_data);

    let mut hasher = DefaultHash::default();
    hasher.update(&bcs::to_bytes(&intent_msg).expect("Message serialization should not fail"));
    let passkey_digest = hasher.finalize().digest;
    println!("passkey_digest: {:?}", passkey_digest);
    let authenticator_data =
        Hex::decode("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000")
            .unwrap();
    let client_data = r#"{"type":"webauthn.get","challenge":"d3mzuzGkSs7m_ZIu6t6cxa1Mj3ySA79pQpnz6fwRLnA","origin":"http://localhost:5173","crossOrigin":false}"#.to_string();

    let sig_bytes = Hex::decode("57c29d22182148753daa5c9ea38158eef4c9b194d0f979998fa7702d670acab9bd34a10bad113123ef08312a9fd2b832618ce52662bde49b8539083574e59033").unwrap();
    let pk_bytes =
        Hex::decode("023eb39eba04d076f06ede0f2dee8fdb90e2d84c5aee3901801a4dac8afd36b732").unwrap();

    let mut user_sig_bytes = vec![SignatureScheme::Secp256r1.flag()];
    user_sig_bytes.extend_from_slice(&sig_bytes);
    user_sig_bytes.extend_from_slice(&pk_bytes);

    let sig = GenericSignature::PasskeyAuthenticator(PasskeyAuthenticator::new(
        authenticator_data,
        client_data,
        Signature::from_bytes(&user_sig_bytes).unwrap(),
    ));

    println!("serialized sig: {:?}", Hex::encode(sig.as_ref()));
    let res = sig.verify_authenticator(
        &intent_msg,
        sender,
        0,
        &Default::default(),
        Arc::new(VerifiedDigestCache::new_empty()),
    );
    assert!(res.is_ok());
}
