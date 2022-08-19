// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::{collections::BTreeMap, sync::Arc};

use futures::future;
use jsonrpsee::core::client::{Client, ClientT, Subscription, SubscriptionClientT};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use sui_types::sui_framework_address_concat_string;
use test_utils::authority::test_and_configure_authority_configs;
use test_utils::transaction::{increment_counter, publish_basics_package_and_make_counter};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio::time::{sleep, Duration};
use tracing::info;

use sui::client_commands::{SuiClientCommandResult, SuiClientCommands, WalletContext};
use sui_config::utils::get_available_port;
use sui_json_rpc_types::{
    SuiEvent, SuiEventEnvelope, SuiEventFilter, SuiMoveStruct, SuiMoveValue, SuiObjectRead,
};
use sui_node::SuiNode;
use sui_swarm::memory::Swarm;
use sui_types::messages::{
    ExecuteTransactionRequest, ExecuteTransactionRequestType, ExecuteTransactionResponse,
};
use sui_types::{
    base_types::{ObjectID, SuiAddress, TransactionDigest},
    messages::TransactionInfoRequest,
};
use test_utils::messages::get_account_and_gas_coins;
use test_utils::messages::make_transactions_with_wallet_context;
use test_utils::network::setup_network_and_wallet;
use test_utils::transaction::{wait_for_all_txes, wait_for_tx};

async fn transfer_coin(
    context: &mut WalletContext,
) -> Result<(ObjectID, SuiAddress, SuiAddress, TransactionDigest), anyhow::Error> {
    let sender = context.keystore.addresses().get(0).cloned().unwrap();
    let receiver = context.keystore.addresses().get(1).cloned().unwrap();

    let object_refs = context.gateway.get_objects_owned_by_address(sender).await?;
    let object_to_send = object_refs.get(1).unwrap().object_id;

    // Send an object
    info!(
        "transferring coin {:?} from {:?} -> {:?}",
        object_to_send, sender, receiver
    );
    let res = SuiClientCommands::Transfer {
        to: receiver,
        coin_object_id: object_to_send,
        gas: None,
        gas_budget: 50000,
    }
    .execute(context)
    .await?;

    let digest = if let SuiClientCommandResult::Transfer(_, cert, _) = res {
        cert.transaction_digest
    } else {
        panic!("transfer command did not return WalletCommandResult::Transfer");
    };

    Ok((object_to_send, sender, receiver, digest))
}

async fn emit_move_events(
    context: &mut WalletContext,
) -> Result<(SuiAddress, ObjectID, TransactionDigest), anyhow::Error> {
    let (sender, gas_objects) = get_account_and_gas_coins(context).await?.swap_remove(0);
    let gas_object = gas_objects.get(0).unwrap().id();

    let res = SuiClientCommands::CreateExampleNFT {
        name: Some("example_nft_name".into()),
        description: Some("example_nft_desc".into()),
        url: Some("https://sui.io/_nuxt/img/sui-logo.8d3c44e.svg".into()),
        gas: Some(*gas_object),
        gas_budget: Some(50000),
    }
    .execute(context)
    .await?;

    let (object_id, digest) = if let SuiClientCommandResult::CreateExampleNFT(
        SuiObjectRead::Exists(obj),
    ) = res
    {
        (obj.reference.object_id, obj.previous_transaction)
    } else {
        panic!("CreateExampleNFT command did not return WalletCommandResult::CreateExampleNFT(SuiObjectRead::Exists, got {:?}", res);
    };

    Ok((sender, object_id, digest))
}

#[tokio::test]
async fn test_full_node_follows_txes() -> Result<(), anyhow::Error> {
    telemetry_subscribers::init_for_testing();

    let (swarm, mut context, _) = setup_network_and_wallet().await?;

    let config = swarm.config().generate_fullnode_config();
    let node = SuiNode::start(&config).await?;

    let (transfered_object, _, receiver, digest) = transfer_coin(&mut context).await?;
    wait_for_tx(digest, node.state().clone()).await;

    // verify that the node has seen the transfer
    let object_read = node.state().get_object_read(&transfered_object).await?;
    let object = object_read.into_object()?;

    assert_eq!(object.owner.get_owner_address().unwrap(), receiver);

    // timestamp is recorded
    let ts = node.state().get_timestamp_ms(&digest).await?;
    assert!(ts.is_some());

    Ok(())
}

#[tokio::test]
async fn test_full_node_shared_objects() -> Result<(), anyhow::Error> {
    telemetry_subscribers::init_for_testing();

    let (swarm, context, _) = setup_network_and_wallet().await?;

    let config = swarm.config().generate_fullnode_config();
    let node = SuiNode::start(&config).await?;

    let sender = context.keystore.addresses().get(0).cloned().unwrap();

    let (package_ref, counter_id) = publish_basics_package_and_make_counter(&context, sender).await;

    let effects = increment_counter(&context, sender, None, package_ref, counter_id).await;
    let digest = effects.certificate.transaction_digest;
    wait_for_tx(digest, node.state().clone()).await;

    Ok(())
}

const HOUR_MS: u64 = 3_600_000;

#[tokio::test]
async fn test_full_node_move_function_index() -> Result<(), anyhow::Error> {
    telemetry_subscribers::init_for_testing();
    let (swarm, context, _) = setup_network_and_wallet().await?;

    let config = swarm.config().generate_fullnode_config();
    let node = SuiNode::start(&config).await?;
    let sender = context.keystore.addresses().get(0).cloned().unwrap();
    let (package_ref, counter_id) = publish_basics_package_and_make_counter(&context, sender).await;
    let effects = increment_counter(&context, sender, None, package_ref, counter_id).await;
    let digest = effects.certificate.transaction_digest;

    wait_for_tx(digest, node.state().clone()).await;
    let txes = node
        .state()
        .get_transactions_by_move_function(
            package_ref.0,
            Some("counter".to_string()),
            Some("increment".to_string()),
        )
        .await?;

    assert_eq!(txes.len(), 1);
    assert_eq!(txes[0].1, digest);

    let txes = node
        .state()
        .get_transactions_by_move_function(package_ref.0, None, None)
        .await?;

    // 2 transactions in the package i.e create and increment counter
    assert_eq!(txes.len(), 2);
    assert_eq!(txes[1].1, digest);

    eprint!("start...");
    let txes = node
        .state()
        .get_transactions_by_move_function(package_ref.0, Some("counter".to_string()), None)
        .await?;

    // 2 transactions in the package i.e publish and increment
    assert_eq!(txes.len(), 2);
    assert_eq!(txes[1].1, digest);

    Ok(())
}

#[tokio::test]
async fn test_full_node_indexes() -> Result<(), anyhow::Error> {
    telemetry_subscribers::init_for_testing();
    let (swarm, mut context, _) = setup_network_and_wallet().await?;

    let config = swarm.config().generate_fullnode_config();
    let node = SuiNode::start(&config).await?;

    let (transfered_object, sender, receiver, digest) = transfer_coin(&mut context).await?;

    wait_for_tx(digest, node.state().clone()).await;

    let txes = node
        .state()
        .get_transactions_by_input_object(transfered_object)
        .await?;

    assert_eq!(txes.len(), 1);
    assert_eq!(txes[0].1, digest);

    let txes = node
        .state()
        .get_transactions_by_mutated_object(transfered_object)
        .await?;
    assert_eq!(txes.len(), 1);
    assert_eq!(txes[0].1, digest);

    let txes = node.state().get_transactions_from_addr(sender).await?;
    assert_eq!(txes.len(), 1);
    assert_eq!(txes[0].1, digest);

    let txes = node.state().get_transactions_to_addr(receiver).await?;
    assert_eq!(txes.len(), 1);
    assert_eq!(txes[0].1, digest);

    // Note that this is also considered a tx to the sender, because it mutated
    // one or more of the sender's objects.
    let txes = node.state().get_transactions_to_addr(sender).await?;
    assert_eq!(txes.len(), 1);
    assert_eq!(txes[0].1, digest);

    // No transactions have originated from the receiver
    let txes = node.state().get_transactions_from_addr(receiver).await?;
    assert_eq!(txes.len(), 0);

    // timestamp is recorded
    let ts = node.state().get_timestamp_ms(&digest).await?;
    assert!(ts.is_some());

    // This is a poor substitute for the post processing taking some time
    // Unfortunately event store writes seem to add some latency so this wait is needed
    sleep(Duration::from_millis(1000)).await;

    // one event is stored, and can be looked up by digest
    // Also query by timestamp verifies that a timestamp is inserted, within an hour
    let all_events = node
        .state()
        .get_events_for_timerange(ts.unwrap() - HOUR_MS, ts.unwrap() + HOUR_MS, None)
        .await?;
    assert_eq!(all_events.len(), 1);
    let events = node.state().get_events_for_transaction(digest).await?;
    assert_eq!(events.len(), 1);

    Ok(())
}

// Test for syncing a node to an authority that already has many txes.
#[tokio::test]
async fn test_full_node_cold_sync() -> Result<(), anyhow::Error> {
    telemetry_subscribers::init_for_testing();

    let (swarm, mut context, _) = setup_network_and_wallet().await?;

    let (_, _, _, _) = transfer_coin(&mut context).await?;
    let (_, _, _, _) = transfer_coin(&mut context).await?;
    let (_, _, _, _) = transfer_coin(&mut context).await?;
    let (_transfered_object, _sender, _receiver, digest) = transfer_coin(&mut context).await?;

    // Make sure the validators are quiescent before bringing up the node.
    sleep(Duration::from_millis(1000)).await;

    let config = swarm.config().generate_fullnode_config();
    let node = SuiNode::start(&config).await?;

    wait_for_tx(digest, node.state().clone()).await;

    let info = node
        .state()
        .handle_transaction_info_request(TransactionInfoRequest {
            transaction_digest: digest,
        })
        .await?;
    assert!(info.signed_effects.is_some());

    Ok(())
}

#[tokio::test]
async fn test_full_node_sync_flood() -> Result<(), anyhow::Error> {
    telemetry_subscribers::init_for_testing();

    let (swarm, context, _) = setup_network_and_wallet().await?;

    let config = swarm.config().generate_fullnode_config();
    let node = SuiNode::start(&config).await?;

    let mut futures = Vec::new();

    let sender = context.keystore.addresses().get(0).cloned().unwrap();
    let (package_ref, counter_id) = publish_basics_package_and_make_counter(&context, sender).await;

    let context = Arc::new(Mutex::new(context));

    // Start up 5 different tasks that all spam txs at the authorities.
    for i in 0..5 {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let context = context.clone();
        tokio::task::spawn(async move {
            let (sender, object_to_split) = {
                let context = &mut context.lock().await;
                let address = context.keystore.addresses()[i];
                SuiClientCommands::SyncClientState {
                    address: Some(address),
                }
                .execute(context)
                .await
                .unwrap();

                let sender = context.keystore.addresses().get(0).cloned().unwrap();

                let coins = context.gas_objects(sender).await.unwrap();
                let object_to_split = coins.first().unwrap().1.reference.to_object_ref();
                (sender, object_to_split)
            };

            let mut owned_tx_digest = None;
            let mut shared_tx_digest = None;
            let mut gas_object = None;
            for _ in 0..10 {
                let res = {
                    let context = &mut context.lock().await;
                    SuiClientCommands::SplitCoin {
                        amounts: vec![1],
                        coin_id: object_to_split.0,
                        gas: gas_object,
                        gas_budget: 50000,
                    }
                    .execute(context)
                    .await
                    .unwrap()
                };

                owned_tx_digest = if let SuiClientCommandResult::SplitCoin(resp) = res {
                    let digest = resp.certificate.transaction_digest;
                    let split_coin_resp =
                        resp.parsed_data.unwrap().to_split_coin_response().unwrap();
                    // Re-use the same gas id next time to avoid O(n^2) fetches due to automatic
                    // gas selection.
                    gas_object = Some(split_coin_resp.updated_gas.id());
                    Some(digest)
                } else {
                    panic!("transfer command did not return WalletCommandResult::Transfer");
                };

                let context = &context.lock().await;
                shared_tx_digest = Some(
                    increment_counter(context, sender, gas_object, package_ref, counter_id)
                        .await
                        .certificate
                        .transaction_digest,
                );
            }
            tx.send((owned_tx_digest.unwrap(), shared_tx_digest.unwrap()))
                .unwrap();
        });
        futures.push(rx);
    }

    // make sure the node syncs up to the last digest sent by each task.
    let digests = future::join_all(futures)
        .await
        .iter()
        .map(|r| r.clone().unwrap())
        .flat_map(|(a, b)| std::iter::once(a).chain(std::iter::once(b)))
        .collect();
    wait_for_all_txes(digests, node.state().clone()).await;

    Ok(())
}

/// Call this function to set up a network and a fullnode with subscription enabled.
async fn set_up_subscription(swarm: &Swarm) -> Result<(SuiNode, Client), anyhow::Error> {
    let port = get_available_port();
    let ws_server_url = format!("127.0.0.1:{}", port);
    let ws_addr: SocketAddr = ws_server_url.parse().unwrap();

    let mut config = swarm.config().generate_fullnode_config();
    config.websocket_address = Some(ws_addr);

    let node = SuiNode::start(&config).await?;

    let client = WsClientBuilder::default()
        .build(&format!("ws://{}", ws_server_url))
        .await?;
    Ok((node, client))
}

/// Call this function to set up a network and a fullnode and return a jsonrpc client.
async fn set_up_jsonrpc(swarm: &Swarm) -> Result<(SuiNode, HttpClient), anyhow::Error> {
    let port = get_available_port();
    let jsonrpc_server_url = format!("127.0.0.1:{}", port);
    let jsonrpc_addr: SocketAddr = jsonrpc_server_url.parse().unwrap();

    let mut config = swarm.config().generate_fullnode_config();
    config.json_rpc_address = jsonrpc_addr;

    let node = SuiNode::start(&config).await?;

    let client = HttpClientBuilder::default().build(&format!("http://{}", jsonrpc_server_url))?;
    Ok((node, client))
}

#[tokio::test]
async fn test_full_node_sub_to_move_event_ok() -> Result<(), anyhow::Error> {
    let (swarm, mut context, _) = setup_network_and_wallet().await?;
    let (node, ws_client) = set_up_subscription(&swarm).await?;

    let mut sub: Subscription<SuiEventEnvelope> = ws_client
        .subscribe(
            "sui_subscribeEvent",
            rpc_params![SuiEventFilter::MoveEventType(
                sui_framework_address_concat_string("::devnet_nft::MintNFTEvent")
            )],
            "sui_unsubscribeEvent",
        )
        .await
        .unwrap();

    let (sender, object_id, digest) = emit_move_events(&mut context).await?;
    wait_for_tx(digest, node.state().clone()).await;

    match timeout(Duration::from_secs(5), sub.next()).await {
        Ok(Some(Ok(SuiEventEnvelope {
            event: SuiEvent::MoveEvent { type_, fields, .. },
            ..
        }))) => {
            assert_eq!(
                type_,
                sui_framework_address_concat_string("::devnet_nft::MintNFTEvent")
            );
            assert_eq!(
                fields,
                Some(SuiMoveStruct::WithFields(BTreeMap::from([
                    ("creator".into(), SuiMoveValue::Address(sender)),
                    (
                        "name".into(),
                        SuiMoveValue::String("example_nft_name".into())
                    ),
                    (
                        "object_id".into(),
                        SuiMoveValue::Address(SuiAddress::from(object_id))
                    ),
                ])))
            );
            // TODO: verify bcs contents
        }
        other => panic!("Failed to get SuiEvent, but {:?}", other),
    }

    match timeout(Duration::from_secs(5), sub.next()).await {
        Err(_) => (),
        other => panic!(
            "Expect to time out because no new events are coming in. Got {:?}",
            other
        ),
    }

    Ok(())
}

// A test placeholder to verify event read APIs
// TODO: add real tests when event store integration is done
#[tokio::test]
async fn test_full_node_event_read_api_ok() -> Result<(), anyhow::Error> {
    let (swarm, _context, address) = setup_network_and_wallet().await?;
    let (_node, jsonrpc_client) = set_up_jsonrpc(&swarm).await?;

    let params = rpc_params![address, 10, 0, 666];
    let response: Vec<SuiEventEnvelope> = jsonrpc_client
        .request("sui_getEventsByOwner", params)
        .await
        .unwrap();
    assert!(response.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_full_node_quorum_driver_basic() -> Result<(), anyhow::Error> {
    let (swarm, mut context, _address) = setup_network_and_wallet().await?;
    let (node, _jsonrpc_client) = set_up_jsonrpc(&swarm).await?;
    let quorum_driver = node
        .quorum_driver()
        .expect("Fullnode should have quorum driver toggled on.");
    let mut rx = node
        .subscribe_to_quorum_driver_effects()
        .expect("Fullnode should have quorum driver toggled on.");

    let mut txns = make_transactions_with_wallet_context(&mut context, 3).await;
    assert!(
        txns.len() >= 3,
        "Expect at least 3 txns. Do we generate enough gas objects during genesis?"
    );

    // Test WaitForEffectsCert
    let txn = txns.swap_remove(0);
    let digest = *txn.digest();
    let res = quorum_driver
        .execute_transaction(ExecuteTransactionRequest {
            transaction: txn,
            request_type: ExecuteTransactionRequestType::WaitForEffectsCert,
        })
        .await
        .unwrap_or_else(|e| panic!("Failed to execute transaction {:?}: {:?}", digest, e));

    match res {
        ExecuteTransactionResponse::EffectsCert(res) => {
            let (certified_txn, certified_txn_effects) = rx.recv().await.unwrap();
            let (ct, cte) = *res;
            assert_eq!(*ct.digest(), digest);
            assert_eq!(*certified_txn.digest(), digest);
            assert_eq!(*cte.digest(), *certified_txn_effects.digest());
        }
        other => {
            panic!(
                "WaitForEffectsCert should get EffectCerts, but got: {:?}",
                other
            );
        }
    };

    // Test WaitForTxCert
    let txn = txns.swap_remove(0);
    let digest = *txn.digest();
    let res = quorum_driver
        .execute_transaction(ExecuteTransactionRequest {
            transaction: txn,
            request_type: ExecuteTransactionRequestType::WaitForTxCert,
        })
        .await
        .unwrap_or_else(|e| panic!("Failed to execute transaction {:?}: {:?}", digest, e));

    match res {
        ExecuteTransactionResponse::TxCert(res) => {
            let (certified_txn, _certified_txn_effects) = rx.recv().await.unwrap();
            let ct = *res;
            assert_eq!(*ct.digest(), digest);
            assert_eq!(*certified_txn.digest(), digest);
        }
        other => {
            panic!("WaitForTxCert should get TxCert, but got: {:?}", other);
        }
    };

    // Test ImmediateReturn
    let txn = txns.swap_remove(0);
    let digest = *txn.digest();
    let res = quorum_driver
        .execute_transaction(ExecuteTransactionRequest {
            transaction: txn,
            request_type: ExecuteTransactionRequestType::ImmediateReturn,
        })
        .await
        .unwrap_or_else(|e| panic!("Failed to execute transaction {:?}: {:?}", digest, e));

    match res {
        ExecuteTransactionResponse::ImmediateReturn => {
            let (certified_txn, _certified_txn_effects) = rx.recv().await.unwrap();
            assert_eq!(*certified_txn.digest(), digest);
        }
        other => {
            panic!(
                "ImmediateReturn should get ImmediateReturn, but got: {:?}",
                other
            );
        }
    };
    wait_for_tx(digest, node.state().clone()).await;

    // verify that the node has seen the transaction
    node.state().get_transaction(digest).await
        .unwrap_or_else(|e| panic!("Fullnode does not know about the txn {:?} that was executed with ImmediateReturn: {:?}", digest, e));

    Ok(())
}

/// Test a validator node does not have quorum driver
#[tokio::test]
async fn test_validator_node_has_no_quorum_driver() {
    let configs = test_and_configure_authority_configs(1);
    let validator_config = &configs.validator_configs()[0];
    let node = SuiNode::start(validator_config).await.unwrap();
    assert!(node.quorum_driver().is_none());
    assert!(node.subscribe_to_quorum_driver_effects().is_err());
}
