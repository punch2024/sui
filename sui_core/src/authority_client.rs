// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::authority::AuthorityState;
use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;
use std::sync::Arc;
use sui_network::network::NetworkClient;
use sui_network::transport::TcpDataStream;
use sui_types::batch::UpdateItem;
use sui_types::{error::SuiError, messages::*, serialize::*};

#[cfg(test)]
use sui_types::{
    base_types::ObjectID,
    committee::Committee,
    crypto::{KeyPair, PublicKeyBytes},
    object::Object,
};

static MAX_ERRORS: i32 = 10;

#[async_trait]
pub trait AuthorityAPI {
    /// Initiate a new transaction to a Sui or Primary account.
    async fn handle_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<TransactionInfoResponse, SuiError>;

    /// Confirm a transaction to a Sui or Primary account.
    async fn handle_confirmation_transaction(
        &self,
        transaction: ConfirmationTransaction,
    ) -> Result<TransactionInfoResponse, SuiError>;

    /// Handle Account information requests for this account.
    async fn handle_account_info_request(
        &self,
        request: AccountInfoRequest,
    ) -> Result<AccountInfoResponse, SuiError>;

    /// Handle Object information requests for this account.
    async fn handle_object_info_request(
        &self,
        request: ObjectInfoRequest,
    ) -> Result<ObjectInfoResponse, SuiError>;

    /// Handle Object information requests for this account.
    async fn handle_transaction_info_request(
        &self,
        request: TransactionInfoRequest,
    ) -> Result<TransactionInfoResponse, SuiError>;

    async fn handle_batch_stream(
        &self,
        request: BatchInfoRequest,
    ) -> Result<BatchInfoResponseItemStream, SuiError>;
}

pub type BatchInfoResponseItemStream = BoxStream<'static, Result<BatchInfoResponseItem, SuiError>>;

#[derive(Clone)]
pub struct NetworkAuthorityClient(NetworkClient);

impl NetworkAuthorityClient {
    pub fn new(network_client: NetworkClient) -> Self {
        Self(network_client)
    }
}

#[async_trait]
impl AuthorityAPI for NetworkAuthorityClient {
    /// Initiate a new transfer to a Sui or Primary account.
    async fn handle_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<TransactionInfoResponse, SuiError> {
        let response = self
            .0
            .send_recv_bytes(serialize_transaction(&transaction))
            .await?;
        deserialize_transaction_info(response)
    }

    /// Confirm a transfer to a Sui or Primary account.
    async fn handle_confirmation_transaction(
        &self,
        transaction: ConfirmationTransaction,
    ) -> Result<TransactionInfoResponse, SuiError> {
        let response = self
            .0
            .send_recv_bytes(serialize_cert(&transaction.certificate))
            .await?;
        deserialize_transaction_info(response)
    }

    async fn handle_account_info_request(
        &self,
        request: AccountInfoRequest,
    ) -> Result<AccountInfoResponse, SuiError> {
        let response = self
            .0
            .send_recv_bytes(serialize_account_info_request(&request))
            .await?;
        deserialize_account_info(response)
    }

    async fn handle_object_info_request(
        &self,
        request: ObjectInfoRequest,
    ) -> Result<ObjectInfoResponse, SuiError> {
        let response = self
            .0
            .send_recv_bytes(serialize_object_info_request(&request))
            .await?;
        deserialize_object_info(response)
    }

    /// Handle Object information requests for this account.
    async fn handle_transaction_info_request(
        &self,
        request: TransactionInfoRequest,
    ) -> Result<TransactionInfoResponse, SuiError> {
        let response = self
            .0
            .send_recv_bytes(serialize_transaction_info_request(&request))
            .await?;
        deserialize_transaction_info(response)
    }

    /// Handle Batch information requests for this authority.
    async fn handle_batch_stream(
        &self,
        request: BatchInfoRequest,
    ) -> Result<BatchInfoResponseItemStream, SuiError> {
        let tcp_stream = self
            .0
            .connect_for_stream(serialize_batch_request(&request))
            .await
            .map_err(|e| SuiError::ClientIoError {
                error: e.to_string(),
            })?;

        let mut error_count = 0;
        let TcpDataStream { framed_read, .. } = tcp_stream;

        let mut start = request.start;
        let stream = framed_read
            .map(|item| {
                item
                    // Convert io error to SuiClient error
                    .map_err(|err| SuiError::ClientIoError {
                        error: format!("io error: {:?}", err),
                    })
                    // If no error try to deserialize
                    .and_then(|bytes| match deserialize_message(&bytes[..]) {
                        Ok(SerializedMessage::Error(error)) => Err(SuiError::ClientIoError {
                            error: format!("io error: {:?}", error),
                        }),
                        Ok(message) => Ok(message),
                        Err(_) => Err(SuiError::InvalidDecoding),
                    })
                    // If deserialized try to parse as Batch Item
                    .and_then(deserialize_batch_info)
            })
            // Establish conditions to stop taking from the stream
            .take_while(move |item| {
                let flag = match item {
                    Ok(BatchInfoResponseItem(UpdateItem::Batch(signed_batch))) => {
                        start = start.or(Some(signed_batch.batch.next_sequence_number));
                        signed_batch.batch.next_sequence_number < start.unwrap() + request.length
                    }
                    Ok(BatchInfoResponseItem(UpdateItem::Transaction((seq, _digest)))) => {
                        start = start.or(Some(*seq));
                        *seq < start.unwrap() + request.length
                    }
                    Err(_e) => {
                        // TODO: record e
                        error_count += 1;
                        error_count < MAX_ERRORS
                    }
                };
                futures::future::ready(flag)
            });
        Ok(Box::pin(stream))
    }
}

#[derive(Clone)]
pub struct LocalAuthorityClient(pub Arc<AuthorityState>);

#[async_trait]
impl AuthorityAPI for LocalAuthorityClient {
    async fn handle_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<TransactionInfoResponse, SuiError> {
        let state = self.0.clone();
        let result = state.handle_transaction(transaction).await;
        result
    }

    async fn handle_confirmation_transaction(
        &self,
        transaction: ConfirmationTransaction,
    ) -> Result<TransactionInfoResponse, SuiError> {
        let state = self.0.clone();
        let result = state.handle_confirmation_transaction(transaction).await;
        result
    }

    async fn handle_account_info_request(
        &self,
        request: AccountInfoRequest,
    ) -> Result<AccountInfoResponse, SuiError> {
        let state = self.0.clone();

        let result = state.handle_account_info_request(request).await;
        result
    }

    async fn handle_object_info_request(
        &self,
        request: ObjectInfoRequest,
    ) -> Result<ObjectInfoResponse, SuiError> {
        let state = self.0.clone();
        let x = state.handle_object_info_request(request).await;
        x
    }

    /// Handle Object information requests for this account.
    async fn handle_transaction_info_request(
        &self,
        request: TransactionInfoRequest,
    ) -> Result<TransactionInfoResponse, SuiError> {
        let state = self.0.clone();

        let result = state.handle_transaction_info_request(request).await;
        result
    }

    /// Handle Batch information requests for this authority.
    async fn handle_batch_stream(
        &self,
        request: BatchInfoRequest,
    ) -> Result<BatchInfoResponseItemStream, SuiError> {
        let state = self.0.clone();
        Ok(Box::pin(state.handle_batch_streaming(request).await?))
    }
}

impl LocalAuthorityClient {
    #[cfg(test)]
    pub async fn new(committee: Committee, address: PublicKeyBytes, secret: KeyPair) -> Self {
        use crate::authority::AuthorityStore;
        use std::{env, fs};
        use sui_adapter::genesis;

        // Random directory
        let dir = env::temp_dir();
        let path = dir.join(format!("DB_{:?}", ObjectID::random()));
        fs::create_dir(&path).unwrap();

        let store = Arc::new(AuthorityStore::open(path, None));
        let state = AuthorityState::new(
            committee.clone(),
            address,
            Arc::pin(secret),
            store,
            genesis::clone_genesis_compiled_modules(),
            &mut genesis::get_genesis_context(),
        )
        .await;
        Self(Arc::new(state))
    }

    #[cfg(test)]
    pub async fn new_with_objects(
        committee: Committee,
        address: PublicKeyBytes,
        secret: KeyPair,
        objects: Vec<Object>,
    ) -> Self {
        let client = Self::new(committee, address, secret).await;
        {
            for object in objects {
                client.0.insert_genesis_object(object).await;
            }
        }
        client
    }
}
