// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use arc_swap::ArcSwap;
use std::sync::Arc;

use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::log::{error, warn};
use tracing::Instrument;

use sui_core::authority_aggregator::AuthorityAggregator;
use sui_core::authority_client::AuthorityAPI;
use sui_types::error::{SuiError, SuiResult};
use sui_types::messages::{
    CertifiedTransaction, ExecuteTransactionRequest, ExecuteTransactionRequestType,
    ExecuteTransactionResponse, Transaction, TransactionEffects,
};

enum QuorumTask<A> {
    ProcessTransaction(Transaction),
    ProcessCertificate(CertifiedTransaction),
    UpdateValidators(AuthorityAggregator<A>),
}

pub struct QuorumDriverHandler<A> {
    quorum_driver: Arc<QuorumDriver<A>>,
    _processor_handle: JoinHandle<()>,
    task_sender: Mutex<Sender<QuorumTask<A>>>,
    // TODO: Change to CertifiedTransactionEffects eventually.
    effects_subscriber: Mutex<Receiver<(CertifiedTransaction, TransactionEffects)>>,
}

struct QuorumDriver<A> {
    validators: ArcSwap<AuthorityAggregator<A>>,
    effects_subscribe_sender: Sender<(CertifiedTransaction, TransactionEffects)>,
}

impl<A> QuorumDriver<A> {
    pub fn new(
        validators: AuthorityAggregator<A>,
        effects_subscribe_sender: Sender<(CertifiedTransaction, TransactionEffects)>,
    ) -> Self {
        Self {
            validators: ArcSwap::from(Arc::new(validators)),
            effects_subscribe_sender,
        }
    }
}

impl<A> QuorumDriverHandler<A>
where
    A: AuthorityAPI + Send + Sync + 'static + Clone,
{
    pub fn new(validators: AuthorityAggregator<A>) -> Self {
        let (task_tx, task_rx) = mpsc::channel::<QuorumTask<A>>(5000);
        let (subscriber_tx, subscriber_rx) = mpsc::channel::<_>(5000);
        let quorum_driver = Arc::new(QuorumDriver::new(validators, subscriber_tx));
        let handle = {
            let task_tx_copy = task_tx.clone();
            let quorum_driver_copy = quorum_driver.clone();
            tokio::task::spawn(async move {
                Self::task_queue_processor(quorum_driver_copy, task_rx, task_tx_copy).await;
            })
        };
        Self {
            quorum_driver,
            _processor_handle: handle,
            task_sender: Mutex::new(task_tx),
            effects_subscriber: Mutex::new(subscriber_rx),
        }
    }

    pub async fn next_effects(&self) -> Option<(CertifiedTransaction, TransactionEffects)> {
        self.effects_subscriber.lock().await.recv().await
    }

    pub async fn update_validators(&self, new_validators: AuthorityAggregator<A>) -> SuiResult {
        self.task_sender
            .lock()
            .await
            .send(QuorumTask::UpdateValidators(new_validators))
            .await
            .map_err(|err| SuiError::QuorumDriverCommunicationError {
                error: err.to_string(),
            })
    }

    async fn task_queue_processor(
        quorum_driver: Arc<QuorumDriver<A>>,
        mut task_receiver: Receiver<QuorumTask<A>>,
        task_sender: Sender<QuorumTask<A>>,
    ) {
        loop {
            if let Some(task) = task_receiver.recv().await {
                match task {
                    QuorumTask::ProcessTransaction(transaction) => {
                        // TODO: We entered here because callers do not want to wait for a
                        // transaction to finish execution. When this failed, we do not have a
                        // way to notify the caller. In the future, we may want to maintain
                        // some data structure for callers to come back and query the status
                        // of a transaction latter.
                        match Self::process_transaction(&quorum_driver, transaction).await {
                            Ok(cert) => {
                                if let Err(err) =
                                    task_sender.send(QuorumTask::ProcessCertificate(cert)).await
                                {
                                    error!(
                                        "Sending task to quorum driver queue failed: {}",
                                        err.to_string()
                                    );
                                }
                            }
                            Err(err) => {
                                warn!("Transaction processing failed: {:?}", err);
                            }
                        }
                    }
                    QuorumTask::ProcessCertificate(certificate) => {
                        // TODO: Similar to ProcessTransaction, we may want to allow callers to
                        // query the status.
                        if let Err(err) =
                            Self::process_certificate(&quorum_driver, certificate).await
                        {
                            warn!("Certificate processing failed: {:?}", err);
                        }
                    }
                    QuorumTask::UpdateValidators(new_validators) => {
                        quorum_driver.validators.store(Arc::new(new_validators));
                    }
                }
            }
        }
    }

    async fn process_transaction(
        quorum_driver: &Arc<QuorumDriver<A>>,
        transaction: Transaction,
    ) -> SuiResult<CertifiedTransaction> {
        quorum_driver
            .validators
            .load()
            .process_transaction(transaction)
            .instrument(tracing::debug_span!("process_tx"))
            .await
    }

    async fn process_certificate(
        quorum_driver: &Arc<QuorumDriver<A>>,
        certificate: CertifiedTransaction,
    ) -> SuiResult<(CertifiedTransaction, TransactionEffects)> {
        let effects = quorum_driver
            .validators
            .load()
            .process_certificate(certificate.clone())
            .instrument(tracing::debug_span!("process_cert"))
            .await?;
        let response = (certificate, effects);
        // An error to send the result to subscribers should not block returning the result.
        if let Err(err) = quorum_driver
            .effects_subscribe_sender
            .send(response.clone())
            .await
        {
            // TODO: We could potentially retry sending if we want.
            error!("{}", err);
        }
        Ok(response)
    }
}

impl<A> QuorumDriverHandler<A>
where
    A: AuthorityAPI + Send + Sync + 'static + Clone,
{
    pub async fn execute_transaction(
        &self,
        request: ExecuteTransactionRequest,
    ) -> SuiResult<ExecuteTransactionResponse> {
        let ExecuteTransactionRequest {
            transaction,
            request_type,
        } = request;
        match request_type {
            ExecuteTransactionRequestType::ImmediateReturn => {
                self.task_sender
                    .lock()
                    .await
                    .send(QuorumTask::ProcessTransaction(transaction))
                    .await
                    .map_err(|err| SuiError::QuorumDriverCommunicationError {
                        error: err.to_string(),
                    })?;
                Ok(ExecuteTransactionResponse::ImmediateReturn)
            }
            ExecuteTransactionRequestType::WaitForTxCert => {
                let certificate =
                    QuorumDriverHandler::process_transaction(&self.quorum_driver, transaction)
                        .instrument(tracing::debug_span!("process_tx"))
                        .await?;
                self.task_sender
                    .lock()
                    .await
                    .send(QuorumTask::ProcessCertificate(certificate.clone()))
                    .await
                    .map_err(|err| SuiError::QuorumDriverCommunicationError {
                        error: err.to_string(),
                    })?;
                Ok(ExecuteTransactionResponse::TxCert(Box::new(certificate)))
            }
            ExecuteTransactionRequestType::WaitForEffectsCert => {
                let certificate =
                    QuorumDriverHandler::process_transaction(&self.quorum_driver, transaction)
                        .instrument(tracing::debug_span!("process_tx"))
                        .await?;
                let response =
                    QuorumDriverHandler::process_certificate(&self.quorum_driver, certificate)
                        .instrument(tracing::debug_span!("process_cert"))
                        .await?;
                Ok(ExecuteTransactionResponse::EffectsCert(Box::new(response)))
            }
        }
    }
}
