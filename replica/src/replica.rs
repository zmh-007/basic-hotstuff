use std::{pin::Pin, time::Duration};
use futures::Future;
use serde::{Serialize};
use serde_json::{json, Value};
use log::{debug, error};
use crate::replica_api::{JsonRpcRequest, JsonRpcResponse};
use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum ReplicaClientError {
    #[error("Failed to send message to {url}, error: {error}")]
    SendError { url: String, error: String },

    #[error("Failed to parse response: {context}, error: {error}")]
    ResponseError {
        context: &'static str,
        error: String,
    },

    #[error("Serde error, context {context}, error: {error}")]
    SerdeError {
        context: &'static str,
        error: serde_json::Error,
    },

    #[error("Unexpected status code when sending message to {url}, status: {status_code}")]
    UnexpectedStatusError {
        url: String,
        status_code: reqwest::StatusCode,
    },

    #[error("Retries limit exceeded when sending message to {url}, attempts: {attempts}, last error: {last_error}")]
    RetriesLimitExceededError {
        url: String,
        attempts: i32,
        last_error: Box<ReplicaClientError>,
    },
}

impl ReplicaClientError {
    pub fn send_error(url: String) -> impl FnOnce(reqwest::Error) -> Self + 'static {
        move |error| Self::SendError { url, error: error.to_string() }
    }

    pub fn response_error(context: &'static str) -> impl FnOnce(reqwest::Error) -> Self + 'static {
        move |error| Self::ResponseError { context, error: error.to_string() }
    }

    pub fn serde_error(context: &'static str) -> impl FnOnce(serde_json::Error) -> Self + 'static {
        move |error| Self::SerdeError { context, error }
    }
}

#[async_trait]
pub trait ReplicaClientApi: Send + Sync {
    async fn get_proposal(&self) -> Result<Value>;
    async fn verify_proposal(&self, msg: String) -> Result<()>;
    async fn finalize_block(&self, msg: String) -> Result<()>;
}

type Result<T> = std::result::Result<T, ReplicaClientError>;

pub struct ReplicaClient {
    replica_address: String,
    client: reqwest::Client,
}

impl ReplicaClient {
    pub fn new(replica_address: String) -> Self {
        Self {
            replica_address,
            client: reqwest::Client::new(),
        }
    }

    async fn call<M, F>(&self, msg: M, path: &'static str, call_fn: F) -> Result<JsonRpcResponse>
    where
        M: Clone + Serialize + Send + Sync + 'static,
        F: FnOnce(
                reqwest::Client,
                M,
                String,
            ) -> Pin<Box<dyn Future<Output = Result<JsonRpcResponse>> + Send>>
            + Send + 'static,
    {
        let url = format!("{}/{}", self.replica_address, path);
        let client = self.client.clone();
        
        call_fn(client, msg, url).await
    }

    pub async fn send_msg<T: Serialize>(
        client: &reqwest::Client,
        method: &str,
        msg: &T,
        url: &str,
    ) -> Result<JsonRpcResponse> {
        let params = Value::Array(vec![json!(msg)]);
        let json_rpc_request = JsonRpcRequest::new(method, params);
        let body = serde_json::to_vec(&json_rpc_request)
        .map_err(ReplicaClientError::serde_error("failed to serialize JSON-RPC request"))?;

        let res = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(ReplicaClientError::send_error(url.to_string()))?;

        if res.status().is_success() {
            let json_rpc_response: JsonRpcResponse = res.json()
                .await
                .map_err(ReplicaClientError::response_error("failed to parse JSON-RPC response"))?;
            Ok(json_rpc_response)
        } else {
            Err(ReplicaClientError::UnexpectedStatusError {
                url: url.to_string(),
                status_code: res.status(),
            })
        }
    }

    async fn send_with_retires<T: Serialize + std::fmt::Debug>(
        client: reqwest::Client,
        method: &str,
        msg: &T,
        url: &str,
    ) -> Result<JsonRpcResponse> {
        let mut attempt = 1;
        let mut backoff = Duration::from_millis(200);

        debug!("attempting to send request to {}, msg: {:?}", url, msg);

        loop {
            match ReplicaClient::send_msg(&client, method, msg, url).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    error!("failed to send request to {} (method: {}, attempt: {}): {:?}", url, method, attempt, err);

                    if attempt > 1 {
                        return Err(ReplicaClientError::RetriesLimitExceededError {
                            url: url.to_string(),
                            attempts: attempt,
                            last_error: Box::new(err),
                        });
                    }

                    attempt += 1;
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
            }
        }
    }
}

#[async_trait]
impl ReplicaClientApi for ReplicaClient {
    async fn get_proposal(&self) -> Result<Value> {
        let response = self.call(
            Value::Null,
            "",
            |client, msg, url| {
                Box::pin(async move {
                    ReplicaClient::send_with_retires(client, "get_proposal_of_next_block", &msg, &url).await
                })
            },
        ).await?;
        if !response.error.is_null() {
            return Err(ReplicaClientError::ResponseError {
                context: "get_proposal failed",
                error: format!("RPC error: {}", response.error)
            });
        }
        Ok(response.result)
    }

    async fn verify_proposal(&self, msg: String) -> Result<()> {
        let block = if !msg.starts_with("0x") {
            format!("0x{}", msg)
        } else {
            msg.clone()
        };
        let response = self.call(
            block,
            "",
            |client, msg, url| {
                Box::pin(async move {
                    ReplicaClient::send_with_retires(client, "verify_proposal_of_next_block", &msg, &url).await
                })
            },
        ).await?;
         if !response.error.is_null() {
            return Err(ReplicaClientError::ResponseError {
                context: "verify_proposal failed",
                error: format!("RPC error: {}", response.error)
            });
        }
        Ok(())
    }

    async fn finalize_block(&self, wp_blk: String) -> Result<()> {
        let wp_blk_with_prefix = if !wp_blk.starts_with("0x") {
            format!("0x{}", wp_blk)
        } else {
            wp_blk.clone()
        };
        let response = self.call(
            wp_blk_with_prefix,
            "",
            |client, msg, url| {
                Box::pin(async move {
                    ReplicaClient::send_with_retires(client, "submit_next_block", &msg, &url).await
                })
            },
        ).await?;
        if !response.error.is_null() {
            return Err(ReplicaClientError::ResponseError {
                context: "finalize_block failed",
                error: format!("RPC error: {}", response.error)
            });
        }
        Ok(())
    }
}
