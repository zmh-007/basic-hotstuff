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
        attempts: u32,
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
    async fn submit_next_block(&self, msg: String) -> Result<()>;
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
    
    fn ensure_hex_prefix(value: String) -> String {
        if value.starts_with("0x") {
            value
        } else {
            format!("0x{}", value)
        }
    }
    
    async fn send_rpc_request<T>(&self, method: &str, params: T) -> Result<JsonRpcResponse> 
    where
        T: Serialize + Clone + Send + Sync + std::fmt::Debug + 'static,
    {
        let method_owned = method.to_string();
        self.call(
            params,
            "",
            |client, msg, url| {
                Box::pin(async move {
                    ReplicaClient::send_with_retries(client, &method_owned, &msg, &url).await
                })
            },
        ).await
    }
    
    fn check_rpc_error(&self, response: &JsonRpcResponse, context: &'static str) -> Result<()> {
        if !response.error.is_null() {
            return Err(ReplicaClientError::ResponseError {
                context,
                error: format!("RPC error: {}", response.error),
            });
        }
        Ok(())
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

    async fn send_with_retries<T: Serialize + std::fmt::Debug>(
        client: reqwest::Client,
        method: &str,
        msg: &T,
        url: &str,
    ) -> Result<JsonRpcResponse> {
        const MAX_RETRIES: u32 = 3;
        const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
        
        debug!("Sending {} request to: {}", method, url);
        
        let mut last_error = None;
        
        for attempt in 1..=MAX_RETRIES {
            match ReplicaClient::send_msg(&client, method, msg, url).await {
                Ok(response) => {
                    if attempt > 1 {
                        debug!("Request succeeded on attempt {} to {}", attempt, url);
                    }
                    return Ok(response);
                }
                Err(err) => {
                    last_error = Some(err);
                    
                    if attempt < MAX_RETRIES {
                        let delay = INITIAL_BACKOFF * 2_u32.pow(attempt - 1);
                        debug!(
                            "Request failed (attempt {}/{}), retrying in {}ms: {:?}",
                            attempt, MAX_RETRIES, delay.as_millis(), last_error
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
        
        Err(ReplicaClientError::RetriesLimitExceededError {
            url: url.to_string(),
            attempts: MAX_RETRIES,
            last_error: Box::new(last_error.unwrap()),
        })
    }
}

#[async_trait]
impl ReplicaClientApi for ReplicaClient {
    async fn get_proposal(&self) -> Result<Value> {
        let response = self.send_rpc_request("get_proposal_of_next_block", Value::Null).await?;
        self.check_rpc_error(&response, "get_proposal")?;
        Ok(response.result)
    }

    async fn verify_proposal(&self, msg: String) -> Result<()> {
        let block = Self::ensure_hex_prefix(msg);
        let response = self.send_rpc_request("verify_proposal_of_next_block", block).await?;
        self.check_rpc_error(&response, "verify_proposal")?;
        Ok(())
    }

    async fn submit_next_block(&self, wp_blk: String) -> Result<()> {
        let block = Self::ensure_hex_prefix(wp_blk);
        let response = self.send_rpc_request("submit_next_block", block).await?;
        self.check_rpc_error(&response, "submit_next_block")?;
        Ok(())
    }
}
