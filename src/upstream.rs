use crate::config::UpstreamConfig;
use reqwest::{Client, StatusCode};
use serde::Serialize;
use serde_json::Value;
use std::{
    env,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tracing::info;

#[derive(Debug, Clone)]
pub struct UpstreamClient {
    config: Arc<UpstreamConfig>,
    client: Client,
    api_key: Option<String>,
}

impl UpstreamClient {
    pub fn new(config: UpstreamConfig) -> Result<Self, UpstreamError> {
        let timeout = Duration::from_millis(config.timeout_ms.max(1));
        let client = Client::builder()
            .timeout(timeout)
            .user_agent("veridion/0.1.0")
            .build()
            .map_err(UpstreamError::HttpClient)?;

        let api_key = match &config.api_key_env {
            Some(var) => match env::var(var) {
                Ok(value) if !value.is_empty() => Some(value),
                Ok(_) => None,
                Err(env::VarError::NotPresent) => None,
                Err(err) => {
                    return Err(UpstreamError::Configuration(format!(
                        "failed to read {var}: {err}",
                    )));
                }
            },
            None => None,
        };

        if api_key.is_none() {
            if let Some(var) = &config.api_key_env {
                info!(
                    "no value found for upstream API key env {var}; continuing without authentication"
                );
            }
        }

        Ok(Self {
            config: Arc::new(config),
            client,
            api_key,
        })
    }

    pub fn config(&self) -> Arc<UpstreamConfig> {
        Arc::clone(&self.config)
    }

    pub async fn forward_chat<T: Serialize + ?Sized>(
        &self,
        payload: &T,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let mut request = self.client.post(&self.config.endpoint);
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key);
        }

        let start = Instant::now();
        let response = request
            .json(payload)
            .send()
            .await
            .map_err(UpstreamError::Request)?;
        let status = response.status();
        let body = response
            .json::<Value>()
            .await
            .map_err(UpstreamError::Request)?;
        let latency_ms = start.elapsed().as_millis();

        if !status.is_success() {
            return Err(UpstreamError::Upstream { status, body });
        }

        Ok(UpstreamResponse {
            status,
            latency_ms,
            body,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    pub status: StatusCode,
    pub latency_ms: u128,
    pub body: Value,
}

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("upstream configuration error: {0}")]
    Configuration(String),
    #[error("failed to build upstream HTTP client: {0}")]
    HttpClient(reqwest::Error),
    #[error("upstream request error: {0}")]
    Request(#[source] reqwest::Error),
    #[error("upstream returned status {status}: {body}")]
    Upstream { status: StatusCode, body: Value },
}
