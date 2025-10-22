use std::sync::Arc;

use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use crate::{
    config::Config,
    filters::FilterEngine,
    policy::{PolicyEngine, PolicyError},
    server::{self, ApplicationState, ServerError},
    storage::{Storage, StorageError},
    telemetry::{Telemetry, TelemetryError},
    upstream::{UpstreamClient, UpstreamError},
};

pub struct Firewall {
    config: Arc<Config>,
    policy_engine: Arc<RwLock<PolicyEngine>>,
    filters: Arc<FilterEngine>,
    telemetry: Telemetry,
    storage: Arc<Storage>,
    upstream: Arc<UpstreamClient>,
}

impl Firewall {
    pub async fn new(config: Config) -> Result<Self, FirewallError> {
        let config = Arc::new(config);
        let telemetry = Telemetry::new(config.telemetry.clone())?;
        let filters = Arc::new(FilterEngine::new(&config.filters));
        let mut policy_engine = PolicyEngine::new(config.security.default_policy.clone());
        policy_engine.reload(&config.policies)?;
        let storage = Arc::new(Storage::new(config.storage.clone()).await?);
        let upstream = Arc::new(UpstreamClient::new(config.upstream.clone())?);

        Ok(Self {
            config,
            policy_engine: Arc::new(RwLock::new(policy_engine)),
            filters,
            telemetry,
            storage,
            upstream,
        })
    }

    pub async fn reload_policies(&self) -> Result<(), FirewallError> {
        let config = Arc::clone(&self.config);
        let mut engine = self.policy_engine.write().await;
        engine.reload(&config.policies)?;
        info!("policy engine reloaded");
        Ok(())
    }

    pub fn config(&self) -> Arc<Config> {
        Arc::clone(&self.config)
    }

    pub fn telemetry(&self) -> &Telemetry {
        &self.telemetry
    }

    pub fn filters(&self) -> Arc<FilterEngine> {
        Arc::clone(&self.filters)
    }

    pub fn storage(&self) -> Arc<Storage> {
        Arc::clone(&self.storage)
    }

    pub fn upstream(&self) -> Arc<UpstreamClient> {
        Arc::clone(&self.upstream)
    }

    pub async fn serve(&self) -> Result<(), FirewallError> {
        let state = ApplicationState {
            config: Arc::clone(&self.config),
            policy_engine: Arc::clone(&self.policy_engine),
            filters: Arc::clone(&self.filters),
            storage: Arc::clone(&self.storage),
            upstream: Arc::clone(&self.upstream),
        };

        server::serve(self.config.clone(), state).await?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("policy engine error: {0}")]
    Policy(#[from] PolicyError),
    #[error("telemetry initialization failed: {0}")]
    Telemetry(#[from] TelemetryError),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("server error: {0}")]
    Server(#[from] ServerError),
    #[error("upstream client error: {0}")]
    Upstream(#[from] UpstreamError),
}
