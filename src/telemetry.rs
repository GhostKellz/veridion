use crate::config::TelemetryConfig;
use std::sync::Arc;
use thiserror::Error;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone)]
pub struct Telemetry {
    config: Arc<TelemetryConfig>,
}

impl Telemetry {
    pub fn new(config: TelemetryConfig) -> Result<Self, TelemetryError> {
        let telemetry = Self {
            config: Arc::new(config),
        };
        telemetry.init_tracing()?;
        Ok(telemetry)
    }

    fn init_tracing(&self) -> Result<(), TelemetryError> {
        if !self.config.enable_tracing {
            return Ok(());
        }

        let env_filter = EnvFilter::try_new(&self.config.log_level)
            .or_else(|_| EnvFilter::try_new("info"))
            .map_err(|err| TelemetryError::InvalidConfig(err.to_string()))?;

        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .try_init()
            .map_err(|err| TelemetryError::Initialization(err.to_string()))?;

        Ok(())
    }

    pub fn config(&self) -> Arc<TelemetryConfig> {
        Arc::clone(&self.config)
    }
}

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("failed to initialize telemetry: {0}")]
    Initialization(String),
    #[error("invalid telemetry configuration: {0}")]
    InvalidConfig(String),
}
