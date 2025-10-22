use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

/// Top-level configuration object loaded from `veridion.toml` or similar sources.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub security: SecurityConfig,
    pub upstream: UpstreamConfig,
    pub policies: PoliciesConfig,
    pub filters: FiltersConfig,
    pub telemetry: TelemetryConfig,
    pub storage: StorageConfig,
}

impl Config {
    /// Loads configuration from the provided file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path_ref = path.as_ref();
        let contents = fs::read_to_string(path_ref)
            .map_err(|err| ConfigError::Io(path_ref.to_path_buf(), err))?;
        let mut config: Config = toml::from_str(&contents)?;
        config.policies.resolve_paths(path_ref.parent());
        Ok(config)
    }

    /// Returns a default in-memory configuration that can be used for tests or quick starts.
    pub fn default_insecure() -> Self {
        Self::default()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            security: SecurityConfig::default(),
            upstream: UpstreamConfig::default(),
            policies: PoliciesConfig::default(),
            filters: FiltersConfig::default(),
            telemetry: TelemetryConfig::default(),
            storage: StorageConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub request_timeout_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            workers: 4,
            request_timeout_ms: 30_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub default_policy: PolicyMode,
    pub enable_provenance: bool,
    pub require_signed_prompts: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            default_policy: PolicyMode::Deny,
            enable_provenance: true,
            require_signed_prompts: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Allow,
    Deny,
    Warn,
}

impl Default for PolicyMode {
    fn default() -> Self {
        PolicyMode::Deny
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UpstreamConfig {
    pub provider: String,
    pub endpoint: String,
    pub api_key_env: Option<String>,
    pub timeout_ms: u64,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            provider: "openai".to_string(),
            endpoint: "https://api.openai.com/v1".to_string(),
            api_key_env: Some("OPENAI_API_KEY".to_string()),
            timeout_ms: 30_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PoliciesConfig {
    pub policy_dir: PathBuf,
    pub reload_interval_sec: u64,
}

impl PoliciesConfig {
    fn resolve_paths(&mut self, base: Option<&Path>) {
        if self.policy_dir.is_relative() {
            if let Some(base_dir) = base {
                self.policy_dir = base_dir.join(&self.policy_dir);
            }
        }
    }
}

impl Default for PoliciesConfig {
    fn default() -> Self {
        Self {
            policy_dir: PathBuf::from("./policies"),
            reload_interval_sec: 60,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FiltersConfig {
    pub input: InputFiltersConfig,
    pub output: OutputFiltersConfig,
}

impl Default for FiltersConfig {
    fn default() -> Self {
        Self {
            input: InputFiltersConfig::default(),
            output: OutputFiltersConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct InputFiltersConfig {
    pub enabled: bool,
    pub detect_injection: bool,
    pub detect_jailbreak: bool,
    pub unicode_normalize: bool,
    pub max_tokens: u32,
}

impl Default for InputFiltersConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            detect_injection: true,
            detect_jailbreak: true,
            unicode_normalize: true,
            max_tokens: 4096,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct OutputFiltersConfig {
    pub enabled: bool,
    pub scan_pii: bool,
    pub scan_secrets: bool,
    pub redact_patterns: Vec<String>,
}

impl Default for OutputFiltersConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_pii: true,
            scan_secrets: true,
            redact_patterns: vec![
                r"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    pub enable_tracing: bool,
    pub enable_metrics: bool,
    pub prometheus_port: u16,
    pub log_level: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enable_tracing: true,
            enable_metrics: true,
            prometheus_port: 9090,
            log_level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub backend: StorageBackend,
    pub path: PathBuf,
    pub audit_retention_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackend::Sqlite,
            path: PathBuf::from("./data/veridion.db"),
            audit_retention_days: 90,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackend {
    Sqlite,
    Postgres,
    Rocksdb,
}

impl Default for StorageBackend {
    fn default() -> Self {
        StorageBackend::Sqlite
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {0:?}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
}
