//! Typed configuration and TOML loading.
//!
//! A [`Config`] is normally loaded from a `veridion.toml` file with
//! [`Config::from_file`]. Every field has a default, so a minimal config only
//! needs to override what it cares about. The default posture is deny-by-default
//! with risk analysis enabled.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Top-level configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Policy loading and default effect.
    pub policy: PolicyConfig,
    /// Risk analyzer selection and approval threshold.
    pub risk: RiskConfig,
    /// Audit log backend.
    pub audit: AuditConfig,
    /// Approval defaults.
    pub approval: ApprovalConfig,
    /// Tracing/logging.
    pub telemetry: TelemetryConfig,
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .map_err(|err| ConfigError::Io(path.to_path_buf(), err))?;
        let config = toml::from_str(&content)?;
        Ok(config)
    }

    /// A permissive configuration for local development: default-allow, no audit
    /// persistence, risk analysis on. Not for production use.
    pub fn permissive() -> Self {
        Self {
            policy: PolicyConfig {
                default_effect: DefaultEffect::Allow,
                ..PolicyConfig::default()
            },
            audit: AuditConfig {
                backend: AuditBackend::Memory,
                ..AuditConfig::default()
            },
            ..Config::default()
        }
    }
}

/// How rules are loaded and what happens when none match.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// Directory of `*.toml` rule files.
    pub policy_dir: PathBuf,
    /// Effect applied when no rule matches.
    pub default_effect: DefaultEffect,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policy_dir: PathBuf::from("policies"),
            default_effect: DefaultEffect::Deny,
        }
    }
}

/// The effect applied when no rule matches an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultEffect {
    /// Allow by default (permissive).
    Allow,
    /// Deny by default (recommended).
    Deny,
    /// Require approval by default.
    RequireApproval,
}

/// Risk analyzer selection and the automatic approval threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RiskConfig {
    /// Master switch for risk analysis.
    pub enabled: bool,
    /// Enable destructive-command detection.
    pub detect_destructive: bool,
    /// Enable secret-in-argument detection.
    pub detect_secrets: bool,
    /// Enable prompt-injection / jailbreak detection.
    pub detect_injection: bool,
    /// When set, actions scoring at or above this value are escalated to
    /// `require_approval` even if a rule (or the default) would allow them.
    pub approval_threshold: Option<u8>,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            detect_destructive: true,
            detect_secrets: true,
            detect_injection: true,
            approval_threshold: Some(75),
        }
    }
}

/// Audit persistence backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Which backend to use.
    pub backend: AuditBackend,
    /// SQLite database path (ignored by the in-memory backend).
    pub path: PathBuf,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            backend: AuditBackend::Sqlite,
            path: PathBuf::from("veridion-audit.db"),
        }
    }
}

/// Supported audit backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditBackend {
    /// Durable SQLite storage.
    Sqlite,
    /// Ephemeral in-process storage (tests, dev).
    Memory,
}

/// Approval defaults used when the engine's own workflow resolves an approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApprovalConfig {
    /// Default resolution when no interactive approver is wired.
    pub default: ApprovalMode,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            default: ApprovalMode::Deny,
        }
    }
}

/// How an unattended approval resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// Refuse anything that needs approval (safe headless default).
    Deny,
    /// Approve anything that needs approval (dangerous; dev only).
    Allow,
    /// Prompt on the terminal.
    Interactive,
}

/// Structured logging / tracing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// Whether to install a tracing subscriber.
    pub enable_tracing: bool,
    /// `EnvFilter` directive, e.g. `info` or `veridion=debug`.
    pub log_level: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enable_tracing: true,
            log_level: "info".to_string(),
        }
    }
}

/// Errors from loading configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The config file could not be read.
    #[error("failed to read config {0:?}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    /// The config file was not valid TOML.
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
}
