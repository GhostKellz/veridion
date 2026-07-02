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
        let mut config: Self = toml::from_str(&content)?;
        if config.policy.policy_dir.is_relative()
            && let Some(parent) = path.parent()
        {
            config.policy.policy_dir = parent.join(&config.policy.policy_dir);
        }
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
    #[serde(default = "default_policy_dir")]
    pub policy_dir: PathBuf,
    /// Effect applied when no rule matches.
    #[serde(default = "default_default_effect")]
    pub default_effect: DefaultEffect,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policy_dir: default_policy_dir(),
            default_effect: default_default_effect(),
        }
    }
}

fn default_policy_dir() -> PathBuf {
    PathBuf::from("policies")
}

fn default_default_effect() -> DefaultEffect {
    DefaultEffect::Deny
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
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Enable destructive-command detection.
    #[serde(default = "default_true")]
    pub detect_destructive: bool,
    /// Enable secret-in-argument detection.
    #[serde(default = "default_true")]
    pub detect_secrets: bool,
    /// Enable prompt-injection / jailbreak detection.
    #[serde(default = "default_true")]
    pub detect_injection: bool,
    /// When set, actions scoring at or above this value are escalated to
    /// `require_approval` even if a rule (or the default) would allow them.
    #[serde(default = "default_approval_threshold")]
    pub approval_threshold: Option<u8>,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            detect_destructive: default_true(),
            detect_secrets: default_true(),
            detect_injection: default_true(),
            approval_threshold: default_approval_threshold(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_approval_threshold() -> Option<u8> {
    Some(75)
}

/// Audit persistence backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Which backend to use.
    #[serde(default = "default_audit_backend")]
    pub backend: AuditBackend,
    /// SQLite database path (ignored by the in-memory backend).
    #[serde(default = "default_audit_path")]
    pub path: PathBuf,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            backend: default_audit_backend(),
            path: default_audit_path(),
        }
    }
}

fn default_audit_backend() -> AuditBackend {
    AuditBackend::Sqlite
}

fn default_audit_path() -> PathBuf {
    PathBuf::from("veridion-audit.db")
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
    #[serde(default = "default_approval_mode")]
    pub default: ApprovalMode,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            default: default_approval_mode(),
        }
    }
}

fn default_approval_mode() -> ApprovalMode {
    ApprovalMode::Deny
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
    #[serde(default = "default_true")]
    pub enable_tracing: bool,
    /// `EnvFilter` directive, e.g. `info` or `veridion=debug`.
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enable_tracing: default_true(),
            log_level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_file_resolves_relative_policy_dir_against_config_dir() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config_path = dir.path().join("veridion.toml");
        std::fs::write(&config_path, "[policy]\npolicy_dir = \"rules\"\n").expect("write config");

        let config = Config::from_file(&config_path).expect("load config");

        assert_eq!(config.policy.policy_dir, dir.path().join("rules"));
    }

    #[test]
    fn from_file_keeps_absolute_policy_dir() {
        let dir = tempfile::tempdir().expect("temp dir");
        let absolute = dir.path().join("rules");
        let config_path = dir.path().join("veridion.toml");
        std::fs::write(
            &config_path,
            format!("[policy]\npolicy_dir = \"{}\"\n", absolute.display()),
        )
        .expect("write config");

        let config = Config::from_file(&config_path).expect("load config");

        assert_eq!(config.policy.policy_dir, absolute);
    }

    #[test]
    fn partial_sections_keep_config_defaults() {
        let config: Config = toml::from_str(
            r#"
            [risk]
            enabled = true

            [audit]
            backend = "memory"

            [telemetry]
            log_level = "debug"
            "#,
        )
        .expect("parse config");

        assert!(config.risk.detect_destructive);
        assert!(config.risk.detect_secrets);
        assert!(config.risk.detect_injection);
        assert_eq!(config.risk.approval_threshold, Some(75));
        assert_eq!(config.audit.backend, AuditBackend::Memory);
        assert_eq!(config.audit.path, PathBuf::from("veridion-audit.db"));
        assert!(config.telemetry.enable_tracing);
        assert_eq!(config.telemetry.log_level, "debug");
    }
}
