//! Audit logging of authorization decisions.
//!
//! Every call to [`Veridion::authorize`](crate::engine::Veridion::authorize)
//! produces an [`AuditRecord`] describing what was requested, what the engine
//! decided, and how any approval resolved. Records are written to an
//! [`AuditLog`], which is backed either by an in-memory buffer (tests, dev) or a
//! durable SQLite database.

use std::path::Path;
use std::str::FromStr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use thiserror::Error;
use uuid::Uuid;

use crate::action::ActionRequest;
use crate::approval::ApprovalOutcome;
use crate::config::{AuditBackend, AuditConfig};
use crate::decision::{ActionDecision, Effect};

/// A single audit record: the request, the decision, and any approval outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unique record id.
    pub id: String,
    /// The subject that requested the action.
    pub subject: String,
    /// The action verb.
    pub action: String,
    /// The action's target resource.
    pub resource: String,
    /// The decided effect.
    pub effect: Effect,
    /// Why the engine decided this way.
    pub reason: String,
    /// The computed risk score (0–100).
    pub risk: u8,
    /// The rule that matched, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    /// How an approval resolved, when the decision required one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalOutcome>,
}

impl AuditRecord {
    /// Build a record from a request and the decision it produced.
    pub fn from_decision(request: &ActionRequest, decision: &ActionDecision) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            subject: request.subject.id.clone(),
            action: request.action.clone(),
            resource: request.resource.clone(),
            effect: decision.effect,
            reason: decision.reason.clone(),
            risk: decision.risk.value,
            matched_rule: decision.matched_rule.as_ref().map(|r| r.name.clone()),
            approval: None,
        }
    }

    /// Attach the approval outcome for a decision that required one.
    pub fn with_approval(mut self, outcome: ApprovalOutcome) -> Self {
        self.approval = Some(outcome);
        self
    }
}

/// A durable (or in-memory) log of authorization decisions.
pub struct AuditLog {
    backend: Backend,
}

enum Backend {
    Memory(Mutex<Vec<AuditRecord>>),
    Sqlite(SqlitePool),
}

impl AuditLog {
    /// An ephemeral in-memory log (tests, dev).
    pub fn memory() -> Self {
        Self {
            backend: Backend::Memory(Mutex::new(Vec::new())),
        }
    }

    /// Build a log from configuration, opening SQLite when selected.
    pub async fn from_config(config: &AuditConfig) -> Result<Self, AuditError> {
        match config.backend {
            AuditBackend::Memory => Ok(Self::memory()),
            AuditBackend::Sqlite => {
                let pool = init_sqlite(&config.path).await?;
                Ok(Self {
                    backend: Backend::Sqlite(pool),
                })
            }
        }
    }

    /// Persist a record.
    pub async fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        match &self.backend {
            Backend::Memory(store) => {
                store
                    .lock()
                    .expect("audit mutex poisoned")
                    .push(record.clone());
                Ok(())
            }
            Backend::Sqlite(pool) => {
                let payload = serde_json::to_string(record)?;
                sqlx::query(
                    "INSERT INTO audit_log (id, subject, action, effect, risk, payload) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&record.id)
                .bind(&record.subject)
                .bind(&record.action)
                .bind(record.effect.to_string())
                .bind(record.risk as i64)
                .bind(payload)
                .execute(pool)
                .await
                .map_err(AuditError::Database)?;
                Ok(())
            }
        }
    }

    /// The most recent records, newest first (up to `limit`).
    pub async fn recent(&self, limit: usize) -> Result<Vec<AuditRecord>, AuditError> {
        match &self.backend {
            Backend::Memory(store) => {
                let store = store.lock().expect("audit mutex poisoned");
                Ok(store.iter().rev().take(limit).cloned().collect())
            }
            Backend::Sqlite(pool) => {
                let rows: Vec<(String,)> =
                    sqlx::query_as("SELECT payload FROM audit_log ORDER BY rowid DESC LIMIT ?")
                        .bind(limit as i64)
                        .fetch_all(pool)
                        .await
                        .map_err(AuditError::Database)?;
                let mut records = Vec::with_capacity(rows.len());
                for (payload,) in rows {
                    records.push(serde_json::from_str(&payload)?);
                }
                Ok(records)
            }
        }
    }
}

async fn init_sqlite(path: &Path) -> Result<SqlitePool, AuditError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(AuditError::Io)?;
    }

    let url = format!("sqlite://{}", path.display());
    let options = SqliteConnectOptions::from_str(&url)
        .map_err(AuditError::Database)?
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .map_err(AuditError::Database)?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_log ( \
             id TEXT PRIMARY KEY, \
             subject TEXT NOT NULL, \
             action TEXT NOT NULL, \
             effect TEXT NOT NULL, \
             risk INTEGER NOT NULL, \
             payload TEXT NOT NULL \
         )",
    )
    .execute(&pool)
    .await
    .map_err(AuditError::Database)?;

    Ok(pool)
}

/// Errors from opening or writing the audit log.
#[derive(Debug, Error)]
pub enum AuditError {
    /// The audit database directory could not be created.
    #[error("audit io error: {0}")]
    Io(#[source] std::io::Error),
    /// A database operation failed.
    #[error("audit database error: {0}")]
    Database(#[source] sqlx::Error),
    /// A record could not be (de)serialized.
    #[error("audit serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::actions;
    use crate::decision::ActionDecision;

    #[tokio::test]
    async fn memory_backend_round_trips() {
        let log = AuditLog::memory();
        let req = ActionRequest::new(actions::EXEC, "ls -la");
        let decision = ActionDecision::allow("ok");
        let record = AuditRecord::from_decision(&req, &decision);
        log.record(&record).await.expect("record");

        let recent = log.recent(10).await.expect("recent");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].action, "exec");
        assert_eq!(recent[0].effect, Effect::Allow);
    }
}
