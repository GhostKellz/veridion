use crate::{
    config::{StorageBackend, StorageConfig},
    filters::FilterDecision,
    policy::PolicyAction,
};
use serde_json::{Value, json};
use sqlx::{
    Row,
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions},
};
use std::{fs, path::PathBuf, str::FromStr};
use thiserror::Error;
use tracing::info;

#[derive(Debug, Clone)]
pub struct Storage {
    backend: StorageBackend,
    path: PathBuf,
    sqlite: Option<SqlitePool>,
}

impl Storage {
    pub async fn new(config: StorageConfig) -> Result<Self, StorageError> {
        match &config.backend {
            StorageBackend::Sqlite => {
                let pool = init_sqlite(&config.path).await?;
                Ok(Self {
                    backend: config.backend.clone(),
                    path: config.path.clone(),
                    sqlite: Some(pool),
                })
            }
            StorageBackend::Postgres => Err(StorageError::UnsupportedBackend(
                "PostgreSQL backend is not yet implemented".to_string(),
            )),
            StorageBackend::Rocksdb => Err(StorageError::UnsupportedBackend(
                "RocksDB backend is not yet implemented".to_string(),
            )),
        }
    }

    pub async fn record_audit_event(&self, event: &AuditEvent) -> Result<(), StorageError> {
        match self.backend.clone() {
            StorageBackend::Sqlite => {
                if let Some(pool) = &self.sqlite {
                    let violations_json = serde_json::to_string(&event.filter_violations)?;
                    sqlx::query(
                        "INSERT INTO audit_log (
                            request_id,
                            user_id,
                            action,
                            policy,
                            policy_action,
                            filter_decision,
                            filter_violations
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    )
                    .bind(&event.request_id)
                    .bind(&event.user_id)
                    .bind(&event.action)
                    .bind(&event.policy)
                    .bind(event.policy_action.to_string())
                    .bind(event.filter_decision.to_string())
                    .bind(violations_json)
                    .execute(pool)
                    .await?;
                } else {
                    info!("sqlite pool unavailable; audit event dropped");
                }
            }
            backend => {
                info!(
                    "audit logging skipped for unsupported backend {:?}",
                    backend
                );
            }
        }

        Ok(())
    }

    pub fn backend(&self) -> StorageBackend {
        self.backend.clone()
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub async fn recent_events(&self, limit: i64) -> Result<Vec<Value>, StorageError> {
        match self.backend.clone() {
            StorageBackend::Sqlite => {
                if let Some(pool) = &self.sqlite {
                    let rows = sqlx::query(
                        "SELECT request_id, user_id, action, policy, policy_action, filter_decision, filter_violations, created_at
                         FROM audit_log ORDER BY created_at DESC LIMIT ?1",
                    )
                    .bind(limit)
                    .fetch_all(pool)
                    .await?;

                    let events = rows
                        .into_iter()
                        .map(|row| {
                            let violations: String = row.get("filter_violations");
                            let violations_json: Value = serde_json::from_str(&violations)
                                .unwrap_or_else(|_| Value::String(violations));
                            json!({
                                "request_id": row.get::<String, _>("request_id"),
                                "user_id": row.get::<String, _>("user_id"),
                                "action": row.get::<String, _>("action"),
                                "policy": row.get::<Option<String>, _>("policy"),
                                "policy_action": row.get::<String, _>("policy_action"),
                                "filter_decision": row.get::<String, _>("filter_decision"),
                                "filter_violations": violations_json,
                                "created_at": row.get::<String, _>("created_at"),
                            })
                        })
                        .collect();
                    Ok(events)
                } else {
                    Ok(Vec::new())
                }
            }
            _ => Ok(Vec::new()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub request_id: String,
    pub user_id: String,
    pub action: String,
    pub policy: Option<String>,
    pub policy_action: PolicyAction,
    pub filter_decision: FilterDecision,
    pub filter_violations: Vec<String>,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("unsupported storage backend: {0}")]
    UnsupportedBackend(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

async fn init_sqlite(path: &PathBuf) -> Result<SqlitePool, StorageError> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    let conn_str = format!("sqlite://{}", path.display());
    let options = SqliteConnectOptions::from_str(&conn_str)?
        .create_if_missing(true)
        .to_owned();
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    migrate_sqlite(&pool).await?;
    Ok(pool)
}

async fn migrate_sqlite(pool: &SqlitePool) -> Result<(), StorageError> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            policy TEXT,
            policy_action TEXT NOT NULL,
            filter_decision TEXT NOT NULL,
            filter_violations TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}
