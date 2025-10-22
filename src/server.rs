use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    config::Config,
    filters::{FilterDecision, FilterEngine},
    policy::{PolicyAction, PolicyContext, PolicyDecision, PolicyEngine},
    storage::{AuditEvent, Storage},
    upstream::UpstreamClient,
};

#[derive(Clone)]
pub struct ApplicationState {
    pub config: Arc<Config>,
    pub policy_engine: Arc<RwLock<PolicyEngine>>,
    pub filters: Arc<FilterEngine>,
    pub storage: Arc<Storage>,
    pub upstream: Arc<UpstreamClient>,
}

pub fn build_router(state: ApplicationState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/chat/completions", post(proxy_chat))
        .with_state(state)
}

pub async fn serve(config: Arc<Config>, state: ApplicationState) -> Result<(), ServerError> {
    let socket_addr = resolve_socket_addr(&config).await?;

    let listener = tokio::net::TcpListener::bind(socket_addr)
        .await
        .map_err(ServerError::BindFailed)?;

    if let Ok(addr) = listener.local_addr() {
        info!("listening on http://{}", addr);
    }

    axum::serve(listener, build_router(state))
        .await
        .map_err(ServerError::ServerFailed)
}

async fn resolve_socket_addr(config: &Config) -> Result<SocketAddr, ServerError> {
    if let Ok(ip) = config.server.host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, config.server.port));
    }

    tokio::net::lookup_host((config.server.host.as_str(), config.server.port))
        .await
        .map_err(|err| {
            ServerError::InvalidAddress(format!(
                "{}:{} ({err})",
                config.server.host, config.server.port
            ))
        })?
        .next()
        .ok_or_else(|| {
            ServerError::InvalidAddress(format!("{}:{}", config.server.host, config.server.port))
        })
}

async fn health(State(state): State<ApplicationState>) -> impl IntoResponse {
    let response = json!({
        "status": "ok",
        "policy_mode": format!("{:?}", state.config.security.default_policy),
    });
    (StatusCode::OK, Json(response))
}

async fn proxy_chat(
    State(state): State<ApplicationState>,
    Json(mut request): Json<ChatProxyRequest>,
) -> impl IntoResponse {
    let request_id = request
        .request_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    request.request_id = Some(request_id.clone());

    let user_id = request
        .user_id
        .clone()
        .unwrap_or_else(|| "anonymous".to_string());

    let headers = HashMap::new();
    let input_preview = request
        .messages
        .last()
        .map(|message| message.content.as_str());

    let token_estimate = request.estimated_tokens();

    let input_filters = match state
        .filters
        .inspect_input(input_preview.unwrap_or_default())
    {
        Ok(verdict) => verdict,
        Err(error) => {
            warn!("input filter error: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if input_filters.decision == FilterDecision::Block {
        let violations: Vec<String> = input_filters
            .violations
            .iter()
            .map(|v| format!("input: {v}"))
            .collect();

        warn!("request blocked by input filters");
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "request blocked by security filters",
                "request_id": request_id,
                "violations": violations,
            })),
        )
            .into_response();
    }

    let policy_decision = evaluate_policy(&state, &headers, input_preview, token_estimate).await;
    let policy_rule_name = policy_decision.rule.as_ref().map(|r| r.name.clone());

    match policy_decision.action {
        PolicyAction::Deny => {
            warn!("request denied by policy");
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "request denied by policy engine",
                    "policy": policy_rule_name,
                    "request_id": request_id,
                })),
            )
                .into_response();
        }
        PolicyAction::Warn => {
            warn!("request flagged by policy");
        }
        PolicyAction::Allow => {}
    }

    let upstream_response = match state.upstream.forward_chat(&request).await {
        Ok(response) => response,
        Err(error) => {
            warn!("upstream request failed: {error}");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": "upstream request failed",
                    "details": error.to_string(),
                    "request_id": request_id,
                })),
            )
                .into_response();
        }
    };

    let output_text = extract_output_text(&upstream_response.body)
        .unwrap_or_else(|| upstream_response.body.to_string());

    let output_filters = match state.filters.inspect_output(&output_text) {
        Ok(verdict) => verdict,
        Err(error) => {
            warn!("output filter error: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut violation_messages: Vec<String> = input_filters
        .violations
        .iter()
        .map(|v| format!("input: {v}"))
        .collect();
    violation_messages.extend(
        output_filters
            .violations
            .iter()
            .map(|v| format!("output: {v}")),
    );

    if output_filters.decision == FilterDecision::Block {
        warn!("response blocked by output filters");

        let audit_event = AuditEvent {
            request_id: request_id.clone(),
            user_id: user_id.clone(),
            action: "proxy_chat".to_string(),
            policy: policy_rule_name.clone(),
            policy_action: policy_decision.action,
            filter_decision: output_filters.decision,
            filter_violations: violation_messages.clone(),
        };

        if let Err(err) = state.storage.record_audit_event(&audit_event).await {
            warn!("failed to record audit event: {err}");
        }

        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "response blocked by security filters",
                "policy": policy_rule_name,
                "request_id": request_id,
                "violations": violation_messages,
            })),
        )
            .into_response();
    }

    let final_decision = combine_decisions(input_filters.decision, output_filters.decision);

    let sanitized_body = if output_filters.decision == FilterDecision::Redact {
        apply_redaction(upstream_response.body.clone())
    } else {
        upstream_response.body.clone()
    };

    let response = ChatProxyResponse {
        request_id: request_id.clone(),
        policy_action: policy_decision.action,
        policy_rule: policy_rule_name.clone(),
        filter_decision: final_decision,
        filter_violations: violation_messages.clone(),
        upstream_latency_ms: upstream_response.latency_ms,
        upstream_response: sanitized_body,
    };

    let audit_event = AuditEvent {
        request_id,
        user_id,
        action: "proxy_chat".to_string(),
        policy: policy_rule_name,
        policy_action: policy_decision.action,
        filter_decision: final_decision,
        filter_violations: violation_messages,
    };

    if let Err(err) = state.storage.record_audit_event(&audit_event).await {
        warn!("failed to record audit event: {err}");
    }

    (StatusCode::OK, Json(response)).into_response()
}

async fn evaluate_policy(
    state: &ApplicationState,
    headers: &HashMap<String, String>,
    input_preview: Option<&str>,
    token_estimate: Option<usize>,
) -> PolicyDecision {
    let context = PolicyContext::new(
        "POST",
        "/v1/chat/completions",
        headers,
        input_preview,
        token_estimate,
    );
    let engine = state.policy_engine.read().await;
    engine.evaluate(&context)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatProxyRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
}

impl ChatProxyRequest {
    fn estimated_tokens(&self) -> Option<usize> {
        let text: String = self
            .messages
            .iter()
            .map(|message| message.content.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        if text.is_empty() {
            None
        } else {
            Some(text.split_whitespace().count())
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct ChatProxyResponse {
    pub request_id: String,
    pub policy_action: PolicyAction,
    pub policy_rule: Option<String>,
    pub filter_decision: FilterDecision,
    pub filter_violations: Vec<String>,
    pub upstream_latency_ms: u128,
    pub upstream_response: Value,
}

fn combine_decisions(a: FilterDecision, b: FilterDecision) -> FilterDecision {
    if decision_rank(a) >= decision_rank(b) {
        a
    } else {
        b
    }
}

fn decision_rank(decision: FilterDecision) -> u8 {
    match decision {
        FilterDecision::Allow => 0,
        FilterDecision::Warn => 1,
        FilterDecision::Redact => 2,
        FilterDecision::Block => 3,
    }
}

fn extract_output_text(value: &Value) -> Option<String> {
    if let Some(choices) = value.get("choices").and_then(|v| v.as_array()) {
        for choice in choices {
            if let Some(content) = choice
                .get("message")
                .and_then(|message| message.get("content"))
                .and_then(Value::as_str)
            {
                return Some(content.to_string());
            }
        }
    }

    value
        .get("content")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
}

fn apply_redaction(mut payload: Value) -> Value {
    if let Some(choices_value) = payload.get_mut("choices") {
        if let Value::Array(choices) = choices_value {
            for choice in choices {
                if let Some(message_value) = choice.get_mut("message") {
                    if let Value::Object(message) = message_value {
                        if let Some(content) = message.get_mut("content") {
                            *content = Value::String("[redacted by veridion]".to_string());
                        }
                    }
                }
            }
        }
    }

    if let Some(content_value) = payload.get_mut("content") {
        *content_value = Value::String("[redacted by veridion]".to_string());
    }

    if payload.is_string() {
        payload = Value::String("[redacted by veridion]".to_string());
    }

    payload
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("failed to bind listener: {0}")]
    BindFailed(#[source] std::io::Error),
    #[error("server encountered an error: {0}")]
    ServerFailed(#[source] std::io::Error),
    #[error("invalid listen address: {0}")]
    InvalidAddress(String),
}
