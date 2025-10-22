use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use httpmock::prelude::*;
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::sync::RwLock;
use tower::util::ServiceExt;
use veridion::{
    config::{Config, PolicyMode, StorageBackend},
    filters::FilterEngine,
    policy::PolicyEngine,
    server::{ApplicationState, ChatMessage, ChatProxyRequest, build_router},
    storage::Storage,
    upstream::UpstreamClient,
};

#[tokio::test]
async fn proxy_pipeline_redacts_and_logs() -> Result<(), Box<dyn std::error::Error>> {
    let mock_server = MockServer::start_async().await;
    let _mock = mock_server
        .mock_async(|when, then| {
            when.method(POST).path("/v1/chat/completions");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                            "choices": [{
                                "message": {
                                    "role": "assistant",
                                    "content": "Contact us at security@example.com"
                                }
                            }]
                }));
        })
        .await;

    let temp_dir = tempdir()?;

    let mut config = Config::default_insecure();
    config.security.default_policy = PolicyMode::Allow;
    config.upstream.endpoint = mock_server.url("/v1/chat/completions");
    config.upstream.api_key_env = None;
    config.filters.input.enabled = false;
    config.filters.output.enabled = true;
    config.filters.output.scan_pii = true;
    config.filters.output.scan_secrets = false;
    config.storage.backend = StorageBackend::Sqlite;
    config.storage.path = temp_dir.path().join("audit.db");
    config.policies.policy_dir = temp_dir.path().join("policies");

    let filters = Arc::new(FilterEngine::new(&config.filters));
    let upstream = Arc::new(UpstreamClient::new(config.upstream.clone())?);
    let storage = Arc::new(Storage::new(config.storage.clone()).await?);
    let mut policy_engine = PolicyEngine::new(config.security.default_policy.clone());
    policy_engine.reload(&config.policies)?;
    let policy_engine = Arc::new(RwLock::new(policy_engine));
    let shared_config = Arc::new(config);

    let state = ApplicationState {
        config: Arc::clone(&shared_config),
        policy_engine,
        filters: Arc::clone(&filters),
        storage: Arc::clone(&storage),
        upstream: Arc::clone(&upstream),
    };

    let app = build_router(state);

    let request_body = ChatProxyRequest {
        model: "gpt-4".to_string(),
        messages: vec![ChatMessage {
            role: "user".to_string(),
            content: "Say hello".to_string(),
        }],
        user_id: Some("user-1".to_string()),
        request_id: None,
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request_body)?))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let json: Value = serde_json::from_slice(&body_bytes)?;

    assert_eq!(
        json.get("policy_action").and_then(Value::as_str),
        Some("allow")
    );
    assert_eq!(
        json.get("filter_decision").and_then(Value::as_str),
        Some("redact")
    );

    let redacted_content = json
        .get("upstream_response")
        .and_then(|v| v.get("choices"))
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    assert_eq!(redacted_content, "[redacted by veridion]");

    let violations = json
        .get("filter_violations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        violations
            .iter()
            .any(|v| v.as_str().unwrap_or_default().contains("email address"))
    );

    let events = storage.recent_events(5).await?;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].get("filter_decision").and_then(Value::as_str),
        Some("redact")
    );

    Ok(())
}
