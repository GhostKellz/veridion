# 🧠 Veridion
**Guarding truth at the edge of intelligence**

![Zero Trust](https://img.shields.io/badge/zero--trust-enforced-blue)
![Security](https://img.shields.io/badge/security-hardened-red)
![AI Firewall](https://img.shields.io/badge/AI-firewall-brightgreen)
![Rust](https://img.shields.io/badge/rust-2024-orange)
![Cargo](https://img.shields.io/badge/cargo-ready-green)
![WASM](https://img.shields.io/badge/WASM-enabled-purple)

---

## Overview

**Veridion** is a zero-trust **AI firewall** and **model integrity platform** designed to protect large language model (LLM) systems from sophisticated threats including prompt injection, dataset poisoning, jailbreaking, and unauthorized data exfiltration.

Acting as a **security perimeter** around your AI inference and training pipelines, Veridion ensures **every token, embedding, and output** is verified, sanitized, and policy-compliant before reaching your models or users.

### Why Veridion?

- 🛡️ **Defense-in-Depth**: Multi-layer protection against prompt injection, indirect attacks, and adversarial inputs
- 🔐 **Zero-Trust Architecture**: Default-deny policies with cryptographic provenance verification
- ⚡ **High Performance**: Built in Rust with async runtime, minimal latency overhead (<5ms p99)
- 🧩 **Extensible**: WASM-based plugin system for custom policies and filters
- 📊 **Observable**: Full OpenTelemetry integration with audit trails and compliance reporting
- 🚀 **Production-Ready**: Designed for enterprise-scale AI deployments

---

## ✳️ Key Capabilities

| Category | Features |
|-----------|-----------|
| **Input Protection** | NLP-aware sanitization, injection detection, pattern redaction, adversarial input filtering |
| **Policy Enforcement** | Declarative TOML/YAML policies for roles, tools, safety rules, and content filtering |
| **Data Provenance** | Cryptographic signing + attestation (Sigstore/ZSig compatible), supply chain verification |
| **Output Guarding** | PII detection, secret scanning, hallucination detection, toxicity filtering, watermarking |
| **Telemetry & Audit** | OpenTelemetry + Prometheus metrics, immutable audit logs, compliance reporting |
| **Extensibility** | WASM and Zig plugin filters for custom redaction, analysis, and policy enforcement |

---

## ⚙️ Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │          Upstream Clients                   │
                    │  (API Gateway, Web UI, Mobile Apps)         │
                    └──────────────────┬──────────────────────────┘
                                       │
                                       ▼
        ╔══════════════════════════════════════════════════════════╗
        ║                    VERIDION FIREWALL                     ║
        ╠══════════════════════════════════════════════════════════╣
        ║                                                          ║
        ║  ┌────────────────────────────────────────────────────┐ ║
        ║  │  INPUT SANITIZATION LAYER                          │ ║
        ║  │  • Prompt injection detection                      │ ║
        ║  │  • Adversarial pattern filtering                   │ ║
        ║  │  • Unicode normalization & encoding validation     │ ║
        ║  │  • Token-level sanitization                        │ ║
        ║  └────────────────────────────────────────────────────┘ ║
        ║                         ▼                                ║
        ║  ┌────────────────────────────────────────────────────┐ ║
        ║  │  POLICY ENGINE                                     │ ║
        ║  │  • RBAC & attribute-based access control           │ ║
        ║  │  • Content policy validation (TOML/YAML)           │ ║
        ║  │  • Rate limiting & quota enforcement               │ ║
        ║  │  • Context-aware rule evaluation                   │ ║
        ║  └────────────────────────────────────────────────────┘ ║
        ║                         ▼                                ║
        ║  ┌────────────────────────────────────────────────────┐ ║
        ║  │  PROVENANCE & ATTESTATION                          │ ║
        ║  │  • Cryptographic signing (Sigstore/ZSig)           │ ║
        ║  │  • Content hashing (SHA-256/BLAKE3)                │ ║
        ║  │  • Supply chain verification                       │ ║
        ║  │  • Tamper-proof audit trail                        │ ║
        ║  └────────────────────────────────────────────────────┘ ║
        ║                         ▼                                ║
        ║  ┌────────────────────────────────────────────────────┐ ║
        ║  │  OUTPUT GUARD                                      │ ║
        ║  │  • PII & secret detection/redaction                │ ║
        ║  │  • Hallucination & factuality checking             │ ║
        ║  │  • Toxicity & bias filtering                       │ ║
        ║  │  • Optional watermarking                           │ ║
        ║  └────────────────────────────────────────────────────┘ ║
        ║                                                          ║
        ║  ┌────────────────────────────────────────────────────┐ ║
        ║  │  TELEMETRY & OBSERVABILITY                         │ ║
        ║  │  • OpenTelemetry traces & metrics                  │ ║
        ║  │  • Prometheus exporter                             │ ║
        ║  │  • Structured audit logging                        │ ║
        ║  └────────────────────────────────────────────────────┘ ║
        ╚══════════════════════════════════════════════════════════╝
                                       │
                                       ▼
                    ┌──────────────────────────────────────────────┐
                    │        Downstream LLM Providers              │
                    │  (vLLM, Ollama, OpenAI, Anthropic, etc.)     │
                    └──────────────────────────────────────────────┘
```

---

## 🔒 Zero-Trust Security Model

Veridion implements a **defense-in-depth** approach with the following principles:

1. **Default-Deny Input Policy** – All inputs are blocked unless explicitly allowed by policy rules
2. **Cryptographic Provenance** – All training data, RAG sources, and system prompts must be cryptographically signed
3. **Policy-Driven Authorization** – Every request validated against declarative RBAC and content policies
4. **Immutable Audit Trail** – Tamper-proof event chain with cryptographic linking for compliance and forensics
5. **Least Privilege** – Minimal permissions granted per request, scoped to specific models and operations
6. **Continuous Verification** – Real-time monitoring and anomaly detection across all layers

---

## 🧩 Tech Stack

| Component | Implementation |
|------------|----------------|
| **Core Runtime** | Rust 2024 (`axum`, `tokio`, `tower`, `serde`) |
| **HTTP/Proxy Layer** | `axum` + `tower` middleware for request filtering |
| **Plugin Filters** | Zig via FFI for zero-allocation high-speed text processing |
| **Async Engine** | Tokio runtime with structured tracing (`tracing`, `tracing-subscriber`) |
| **Provenance** | `sigstore-rs` signing, SHA-256/BLAKE3 content hashing |
| **Storage** | PostgreSQL / SQLite / RocksDB (policy store + audit log) |
| **Extensibility** | WASM sandbox (`wasmtime`) for tenant-safe dynamic policies |
| **Telemetry** | OpenTelemetry SDK + Prometheus exporter |
| **Serialization** | `serde` with TOML/YAML/JSON support |

---

## 📦 Installation

### From Source (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/ghostkellz/veridion.git
cd veridion

# Build in release mode
cargo build --release

# Run tests
cargo test

# Install binary to system
cargo install --path .
```

### As a Cargo Dependency

Add Veridion to your `Cargo.toml`:

```toml
[dependencies]
veridion = { git = "https://github.com/ghostkellz/veridion", branch = "main" }

# Or specify a version when published to crates.io
# veridion = "0.1.0"
```

Then use it in your Rust application:

```rust
use veridion::{Firewall, PolicyEngine, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = Config::from_file("veridion.toml")?;

    // Initialize firewall
    let firewall = Firewall::new(config).await?;

    // Start the proxy server
    firewall.serve("0.0.0.0:8080").await?;

    Ok(())
}
```

### Using Docker (Coming Soon)

```bash
docker pull ghcr.io/ghostkellz/veridion:latest
docker run -p 8080:8080 -v ./config:/config veridion:latest
```

---

## ⚡ Quick Start

### 1. Create a Configuration File

Create `veridion.toml` in your project directory:

```toml
[server]
host = "0.0.0.0"
port = 8080
workers = 4

[security]
# Zero-trust mode: reject all by default
default_policy = "deny"
enable_provenance = true
require_signed_prompts = false

[upstream]
# Your LLM backend
provider = "openai"
endpoint = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"
timeout_ms = 30000

[policies]
# Load policy rules from directory
policy_dir = "./policies"
reload_interval_sec = 60

[filters.input]
enabled = true
detect_injection = true
detect_jailbreak = true
unicode_normalize = true
max_tokens = 4096

[filters.output]
enabled = true
scan_pii = true
scan_secrets = true
redact_patterns = ["\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"]

[telemetry]
enable_tracing = true
enable_metrics = true
prometheus_port = 9090
log_level = "info"

[storage]
backend = "sqlite"
path = "./data/veridion.db"
audit_retention_days = 90
```

### 2. Define Security Policies

Create `policies/default.toml`:

```toml
[[policy]]
name = "block_injection_patterns"
description = "Prevent common prompt injection techniques"
action = "deny"

[policy.conditions]
input_contains = [
    "ignore previous instructions",
    "disregard all prior",
    "system: you are now",
    "<!-- inject:",
]

[[policy]]
name = "allow_authenticated_users"
description = "Allow requests from authenticated users"
action = "allow"

[policy.conditions]
headers."x-api-key" = { exists = true }
rate_limit = { max_requests = 100, window_sec = 60 }

[[policy]]
name = "redact_sensitive_output"
description = "Remove PII from model outputs"
action = "allow"

[policy.transformations]
redact_email = true
redact_phone = true
redact_ssn = true
redact_credit_card = true
```

### 3. Run Veridion

```bash
# Start the firewall
veridion --config ./veridion.toml

# Or with environment variables
VERIDION_CONFIG=./veridion.toml \
OPENAI_API_KEY=sk-your-key \
veridion
```

### 4. Send Requests Through the Firewall

```bash
# Route your AI requests through Veridion
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "Explain quantum computing"}
    ]
  }'
```

Veridion will:
1. ✅ Validate the request against security policies
2. ✅ Scan for prompt injection attempts
3. ✅ Forward sanitized request to upstream LLM
4. ✅ Scan response for PII/secrets
5. ✅ Return filtered response with audit trail

---

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VERIDION_CONFIG` | Path to configuration file | `./veridion.toml` |
| `VERIDION_LOG_LEVEL` | Logging level (trace, debug, info, warn, error) | `info` |
| `VERIDION_POLICY_DIR` | Directory containing policy files | `./policies` |
| `VERIDION_TELEMETRY_ENDPOINT` | OpenTelemetry collector endpoint | - |

### Policy Language Reference

Policies are written in TOML with the following structure:

```toml
[[policy]]
name = "policy_identifier"
description = "Human-readable description"
priority = 100  # Higher = evaluated first
action = "allow" | "deny" | "warn"

[policy.conditions]
# Request matching conditions
method = "POST"
path = "/v1/chat/completions"
headers."x-role" = "admin"
input_contains = ["pattern1", "pattern2"]
input_regex = "regex_pattern"
token_count = { min = 10, max = 4096 }

[policy.transformations]
# Output transformations
redact_email = true
redact_patterns = ["SSN:\\s*\\d{3}-\\d{2}-\\d{4}"]
add_watermark = true
```

---

## 📊 Monitoring & Observability

### Prometheus Metrics

Veridion exposes metrics on the configured Prometheus port (default: `:9090/metrics`):

- `veridion_requests_total` - Total requests processed
- `veridion_requests_blocked_total` - Requests blocked by policies
- `veridion_latency_seconds` - Request processing latency (histogram)
- `veridion_injection_detected_total` - Prompt injection attempts detected
- `veridion_pii_redacted_total` - PII instances redacted from outputs
- `veridion_policy_violations_total` - Policy violations by type

### Structured Logging

All events are logged with structured fields:

```json
{
  "timestamp": "2025-10-14T12:00:00Z",
  "level": "warn",
  "event": "policy_violation",
  "request_id": "req_abc123",
  "policy": "block_injection_patterns",
  "action": "deny",
  "user_id": "user_456",
  "ip_address": "192.168.1.100"
}
```

### Audit Trail

Every request creates an immutable audit record:

```sql
SELECT * FROM audit_log
WHERE request_id = 'req_abc123';

-- Returns:
-- id, timestamp, request_id, user_id, action, policy_matched,
-- input_hash, output_hash, signature, prev_hash
```

---

## 🚀 Use Cases

### 1. **Production LLM API Gateway**
Deploy Veridion as a reverse proxy in front of OpenAI, Anthropic, or self-hosted models to enforce organization-wide security policies.

### 2. **Multi-Tenant AI Platform**
Isolate tenants with WASM-based custom policies, ensuring data separation and compliance per customer.

### 3. **Compliance & Regulatory**
Meet SOC2, GDPR, HIPAA requirements with cryptographic audit trails and automatic PII redaction.

### 4. **RAG Pipeline Protection**
Sign and verify all retrieval documents, preventing poisoned context injection.

### 5. **Research & Red Teaming**
Test LLM robustness against adversarial prompts with detailed attack telemetry.

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone and setup
git clone https://github.com/ghostkellz/veridion.git
cd veridion

# Install development tools
cargo install cargo-watch cargo-audit

# Run in development mode with auto-reload
cargo watch -x run

# Run linter and formatter
cargo clippy --all-targets --all-features
cargo fmt --check

# Run full test suite
cargo test --all-features

# Check for security vulnerabilities
cargo audit
```

### Project Structure

```
veridion/
├── src/
│   ├── main.rs              # Entry point
│   ├── firewall.rs          # Core firewall logic
│   ├── policy/              # Policy engine
│   ├── filters/             # Input/output filters
│   ├── telemetry/           # Observability
│   └── storage/             # Persistence layer
├── policies/                # Example policies
├── config/                  # Configuration examples
├── tests/                   # Integration tests
└── benches/                 # Performance benchmarks
```

---

## 📚 Documentation

- [Architecture Deep Dive](docs/architecture.md)
- [Policy Language Guide](docs/policies.md)
- [WASM Plugin Development](docs/plugins.md)
- [API Reference](docs/api.md)
- [Security Best Practices](docs/security.md)
- [Deployment Guide](docs/deployment.md)

---

## 🔐 Security

**Reporting Vulnerabilities**: Please email security@veridion.dev or open a private security advisory on GitHub.

We follow responsible disclosure practices and will acknowledge reports within 48 hours.

---

## 📜 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

Built with:
- [Rust](https://www.rust-lang.org/) - Systems programming language
- [Tokio](https://tokio.rs/) - Async runtime
- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [Sigstore](https://www.sigstore.dev/) - Supply chain security
- [OpenTelemetry](https://opentelemetry.io/) - Observability

Inspired by security frameworks from OWASP LLM Top 10 and NIST AI RMF.

---

**Made with 🛡️ Zero Trust in mind*
*Securing AI, one token at a time.*
