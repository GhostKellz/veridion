<p align="center">
  <img src="assets/logo/veridion.png" alt="Veridion" width="300"/>
</p>

<h1 align="center">Veridion</h1>

<p align="center">
  <strong>OPA meets sudo meets AI safety — authorize agent actions before they run</strong>
</p>

<p align="center">
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-2024-CE422B?style=for-the-badge&logo=rust&logoColor=white" alt="Rust 2024"/></a>
  <a href="https://tokio.rs/"><img src="https://img.shields.io/badge/Tokio-Async_Runtime-0B7261?style=for-the-badge&logo=tokio&logoColor=white" alt="Tokio"/></a>
  <a href="https://www.sqlite.org/"><img src="https://img.shields.io/badge/SQLite-Audit_Log-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite"/></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Policy_Engine-TOML-43A047?style=for-the-badge" alt="Policy Engine · TOML"/>
  <img src="https://img.shields.io/badge/Risk-Scoring-E53935?style=for-the-badge" alt="Risk Scoring"/>
  <img src="https://img.shields.io/badge/Approval-Workflow-F57C00?style=for-the-badge" alt="Approval Workflow"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Audit-Trail-8E24AA?style=for-the-badge" alt="Audit Trail"/>
  <img src="https://img.shields.io/badge/Zero_Trust-Default_Deny-1E88E5?style=for-the-badge" alt="Zero Trust"/>
</p>

---

## Overview

**Veridion** is an in-process Rust **library** that authorizes the actions an AI
agent wants to take — running a shell command, writing a file, delegating to a
sub-agent, reaching a remote host — *before* they execute. Think **OPA meets
sudo meets AI safety**: declarative policy, a deny-by-default posture, risk
scoring, and human-in-the-loop approval, all evaluated in-process.

It is not a server, proxy, or gateway. There is no HTTP, no upstream model, and
no content redaction. An agent builds an `ActionRequest`, calls
`veridion.authorize(&request).await`, and runs the action only if the returned
`Authorization` is `permitted`.

### Why Veridion?

- **Deny-by-default** — actions are denied unless a policy rule explicitly allows them.
- **Always-deny floor** — catastrophic patterns are blocked before any rule can allow them, and the floor cannot be overridden.
- **Risk-aware** — heuristic analyzers score each action and can escalate an `allow` to `require_approval`.
- **Human-in-the-loop** — pluggable approval workflows for headless, dev, or interactive gating.
- **Auditable** — every authorization writes a record to a SQLite or in-memory audit log.
- **In-process** — a plain async Rust API; no network hop, no sidecar.

---

## Core Model

An agent constructs a request, evaluates it, and acts on the decision.

| Type | Role |
|------|------|
| `ActionRequest` | The action to authorize: `action` verb, `resource` target, `subject`, `context` attributes. |
| `ActionDecision` | The outcome of pure evaluation: an `Effect` plus the matched rule and risk. |
| `PolicyEngine` | Ordered rules (first match by priority), the always-deny floor, and risk escalation. |
| `RiskScore` | 0–100 heuristic score with a `RiskLevel` (Low/Medium/High/Critical). |
| `AuditLog` | Append-only record of every authorization (`sqlite` or `memory`). |
| `ApprovalWorkflow` | Wraps an `Approver` to gate `require_approval` decisions. |
| `Veridion` | Facade tying the engine, risk, audit, and approval together. |

`Effect` is one of `allow`, `deny`, or `require_approval`.

The `Subject` carries `id`, an optional `on_behalf_of`, and `roles`. Action
verbs are available as constants under `veridion::action::actions`: `exec`,
`fs.read`, `fs.write`, `fs.edit`, `agent.delegate`, `net.remote`,
`memory.remember`.

`veridion.evaluate(&request)` returns an `ActionDecision` with no side effects.
`veridion.authorize(&request).await` runs the full pipeline (including approval)
and writes an audit record, returning `Authorization { decision, approval, permitted }`.

---

## Architecture

```
   ┌─────────────────────────────────────────────┐
   │  AI Agent (e.g. Jarvis)                      │
   │  builds an ActionRequest and asks first      │
   └───────────────────────┬─────────────────────┘
                           │  veridion.authorize(&request).await
                           ▼
   ╔═════════════════════════════════════════════╗
   ║                 VERIDION                     ║
   ╠═════════════════════════════════════════════╣
   ║                                              ║
   ║   1. Risk scoring                            ║
   ║      analyzers → RiskScore (0–100)           ║
   ║                    │                         ║
   ║   2. Always-deny floor                       ║
   ║      catastrophic patterns → deny (locked)   ║
   ║                    │                         ║
   ║   3. Ordered policy rules                    ║
   ║      first match wins (priority desc)        ║
   ║                    │                         ║
   ║   4. Risk escalation                         ║
   ║      allow → require_approval if risk ≥ thr  ║
   ║                    │                         ║
   ║   5. Approval workflow                       ║
   ║      Approver resolves require_approval       ║
   ║                                              ║
   ╚═══════════════════════┬═════════════════════╝
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
   ┌──────────────────────┐   ┌────────────────────┐
   │  Authorization       │   │  AuditLog          │
   │  { decision,         │   │  AuditRecord per   │
   │    approval,         │   │  authorize()       │
   │    permitted }       │   │  (sqlite | memory) │
   └──────────────────────┘   └────────────────────┘
```

The agent runs the action only if `authorization.permitted` is `true`.

---

## Zero-Trust Model

1. **Default effect is deny** — with no matching rule, the action is denied.
2. **Non-overridable floor** — `rm -rf /`, `rm -rf ~`, `mkfs`, raw writes to `/dev/sd*`/`/dev/nvme*`, and fork bombs are denied before any rule runs.
3. **First match wins** — rules are evaluated in priority order (descending); the first match decides the effect.
4. **Risk escalation** — when risk scoring is enabled and a score meets the configured threshold, an `allow` becomes `require_approval`.
5. **Explicit approval** — `require_approval` decisions are resolved by an `Approver`; the safe headless default denies.
6. **Every decision is recorded** — each `authorize` writes an `AuditRecord`.

Risk analyzers are heuristics, not a security boundary — the policy floor and
rules are the enforcement mechanism.

---

## Risk Scoring

`RiskScore` is a saturating 0–100 value with a `RiskLevel`:

| Level | Range |
|-------|-------|
| Low | 0–24 |
| Medium | 25–49 |
| High | 50–74 |
| Critical | 75–100 |

Built-in analyzers:

| Analyzer | Weight | Detects |
|----------|--------|---------|
| `DestructiveCommandAnalyzer` | 80 | Destructive shell operations |
| `InjectionAnalyzer` | 50 | Prompt/command injection patterns |
| `SecretAnalyzer` | 40 | Secrets and credentials |
| `JailbreakAnalyzer` | 40 | Jailbreak attempts |

---

## Tech Stack

| Component | Implementation |
|-----------|----------------|
| **Language** | Rust 1.96, edition 2024 |
| **Async runtime** | `tokio` (rt-multi-thread + macros) |
| **Serialization** | `serde`, `serde_json`, `toml` |
| **Audit storage** | `sqlx` (SQLite) |
| **Matching** | `regex`, `globset` |
| **Identifiers** | `uuid` |
| **Telemetry** | `tracing`, `tracing-subscriber` |
| **Errors** | `thiserror` |

---

## Installation

### As a Cargo Dependency

```toml
[dependencies]
veridion = { git = "https://github.com/ghostkellz/veridion", branch = "main" }
```

### From Source

```bash
git clone https://github.com/ghostkellz/veridion.git
cd veridion

cargo build --release
cargo test
cargo install --path .
```

---

## Library Quickstart

```rust
use veridion::{Config, Veridion};
use veridion::action::{ActionRequest, Subject, actions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let veridion = Veridion::from_config(&Config::default()).await?;
    let request = ActionRequest::new(actions::EXEC, "rm -rf /tmp/cache")
        .subject(Subject::new("jarvis").with_role("agent"))
        .attr("repo", "veridion");
    let auth = veridion.authorize(&request).await?;
    if auth.permitted {
        // run the command
    }
    Ok(())
}
```

---

## Writing Policies

Policy rules live in `policies/*.toml`. Each rule has a `priority`, an `effect`
(`allow`, `deny`, or `require_approval` — default `deny`), and a set of
conditions. The engine evaluates rules in priority order and the first match
wins.

```toml
[[policy]]
name = "allow_repo_writes"
description = "writes inside the working repo"
priority = 10
effect = "allow"                # allow | deny | require_approval (default deny)
[policy.conditions]
action = "fs.write"
subject_roles = ["agent"]
[policy.conditions.attributes]
repo = { type = "equals", value = "veridion" }   # exists | equals | regex | one_of
```

Attribute condition types: `exists`, `equals`, `regex`, `one_of`.

---

## Configuration

Configuration lives in `veridion.toml`:

```toml
[policy]
policy_dir = "policies"
default_effect = "deny"        # allow | deny | require_approval

[risk]
enabled = true
detect_destructive = true
detect_secrets = true
detect_injection = true
approval_threshold = 75         # risk score that should require approval

[audit]
backend = "sqlite"              # sqlite | memory
path = "veridion-audit.db"

[approval]
default = "deny"                # deny | allow | interactive

[telemetry]
enable_tracing = true
log_level = "info"
```

Approval modes:

- `deny` — the safe headless default; denies every `require_approval`.
- `allow` — approves everything (development only).
- `interactive` — prompts on the terminal.

Custom approvers implement the `Approver` trait.

---

## CLI

The `veridion` binary reads a JSON `ActionRequest` on stdin and prints the
`Authorization` as JSON. It exits `0` if permitted, `1` if not, and `2` on
error, so it composes with shell control flow. The config path is read from
`VERIDION_CONFIG`.

```bash
echo '{"action":"exec","resource":"ls -la"}' | veridion && run-the-thing
```

---

## Example: Agent Integration

[`examples/jarvis_integration.rs`](examples/jarvis_integration.rs) shows a
Jarvis-style `Action` enum mapped into `ActionRequest` inside a dispatch loop —
the engine is consulted before every action:

```
[RUN ] read: src/main.rs                        risk=  0 effect=allow — matched rule 'allow_reads'
[RUN ] bash: git status                         risk=  0 effect=allow — matched rule 'allow_safe_bash'
[RUN ] write: src/policy.rs (7 bytes)           risk=  0 effect=allow — matched rule 'allow_repo_writes'
[BLOCK] bash: rm -rf / --no-preserve-root        risk= 80 effect=deny — blocked by always-deny floor: floor_rm_root
[BLOCK] remote prod-1: systemctl restart api     risk=  0 effect=require_approval — matched rule 'approve_remote'
```

---

## Use Cases

- **Autonomous agent runtimes** — an agent like Jarvis calls `authorize` before any sensitive action, gating shell execution, file reads/writes/edits, sub-agent delegation, and remote commands.
- **Guarding shell and filesystem access** — allow reads and safe commands, deny destructive ones outright via the always-deny floor, and require approval for anything risky.
- **Delegation control** — decide whether an agent may hand work to another agent (`agent.delegate`).
- **Remote action gating** — require human approval before an agent touches a remote host (`net.remote`).
- **Auditable agent behavior** — retain a durable record of every action an agent attempted and its decision.

---

## Project Structure

```
veridion/
├── src/
│   ├── action.rs        # ActionRequest, Subject, action verbs
│   ├── decision.rs      # ActionDecision, Effect, Authorization
│   ├── policy.rs        # policy rules, conditions, loading
│   ├── risk.rs          # RiskScore, RiskLevel, analyzers
│   ├── audit.rs         # AuditLog, AuditRecord
│   ├── approval.rs      # ApprovalWorkflow, Approver
│   ├── engine.rs        # PolicyEngine pipeline
│   ├── config.rs        # Config and veridion.toml parsing
│   ├── telemetry.rs     # tracing setup
│   ├── lib.rs           # Veridion facade
│   └── main.rs          # CLI entry point
├── policies/            # example policy rules
└── examples/            # jarvis_integration.rs
```

---

## Documentation

Full documentation index: [docs/README.md](docs/README.md).

- [Installation](docs/getting-started/installation.md)
- [Quickstart](docs/getting-started/quickstart.md)
- [Configuration](docs/getting-started/configuration.md)
- [Writing Policies](docs/guides/writing-policies.md)
- [Risk Scoring](docs/guides/risk-scoring.md)
- [Approvals](docs/guides/approvals.md)
- [Audit Logging](docs/guides/audit-logging.md)
- [Observability](docs/guides/observability.md)
- [Library API](docs/reference/library-api.md)
- [Policy Language](docs/reference/policy-language.md)
- [CLI](docs/reference/cli.md)
- [Architecture](docs/internals/architecture.md)
- [Running Tests](docs/testing/running-tests.md)

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
git clone https://github.com/ghostkellz/veridion.git
cd veridion

cargo clippy --all-targets --all-features
cargo fmt --check
cargo test --all-features
```

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability reporting process,
supported versions, and disclosure policy.

---

## License

Licensed under the **MIT License** — see [LICENSE](LICENSE) for details.
