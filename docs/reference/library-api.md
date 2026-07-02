# Library API

Veridion is a Rust library for authorizing AI agent actions. An agent describes
what it is about to do as an [`ActionRequest`] and asks Veridion whether it may
proceed; Veridion answers with an [`ActionDecision`] — allow, deny, or require
approval — and, through the [`Veridion`] facade, resolves any approval and writes
an audit record.

The crate re-exports its primary types from the root:

```rust
pub use action::{ActionRequest, Context, Subject};
pub use approval::{ApprovalOutcome, ApprovalWorkflow, Approver};
pub use audit::{AuditLog, AuditRecord};
pub use config::Config;
pub use decision::{ActionDecision, Effect};
pub use engine::{Authorization, Veridion};
pub use policy::{PolicyEngine, PolicyRule};
pub use risk::{RiskLevel, RiskScore};
```

Public modules: `action`, `approval`, `audit`, `config`, `decision`, `engine`,
`policy`, `risk`, `telemetry`.

## Quick Start

`Veridion` is the object an agent runtime holds. Build it from a `Config`, then
call `authorize` and branch on `permitted`:

```rust
use veridion::{Config, Veridion};
use veridion::action::{ActionRequest, Subject, actions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let veridion = Veridion::from_config(&Config::default()).await?;

    let request = ActionRequest::new(actions::EXEC, "git push origin main")
        .subject(Subject::new("jarvis").with_role("agent"))
        .attr("repo", "veridion");

    let auth = veridion.authorize(&request).await?;
    if auth.permitted {
        // run the command
    } else {
        eprintln!("blocked: {}", auth.decision.reason);
    }
    Ok(())
}
```

`authorize` runs the full workflow: evaluate the request, resolve any required
approval, write an [`AuditRecord`], and report whether the action may proceed.

For a decision without side effects — no approval prompt, no audit write — use
the pure `evaluate`:

```rust
let decision = veridion.evaluate(&request);
if decision.is_allowed() {
    // safe to proceed with no approval step
}
```

## `Veridion`

The facade composes a [`PolicyEngine`], an [`ApprovalWorkflow`], and an
[`AuditLog`].

| Method | Returns | Description |
|--------|---------|-------------|
| `Veridion::from_config(&Config)` | `Result<Veridion, VeridionError>` (async) | Build the whole stack from config |
| `Veridion::new(policy, approval, audit)` | `Veridion` | Assemble from explicit parts |
| `veridion.evaluate(&ActionRequest)` | `ActionDecision` | Pure decision, no side effects |
| `veridion.authorize(&ActionRequest)` | `Result<Authorization, VeridionError>` (async) | Full workflow: evaluate, approve, audit |
| `veridion.policy()` | `&PolicyEngine` | The policy engine, for reload and inspection |
| `veridion.audit()` | `&AuditLog` | The audit log, for querying recent decisions |

`Authorization` is the outcome of a full `authorize` call:

```rust
pub struct Authorization {
    pub decision: ActionDecision,
    pub approval: Option<ApprovalOutcome>,
    pub permitted: bool,
}
```

`permitted` is `true` for an `Allow`, `false` for a `Deny`, and — for
`RequireApproval` — `true` only when the approver approved.

## `action` — the request

An [`ActionRequest`] is attribute-based access control (ABAC): a `subject`
performs an `action` on a `resource` within a `context` of attributes.

```rust
use veridion::action::{ActionRequest, Subject, actions};

let request = ActionRequest::new(actions::EXEC, "rm -rf /tmp/cache")
    .subject(Subject::new("jarvis").with_role("agent").on_behalf_of("alice"))
    .attr("repo", "veridion")
    .attr("interactive", true);
```

Fields: `action: String`, `resource: String`, `subject: Subject`,
`context: Context`.

| Type | Selected API |
|------|--------------|
| `ActionRequest` | `new(action, resource)`, `.subject(Subject)`, `.attr(k, v)` |
| `Subject` | `new(id)`, `.with_role(r)`, `.on_behalf_of(p)`, `.has_role(r)` |
| `Context` | `new()`, `.with(k, v)`, `.get(k)` |

The `actions` module provides well-known verb constants: `EXEC`, `FS_READ`,
`FS_WRITE`, `FS_EDIT`, `AGENT_DELEGATE`, `NET_REMOTE`, `MEMORY_REMEMBER`. Actions
are plain namespaced strings, so an agent can introduce its own verbs.

Attribute values are a small closed set (`AttributeValue`): text, integer, bool,
or list of text. Any `impl Into<AttributeValue>` is accepted by `.attr`/`.with`.

## `decision` — the outcome

```rust
pub struct ActionDecision {
    pub effect: Effect,               // Allow | Deny | RequireApproval
    pub reason: String,
    pub matched_rule: Option<RuleRef>,
    pub risk: RiskScore,
}
```

Constructors and helpers:

| Item | Description |
|------|-------------|
| `ActionDecision::allow(reason)` | An allow decision |
| `ActionDecision::deny(reason)` | A deny decision |
| `ActionDecision::require_approval(reason)` | A require-approval decision |
| `.with_rule(RuleRef)` | Attach the rule that matched |
| `.with_risk(RiskScore)` | Attach the computed risk |
| `.is_allowed()` | Whether the action may proceed without approval |
| `.needs_approval()` | Whether it needs approval first |

`Effect` serializes as snake_case (`allow`, `deny`, `require_approval`),
implements `Display`, and has `.is_allow()`.

## `policy` — the engine and rules

[`PolicyEngine`] evaluates a request against an ordered rule set. Rules are
sorted by priority (descending) and the first match wins; a non-overridable
always-deny floor runs first, and risk escalation runs last. See
[Policy Language](policy-language.md) for the rule semantics.

```rust
use veridion::policy::{PolicyEngine, PolicyRule, RuleEffect, Conditions};
use veridion::risk::RiskEngine;

let rule = PolicyRule {
    name: "allow_reads".to_string(),
    description: None,
    priority: Some(10),
    effect: RuleEffect::Allow,
    conditions: Conditions {
        action: Some("fs.read".to_string()),
        ..Conditions::default()
    },
};

let engine = PolicyEngine::with_rules(
    RuleEffect::Deny,       // default effect when no rule matches
    vec![rule],
    RiskEngine::empty(),
    Some(75),               // approval threshold, or None
)?;

let decision = engine.evaluate(&request);
```

| Method | Returns | Description |
|--------|---------|-------------|
| `PolicyEngine::new(RuleEffect)` | `PolicyEngine` | No user rules, no risk analysis |
| `PolicyEngine::with_rules(default, rules, risk, threshold)` | `Result<_, PolicyError>` | Explicit rules (tests, embedding) |
| `PolicyEngine::from_config(&Config)` | `Result<_, PolicyError>` | Load rule files and risk analyzers from config |
| `engine.reload(&PolicyConfig)` | `Result<(), PolicyError>` | Re-read the policy directory in place |
| `engine.evaluate(&ActionRequest)` | `ActionDecision` | Decide what to do with an action |

`PolicyRule` fields: `name`, `description: Option<String>`,
`priority: Option<u32>`, `effect: RuleEffect`, `conditions: Conditions`.
`RuleEffect` is `Allow | Deny (default) | RequireApproval`.

## `risk` — scoring

The [`RiskEngine`] runs a set of [`RiskAnalyzer`]s and sums their weighted
signals into a [`RiskScore`] on a 0–100 scale.

```rust
use veridion::risk::{RiskEngine, DestructiveCommandAnalyzer};

let engine = RiskEngine::empty()
    .with_analyzer(Box::new(DestructiveCommandAnalyzer));
let score = engine.score(&request);
// score.value: u8, score.level(): RiskLevel, score.signals: Vec<RiskSignal>
```

| Item | Description |
|------|-------------|
| `RiskEngine::empty()` | No analyzers; every action scores zero |
| `RiskEngine::from_config(&RiskConfig)` | Enable the built-ins the config selects |
| `.with_analyzer(Box<dyn RiskAnalyzer>)` | Register another analyzer |
| `.score(&ActionRequest)` | Aggregate all signals into a `RiskScore` |

Built-in analyzers and their signal weights: `DestructiveCommandAnalyzer` (80),
`SecretAnalyzer` (40), `InjectionAnalyzer` (50), `JailbreakAnalyzer` (40). The
`RiskAnalyzer` trait is `name()` plus `analyze(&ActionRequest) -> Vec<RiskSignal>`.

`RiskScore { value: u8, signals: Vec<RiskSignal> }`; `.level()` maps the value to
a `RiskLevel`: `Low` (0–24), `Medium` (25–49), `High` (50–74), `Critical`
(75–100). `RiskSignal { code, weight, detail }`.

These analyzers are string-level heuristics, not a security boundary.

## `approval` — resolving escalations

When a decision is `RequireApproval`, an [`Approver`] decides whether it may
proceed. [`ApprovalWorkflow`] wraps a chosen approver.

| Constructor | Behavior |
|-------------|----------|
| `ApprovalWorkflow::new(Box<dyn Approver>)` | Arbitrary approver |
| `ApprovalWorkflow::auto_deny()` | Refuse (safe headless default) |
| `ApprovalWorkflow::auto_approve()` | Approve (dev only) |
| `ApprovalWorkflow::interactive()` | Prompt on the terminal (stdin) |
| `ApprovalWorkflow::from_config(&ApprovalConfig)` | Choose based on config |

`workflow.resolve(&ActionRequest, &ActionDecision) -> ApprovalOutcome`.
`ApprovalOutcome` is `Approved | Denied` with `.is_approved()`. The `Approver`
trait is a single method:
`approve(&self, &ActionRequest, &ActionDecision) -> ApprovalOutcome`. Built-in
impls: `AutoDeny`, `AutoApprove`, `StdinApprover`.

## `audit` — the log

[`AuditLog`] records one [`AuditRecord`] per authorization. It is backed by an
in-memory buffer or a SQLite database.

```rust
use veridion::audit::{AuditLog, AuditRecord};

let log = AuditLog::memory();
let record = AuditRecord::from_decision(&request, &decision);
log.record(&record).await?;
let recent = log.recent(50).await?; // Vec<AuditRecord>, newest first
```

| Method | Description |
|--------|-------------|
| `AuditLog::memory()` | Ephemeral in-memory log |
| `AuditLog::from_config(&AuditConfig)` (async) | Open SQLite when selected |
| `log.record(&AuditRecord)` (async) | Persist a record |
| `log.recent(limit)` (async) | The most recent records, newest first |

`AuditRecord` fields: `id`, `subject`, `action`, `resource`, `effect`, `reason`,
`risk`, `matched_rule: Option<String>`, `approval: Option<ApprovalOutcome>`.
Build one with `AuditRecord::from_decision(&request, &decision)` and, when an
approval was resolved, `.with_approval(outcome)`.

## `config` — configuration

[`Config`] is normally loaded from a TOML file; every field has a default.

```rust
use veridion::Config;

let config = Config::from_file("veridion.toml")?;  // ConfigError on I/O or parse
let config = Config::default();                     // deny-by-default, SQLite audit
let config = Config::permissive();                  // dev: default-allow, in-memory audit
```

`Config` groups sub-configs: `policy`, `risk`, `audit`, `approval`, `telemetry`.

| Sub-config | Key fields |
|------------|------------|
| `PolicyConfig` | `policy_dir: PathBuf`, `default_effect: DefaultEffect` (Allow/Deny/RequireApproval) |
| `RiskConfig` | `enabled`, `detect_destructive`, `detect_secrets`, `detect_injection`, `approval_threshold: Option<u8>` |
| `AuditConfig` | `backend: AuditBackend` (Sqlite/Memory), `path: PathBuf` |
| `ApprovalConfig` | `default: ApprovalMode` (Deny/Allow/Interactive) |
| `TelemetryConfig` | `enable_tracing: bool`, `log_level: String` |

## `telemetry` — tracing

`Telemetry::new(TelemetryConfig)` installs a `tracing` subscriber when
`enable_tracing` is set, using `log_level` as the `EnvFilter` directive. It
returns `TelemetryError` on an invalid filter or initialization failure.

## Error Types

Each subsystem defines a `thiserror` enum:

| Error | Variants |
|-------|----------|
| `VeridionError` | `Policy`, `Audit` |
| `PolicyError` | `Io`, `Parse`, `InvalidRule` |
| `AuditError` | `Io`, `Database`, `Serialization` |
| `ConfigError` | `Io`, `Parse` |
| `TelemetryError` | `Initialization`, `InvalidConfig` |

`VeridionError` aggregates `PolicyError` and `AuditError` via `#[from]`.

## Next Steps

- [Policy Language](policy-language.md) - Authoring the rules the engine evaluates
- [CLI](cli.md) - The `veridion` binary over this library
- [Architecture](../internals/architecture.md) - How these pieces fit together
