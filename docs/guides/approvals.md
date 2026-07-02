# Approvals

When a decision resolves to `require_approval` — either from a rule or from
[risk escalation](risk-scoring.md) — `authorize` consults the approval workflow to get a
final answer. `evaluate` never involves approval; it returns the raw `ActionDecision`
without side effects.

## The Workflow

`ApprovalWorkflow` wraps an `Approver`. `authorize` only calls it when the decision effect
is `require_approval`; `allow` and `deny` pass through unchanged. The built-in constructors
cover the common cases:

| Constructor | Behavior |
|-------------|----------|
| `ApprovalWorkflow::auto_deny()` | Refuses everything — the safe headless default |
| `ApprovalWorkflow::auto_approve()` | Approves everything — dev only, dangerous |
| `ApprovalWorkflow::interactive()` | `StdinApprover` prompts on the terminal (`approve? [y/N]`) |

Wire it from config with `ApprovalWorkflow::from_config(&config.approval)`:

```toml
[approval]
default = "deny"    # deny | allow | interactive
```

## The Approver Trait

An `Approver` decides a single escalated request:

```rust
pub trait Approver {
    fn approve(&self, request: &ActionRequest, decision: &ActionDecision) -> ApprovalOutcome;
}
```

`ApprovalOutcome` is `Approved` or `Denied`.

## Reading the Result

`authorize` returns an `Authorization`:

```rust
pub struct Authorization {
    pub decision: ActionDecision,
    pub approval: Option<ApprovalOutcome>,
    pub permitted: bool,
}
```

`permitted` collapses the decision and approval into a single go/no-go:

| Decision effect | `permitted` |
|-----------------|-------------|
| `allow` | `true` |
| `deny` | `false` |
| `require_approval` | equals the approval outcome (`Approved` → `true`) |

`approval` is populated only for `require_approval` decisions; it is `None` otherwise.

```rust
let auth = veridion.authorize(&request).await?;
if auth.permitted {
    // proceed with the action
}
```

## Custom Approvers

Embedders can route approvals anywhere — Slack, a ticket system, a web console — by
implementing `Approver`:

```rust
struct SlackApprover {
    client: SlackClient,
}

impl Approver for SlackApprover {
    fn approve(&self, request: &ActionRequest, decision: &ActionDecision) -> ApprovalOutcome {
        let text = format!(
            "{} wants to {} on {} (risk {})",
            request.subject.id, request.action, request.resource, decision.risk.value,
        );
        if self.client.ask_and_wait(&text) {
            ApprovalOutcome::Approved
        } else {
            ApprovalOutcome::Denied
        }
    }
}

let workflow = ApprovalWorkflow::new(Box::new(SlackApprover { client }));
```

The request and the full decision — including the matched rule and risk score — are both
available, so an approver can show reviewers exactly why the action was escalated.

## Next Steps

- [Writing Policies](writing-policies.md) - Emit `require_approval` from a rule
- [Risk Scoring](risk-scoring.md) - The other source of escalation
- [Audit Logging](audit-logging.md) - The approval outcome is recorded on every authorize
