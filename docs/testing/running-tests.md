# Running Tests

Veridion ships unit tests inside the source modules, an integration test that
exercises the public `Veridion` facade end to end, and doctests on the crate's
examples.

## Run Everything

```bash
cargo test
```

This runs:

- **Unit tests** (in-module) across `action`, `decision`, `policy`, `risk`,
  `audit`, and `engine` — builder behavior, priority ordering and condition
  matching, the always-deny floor, risk scoring and saturation, and the
  facade's permit logic.
- **Integration tests** in `tests/authorization.rs`.
- **Doctests** compiled from the crate's documentation examples.

## The Integration Test

`tests/authorization.rs` drives the public [`Veridion`](../reference/library-api.md)
facade — building a `PolicyEngine` with explicit rules, an `ApprovalWorkflow`,
and an in-memory `AuditLog` — and asserts the full authorization contract:

1. `allowed_action_proceeds_and_is_audited` — a matched `allow` rule permits the
   action and writes exactly one audit record.
2. `default_deny_blocks_unmatched_action` — an unmatched action falls through to
   deny-by-default with no matched rule.
3. `always_deny_floor_cannot_be_overridden` — the catastrophic-command floor
   denies `rm -rf /` even under an `allow`-all rule and an auto-approve workflow.
4. `high_risk_allow_escalates_to_approval` — a high-risk `allow` is escalated to
   `require_approval`, then permitted or refused according to the approver.
5. `pure_evaluate_has_no_side_effects` — `evaluate` returns a decision without
   writing to the audit log.

These build `Veridion` from parts with `Veridion::new` and `AuditLog::memory()`
— a good template for further authorization tests.

## The Example

A runnable end-to-end example wires Veridion into a sketch of an agent runtime:

```bash
cargo run --example jarvis_integration
```

It authorizes a queue of actions (read, safe shell, repo write, a floor-blocked
`rm -rf /`, and a remote command needing approval) and prints each verdict plus
the resulting audit trail.

## Useful Invocations

```bash
# A single test by name
cargo test always_deny_floor_cannot_be_overridden

# Only library unit tests
cargo test --lib

# Only the integration test binary
cargo test --test authorization

# Show captured stdout/logs
cargo test -- --nocapture
```

## Quality Gates

Run the same checks CI does before opening a PR:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit
```

`cargo audit` should report zero vulnerabilities.

## Next Steps

- [Architecture](../internals/architecture.md) - The lifecycle the integration test covers
- [Library API](../reference/library-api.md) - Building a `Veridion` for custom tests
