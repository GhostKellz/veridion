# Quickstart

Veridion authorizes AI agent actions in-process. An agent builds an `ActionRequest`,
calls `veridion.authorize(&request).await`, and branches on the result. Every decision
runs through the policy engine, risk analyzers, an always-deny floor, and the audit log.

## Prerequisites

- Rust 1.96+ (edition 2024)

## 1. Add the Dependency

```toml
[dependencies]
veridion = { path = "." }   # or a version once published
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## 2. Build a Veridion Instance

`Config::default()` denies by default, audits to sqlite, and enables risk analysis.

```rust
use veridion::{Config, Veridion};

let veridion = Veridion::from_config(&Config::default()).await?;
```

To load a config file instead, use `Config::from_file("veridion.toml")`. For
development, `Config::permissive()` allows by default and audits in memory.

## 3. Construct an ActionRequest

An `ActionRequest` names an action verb, a resource, the subject taking the action, and
optional attributes.

```rust
use veridion::action::{ActionRequest, Subject, actions};

let request = ActionRequest::new(actions::EXEC, "rm -rf /tmp/cache")
    .subject(Subject::new("jarvis").with_role("agent"))
    .attr("repo", "veridion");
```

Action verb constants: `exec`, `fs.read`, `fs.write`, `fs.edit`, `agent.delegate`,
`net.remote`, `memory.remember`.

## 4. Authorize and Branch

```rust
let auth = veridion.authorize(&request).await?;
if auth.permitted {
    // run the command
}
```

`Authorization` carries `decision`, `approval`, and the resolved `permitted` boolean.
For a pure decision with no side effects (no audit write), use
`veridion.evaluate(&request)`, which returns an `ActionDecision`.

## 5. See the Decisions

With the deny-by-default `Config::default()` and no policy rules, three representative
requests resolve like this:

- An `fs.read` on a project file: **denied** — nothing has allowed it yet.
- Any action with no matching rule: **denied** — deny is the default effect.
- `exec` of `rm -rf /`: **denied by the always-deny floor**, which is non-overridable
  even if a policy would otherwise allow it.

The floor also blocks `rm -rf ~`, `mkfs`, raw disk writes, and fork bombs.

## 6. Add a Policy Rule File

Point `policy_dir` at a directory of `*.toml` rule files (`policies` by default) and
create `policies/example.toml`:

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
repo = { type = "equals", value = "veridion" }
```

Now an `fs.write` by a subject with the `agent` role and a `repo=veridion` attribute
matches this rule and is **allowed**. A request that does not match still falls through
to the deny default.

Risk escalation can upgrade an `allow` to `require_approval` when a request's risk score
crosses `approval_threshold`. See [Writing Policies](../guides/writing-policies.md) and
the [Policy Language](../reference/policy-language.md) reference.

## 7. Alternative: the CLI

The `veridion` binary reads an `ActionRequest` JSON on stdin and prints an
`Authorization` JSON on stdout. It exits `0` if permitted, `1` if not, `2` on error.

```bash
echo '{"action":"exec","resource":"ls -la","subject":{"id":"jarvis","roles":["agent"]}}' | veridion
```

The config path comes from `VERIDION_CONFIG`; the built-in defaults apply if it is unset.

## Next Steps

- [Library API](../reference/library-api.md) - Full type and method surface
- [Risk Scoring](../guides/risk-scoring.md) - What the analyzers detect and how escalation works
- [Audit Logging](../guides/audit-logging.md) - Inspect recorded decisions
