# Writing Policies

Policies decide whether an agent action is allowed, denied, or escalated for approval.
Given an `ActionRequest`, the [policy engine](../reference/library-api.md) evaluates your rules
and returns an `ActionDecision`. This guide covers the authoring workflow; see the
[Policy Language](../reference/policy-language.md) reference for the full condition set.

## Where Policies Live

Policy files are TOML files in `policy_dir` (default `./policies`). A relative path is
resolved against the directory of your config file. Every `*.toml` file in that directory
is loaded; non-TOML files are ignored.

```
policies/
├── default.toml
├── filesystem.toml
└── network.toml
```

Splitting rules across files is purely organizational — all `[[policy]]` entries are
merged into a single, priority-sorted rule set.

## Rule Shape

Each rule is a `[[policy]]` entry with a top-level identity, an `effect`, and a
`[policy.conditions]` block:

```toml
[[policy]]
name = "deny_git_push"
description = "pushes need review"
priority = 100                  # higher = evaluated first (default 0)
effect = "deny"                 # allow | deny | require_approval (default deny)

[policy.conditions]
action = "exec"                 # exact action verb
resource_regex = ["git\\s+push"]
```

Actions are addressed by verb. The built-in verbs are `exec`, `fs.read`, `fs.write`,
`fs.edit`, `agent.delegate`, `net.remote`, and `memory.remember`. Conditions may match the
verb exactly (`action`) or by glob (`action_glob = "fs.*"`), and match the resource by
exact string (`resource`), glob (`resource_glob`), or regex (`resource_regex`, where **all**
listed patterns must match).

An empty `[policy.conditions]` block matches everything — useful for a catch-all.

## Evaluation Model

Veridion is OPA-style policy plus a sudo-style approval gate. A request flows through
three stages:

1. **Always-deny floor.** Before any rule runs, a non-overridable floor blocks
   catastrophic patterns — `floor_rm_root` (`rm -rf /`), `floor_rm_home` (`rm -rf ~`),
   `floor_mkfs`, `floor_raw_disk_write` (`of=/dev/sd|nvme|disk|hd`), and `floor_fork_bomb`.
   No rule can allow these.
2. **Your rules.** Rules are sorted by `priority` descending and the **first match wins**.
   If no rule matches, the `default_effect` (default `deny`) applies.
3. **Risk escalation.** When the resulting effect is `allow` but the request's
   [risk score](risk-scoring.md) is at or above `approval_threshold`, the decision is
   upgraded to `require_approval`.

## Deny-by-Default Workflow

With `default_effect = "deny"`, nothing runs until a rule allows it. A typical starting
point:

```toml
# policies/default.toml

[[policy]]
name = "deny_push"
description = "Pushes always go through review"
priority = 100
effect = "require_approval"

[policy.conditions]
action = "exec"
resource_regex = ["git\\s+push"]

[[policy]]
name = "allow_reads"
description = "Reading files is fine"
priority = 10
effect = "allow"

[policy.conditions]
action = "fs.read"
```

Because `deny_push` has the higher priority, it is evaluated before `allow_reads`.

## Priorities

Rules are sorted by `priority` descending and the first match wins. Use priority bands to
keep intent clear:

| Band | Use |
|------|-----|
| 90-100 | Hard denies and mandatory approvals |
| 40-70 | Scoped grants and soft limits |
| 1-30 | Broad allows |

## Combining Conditions

Within one rule, every condition must match (logical AND). Conditions can narrow on the
subject, the subject's roles, the risk band, and request context attributes:

```toml
[[policy]]
name = "allow_trusted_writes_low_risk"
priority = 50
effect = "allow"

[policy.conditions]
action_glob = "fs.*"
subject_roles = ["trusted"]     # subject must hold ALL listed roles
max_risk = 24                   # only when risk is Low

[policy.conditions.attributes]
repo = { type = "equals", value = "veridion" }
env  = { type = "one_of", value = ["dev", "staging"] }
```

Attribute conditions take a `type` of `exists`, `equals`, `regex`, or `one_of`. The
`min_risk` / `max_risk` bounds let a rule apply only within a [risk band](risk-scoring.md).

To express OR, write separate rules:

```toml
[[policy]]
name = "allow_role_admin"
priority = 20
effect = "allow"
[policy.conditions]
subject_roles = ["admin"]

[[policy]]
name = "allow_role_service"
priority = 20
effect = "allow"
[policy.conditions]
subject_roles = ["service"]
```

## Escalating to Approval

A rule can require a human in the loop directly with `effect = "require_approval"`, or the
engine can escalate an `allow` automatically when risk crosses `approval_threshold`. Either
way, the decision is resolved by the [approval workflow](approvals.md) during `authorize`.

## Loading and Reloading

`PolicyEngine::from_config(&config)` reads `policy_dir` at startup. `reload(&PolicyConfig)`
re-reads the directory into the running engine without a restart. For embedding and tests,
construct an engine directly:

```rust
let engine = PolicyEngine::with_rules(default_effect, rules, risk_engine, approval_threshold);
```

## Validation

Invalid patterns fail loudly at load time — a bad glob or regex produces a
`PolicyError::InvalidRule` naming the offending rule, and a malformed TOML file produces a
parse error. Fix the reported rule and reload.

## Next Steps

- [Policy Language](../reference/policy-language.md) - Every condition and its semantics
- [Risk Scoring](risk-scoring.md) - How the risk score that drives escalation is computed
- [Approvals](approvals.md) - Resolving `require_approval` decisions
