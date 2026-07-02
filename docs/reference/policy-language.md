# Policy Language

Policies are TOML files in the configured `policy_dir`. Every `*.toml` file is
loaded, each `[[policy]]` entry is compiled, and the combined rule set is sorted
by priority (highest first, then by name). The first rule whose conditions all
match wins; if none match, the configured `default_effect` applies.

Veridion authorizes *actions*, not HTTP traffic. A rule matches on the action
verb, the target resource, the subject and its roles, arbitrary context
attributes, and the computed risk score — attribute-based access control (ABAC)
in the spirit of OPA, with sudo-style allow/deny/ask effects.

## Rule Structure

```toml
[[policy]]
name = "policy_identifier"           # required, unique label
description = "human-readable note"   # optional
priority = 100                        # optional, higher evaluated first (default 0)
effect = "deny"                       # allow | deny | require_approval (default deny)

[policy.conditions]
# all present conditions must match (logical AND)
```

`effect` defaults to `deny` when omitted, matching Veridion's deny-by-default
posture.

## Conditions

All specified conditions must match for the rule to fire. Omitted conditions are
ignored.

| Condition | Type | Semantics |
|-----------|------|-----------|
| `action` | string | Exact action verb, e.g. `exec` |
| `action_glob` | string | Glob over the verb, e.g. `fs.*` |
| `resource` | string | Exact resource string |
| `resource_glob` | string | Glob over the resource, e.g. `/etc/**` |
| `resource_regex` | string[] | **All** regexes must match the resource |
| `subject` | string | Exact subject id |
| `subject_roles` | string[] | Subject must hold **all** listed roles |
| `attributes` | table | Per-attribute condition, see below |
| `min_risk` | int | Rule applies only when risk ≥ this value (0–100) |
| `max_risk` | int | Rule applies only when risk ≤ this value (0–100) |

### Attribute Conditions

Each entry in `[policy.conditions.attributes]` maps an attribute name to a tagged
condition with a `type` and, for most types, a `value`. A scalar attribute
matches by its string form; a list attribute matches by membership.

```toml
# attribute must be present (any value)
[policy.conditions.attributes.repo]
type = "exists"

# attribute must equal a specific value
[policy.conditions.attributes.repo]
type = "equals"
value = "veridion"

# attribute's scalar form must match a regex
[policy.conditions.attributes.branch]
type = "regex"
value = "^release/"

# attribute must equal (or, for a list, contain) one of these values
[policy.conditions.attributes.env]
type = "one_of"
value = ["staging", "prod"]
```

The four types are `exists`, `equals`, `regex`, and `one_of`.

### Risk Range

```toml
[policy.conditions]
min_risk = 50
max_risk = 74
```

`min_risk` and `max_risk` are inclusive bounds on the request's aggregate risk
score. Either may be omitted. The risk score is computed before rules are
evaluated (see [Library API](library-api.md#risk--scoring) for the analyzers and
weights).

## Evaluation Order

1. **Risk is scored** for the request.
2. **The always-deny floor** runs first — a fixed set of catastrophic patterns
   that no rule can override (see below).
3. **User rules** are evaluated in priority order (descending, then by name).
   The first rule whose conditions all match returns its `effect`.
4. **Default effect** applies when no rule matches.
5. **Risk escalation** runs last: an `allow` is upgraded to `require_approval`
   when the risk score is at or above the configured `approval_threshold`.

Because higher priority wins, a narrow high-priority `deny` overrides a broad
low-priority `allow`.

## The Always-Deny Floor

Before any user rule is considered, the resource is checked against a
non-overridable set of catastrophic-command patterns. A match denies the action
outright, regardless of rule effects or approval — the floor beats even risk
escalation and an `allow`-all rule. These rules carry priority `u32::MAX` and
cannot be disabled:

| Rule | Blocks |
|------|--------|
| `floor_rm_root` | recursive delete rooted at `/` |
| `floor_rm_home` | recursive delete of the home directory |
| `floor_mkfs` | filesystem formatting |
| `floor_raw_disk_write` | raw writes to a block device (`of=/dev/sd…`) |
| `floor_fork_bomb` | shell fork bombs |

The floor is a heuristic backstop, not a security boundary.

## Examples

### Deny `git push` by resource regex (high priority)

```toml
[[policy]]
name = "deny_git_push"
description = "block pushes; agents open PRs instead"
priority = 100
effect = "deny"

[policy.conditions]
resource_regex = ["\\bgit\\s+push\\b"]
```

### Allow all reads by action

```toml
[[policy]]
name = "allow_reads"
priority = 10
effect = "allow"

[policy.conditions]
action = "fs.read"
```

### Require approval for remote execution

```toml
[[policy]]
name = "approve_remote"
description = "remote execution always needs a human"
priority = 20
effect = "require_approval"

[policy.conditions]
action = "net.remote"
```

### Allow a trusted role inside a specific repo

```toml
[[policy]]
name = "allow_trusted_in_repo"
priority = 50
effect = "allow"

[policy.conditions]
action = "fs.write"
subject_roles = ["trusted"]

[policy.conditions.attributes.repo]
type = "equals"
value = "veridion"
```

### Gate high-risk actions on approval

```toml
[[policy]]
name = "approve_high_risk_exec"
description = "escalate risky shell commands to a human"
priority = 80
effect = "require_approval"

[policy.conditions]
action = "exec"
min_risk = 50
```

## Errors

Loading fails fast with a clear message when a rule contains an invalid
`action_glob`, `resource_glob`, `resource_regex`, or attribute `regex` pattern,
or when a policy file cannot be parsed as TOML. Errors surface as `PolicyError`.

## Next Steps

- [Writing Policies](../guides/writing-policies.md) - Workflow and reloading
- [Library API](library-api.md) - Evaluating rules programmatically
- [CLI](cli.md) - How decisions surface on the command line
