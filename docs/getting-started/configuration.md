# Configuration

Veridion loads a single TOML file, resolved from `VERIDION_CONFIG` (default
`veridion.toml`). Every section has defaults, so a minimal file only needs to override
what you care about. Relative `policy_dir` paths are resolved against the config file's
directory.

If `VERIDION_CONFIG` is unset, or the file cannot be read, Veridion falls back to
built-in defaults — a deny-by-default configuration with sqlite audit and risk analysis
enabled.

## Loaders

| Loader | Effect |
|--------|--------|
| `Config::from_file(path)` | Load and parse the TOML file at `path` |
| `Config::default()` | Deny-by-default, sqlite audit, risk analysis on |
| `Config::permissive()` | Default-allow, in-memory audit — development only |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VERIDION_CONFIG` | Path to the TOML config file | built-in defaults if unset |

## `[policy]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `policy_dir` | path | `"policies"` | Directory of `*.toml` rule files |
| `default_effect` | enum | `"deny"` | Effect when no rule matches: `allow`, `deny`, or `require_approval` |

Only files ending in `.toml` are read. `default_effect = "deny"` means requests are
rejected until a rule allows them. See [Policy Language](../reference/policy-language.md).

## `[risk]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Master switch for risk analysis |
| `detect_destructive` | bool | `true` | Score destructive operations (e.g. recursive deletes) |
| `detect_secrets` | bool | `true` | Score requests that touch secrets |
| `detect_injection` | bool | `true` | Score prompt-injection indicators |
| `approval_threshold` | u8? | *(unset)* | Risk score at which an `allow` is escalated to `require_approval`; omit to disable escalation |

When a request's risk score reaches `approval_threshold`, an otherwise-`allow` decision
is upgraded to `require_approval`. See [Risk Scoring](../guides/risk-scoring.md).

## `[audit]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `backend` | enum | `"sqlite"` | `sqlite` (durable) or `memory` (in-process, non-persistent) |
| `path` | path | `"veridion-audit.db"` | SQLite database file; used when `backend = "sqlite"` |

`memory` keeps audit events in-process only and is intended for tests and development.
See [Audit Logging](../guides/audit-logging.md).

## `[approval]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `default` | enum | `"deny"` | How `require_approval` decisions resolve: `deny`, `allow`, or `interactive` |

`deny` rejects pending approvals, `allow` grants them, and `interactive` prompts for a
decision. See [Approvals](../guides/approvals.md).

## `[telemetry]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_tracing` | bool | `true` | Initialize the `tracing` subscriber |
| `log_level` | string | `"info"` | `EnvFilter` directive, e.g. `"info"` or `"veridion=debug"` |

See [Observability](../guides/observability.md).

## Full Example

```toml
[policy]
policy_dir = "policies"         # directory of *.toml rule files
default_effect = "deny"         # allow | deny | require_approval

[risk]
enabled = true
detect_destructive = true
detect_secrets = true
detect_injection = true
approval_threshold = 75         # optional; omit to disable risk escalation

[audit]
backend = "sqlite"              # sqlite | memory
path = "veridion-audit.db"

[approval]
default = "deny"                # deny | allow | interactive

[telemetry]
enable_tracing = true
log_level = "info"              # EnvFilter directive, e.g. "info" or "veridion=debug"
```
