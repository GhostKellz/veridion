# Audit Logging

Every call to `authorize` writes one audit record describing the request and how it was
resolved. `evaluate` does **not** audit — it is the pure, side-effect-free path. See the
[engine](../reference/library-api.md) for where auditing sits in the authorize flow.

## The Record

Each authorize produces an `AuditRecord`:

```rust
pub struct AuditRecord {
    pub id: String,
    pub subject: String,
    pub action: String,
    pub resource: String,
    pub effect: Effect,
    pub reason: String,
    pub risk: RiskScore,
    pub matched_rule: Option<String>,
    pub approval: Option<ApprovalOutcome>,
}
```

`action` holds the verb — values like `exec` or `fs.write`. `matched_rule` names the rule
that decided the request, if any, and `approval` carries the outcome for
`require_approval` decisions (see [Approvals](approvals.md)).

## Backends

Select a backend under `[audit]`:

```toml
[audit]
backend = "sqlite"    # sqlite | memory
path = "./data/veridion.db"
```

- `AuditLog::memory()` — an ephemeral in-memory log, handy for tests.
- `AuditLog::from_config(&config.audit)` — builds the configured backend; SQLite persists
  to `path`.

## SQLite Schema

The SQLite backend stores each record in a single table:

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    id      TEXT PRIMARY KEY,
    subject TEXT,
    action  TEXT,
    effect  TEXT,
    risk    INTEGER,
    payload TEXT       -- full AuditRecord as JSON
);
```

The indexed columns support quick filtering; `payload` holds the complete record as JSON so
nothing is lost. Records are returned in insertion order (by rowid).

## Querying

### From the library

`recent(limit)` returns the most recent records, newest last:

```rust
let auth = veridion.authorize(&request).await?;
for record in veridion.audit().recent(20).await? {
    println!("{} {} on {} -> {}", record.id, record.action, record.resource, record.effect);
}
```

### With sqlite3

```bash
sqlite3 ./data/veridion.db \
  "SELECT id, subject, action, effect, risk FROM audit_log ORDER BY rowid DESC LIMIT 20;"
```

### Find escalated or denied actions

```bash
sqlite3 ./data/veridion.db \
  "SELECT id, subject, action FROM audit_log
   WHERE effect IN ('deny', 'require_approval') ORDER BY rowid DESC;"
```

## Next Steps

- [Observability](observability.md) - Logs and tracing alongside the audit trail
- [Approvals](approvals.md) - The approval outcome recorded on each record
- [Configuration](../getting-started/configuration.md) - Audit settings
