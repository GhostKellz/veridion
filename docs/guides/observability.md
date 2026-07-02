# Observability

Veridion emits structured logs and traces through the `tracing` ecosystem. There is no
metrics server today; metrics export is planned but not yet wired.

## Logging and Tracing

`Telemetry::new(config.telemetry)` installs a `tracing_subscriber` when
`enable_tracing = true`, using `log_level` as the `EnvFilter` directive. Logs are written
to stderr.

```toml
[telemetry]
enable_tracing = true
log_level = "info"    # trace | debug | info | warn | error
```

The `log_level` value is used directly as the `EnvFilter` directive. If it cannot be
parsed, Veridion falls back to `info`.

### Setting the level

You can use standard `EnvFilter` syntax to scope levels per module:

```toml
log_level = "info,veridion=debug"
```

### What gets logged

Tracing output covers the authorization path — decisions, escalations, and failures.
For a durable, queryable record of every authorize, use the [audit log](audit-logging.md);
tracing is for live diagnostics, the audit trail is the system of record.

## Metrics

There is no metrics endpoint at present. If metrics are added, they will be framed around
decisions rather than requests — counts such as authorized, denied, and escalated actions —
so they line up with what the [audit log](audit-logging.md) already records.

Until then, use the [audit log](audit-logging.md) and structured logs for visibility into
what the engine decided and why.

## Next Steps

- [Audit Logging](audit-logging.md) - Persistent per-authorize records
- [Configuration](../getting-started/configuration.md) - Telemetry settings
