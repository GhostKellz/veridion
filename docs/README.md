# Veridion Documentation

Policy authorization library for AI agent actions, written in Rust. OPA meets sudo meets AI safety.

## Getting Started

- [Installation](getting-started/installation.md) - From source, as a crate, and the CLI binary
- [Quickstart](getting-started/quickstart.md) - Authorize your first action
- [Configuration](getting-started/configuration.md) - Every config section and environment variable

## Reference

- [Library API](reference/library-api.md) - Using Veridion as a Rust crate
- [Policy Language](reference/policy-language.md) - TOML policy rules and conditions
- [CLI](reference/cli.md) - The stdin/stdout authorization binary

## Guides

- [Writing Policies](guides/writing-policies.md) - Authoring and reloading policy rules
- [Risk Scoring](guides/risk-scoring.md) - Risk analyzers and approval escalation
- [Approvals](guides/approvals.md) - Approval modes and interactive flow
- [Audit Logging](guides/audit-logging.md) - Audit schema and querying events
- [Observability](guides/observability.md) - Structured logging and tracing

## Internals

- [Architecture](internals/architecture.md) - Module map and authorization lifecycle

## Testing

- [Running Tests](testing/running-tests.md) - Unit and integration test workflow

## Security

- [Accepted Advisories](advisories/accepted.md) - Knowingly accepted advisories (currently none)
- [Resolved Advisories](advisories/resolved.md) - Advisories cleared by dependency updates

## Quick Links

Veridion is an in-process library: an agent builds an `ActionRequest`, calls
`veridion.authorize(&request).await`, and receives an `Authorization { decision,
approval, permitted }`. There is no HTTP server, proxy, or listening port.

Configuration is loaded from `veridion.toml` (override with `VERIDION_CONFIG`). When no
config file is found, Veridion falls back to a built-in default that denies by default.
