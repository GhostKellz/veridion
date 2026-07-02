# Security Policy

Veridion is a security tool, so we take issues in its own code and dependencies
seriously. This document explains how to report a vulnerability and what to expect.

## Supported Versions

Veridion is pre-1.0 and under active development. Security fixes are applied to the
`main` branch and the latest tagged release only.

| Version | Supported |
|---------|-----------|
| `main` | Yes |
| latest `0.x` tag | Yes |
| older `0.x` tags | No |

## Reporting a Vulnerability

**Do not open a public issue for security problems.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/ghostkellz/veridion/security/advisories/new)
("Report a vulnerability"). Include:

- A description of the issue and its impact
- Steps to reproduce or a proof of concept
- Affected version, commit, or configuration
- Any suggested remediation

### What to expect

- **Acknowledgement** within 48 hours of your report.
- **Assessment** with a severity classification and initial remediation plan.
- **Coordinated disclosure** — we will agree on a disclosure timeline with you and credit
  you in the advisory unless you prefer to remain anonymous.

## Scope

In scope:

- The `veridion` crate and binary (proxy, policy engine, filters, storage, upstream)
- Bypasses of the policy engine or input/output filters
- Audit-log integrity issues
- Vulnerable or malicious dependencies in `Cargo.lock`

Out of scope:

- Weaknesses in third-party upstream LLM providers
- Misconfigurations in a deployer's own environment
- The intentionally simple, heuristic nature of the current filter detectors (see
  [docs/guides/filtering.md](docs/guides/filtering.md)) — hardening these is tracked as
  ordinary feature work, not a vulnerability

## Dependency Hygiene

We track advisories with [`cargo audit`](https://github.com/rustsec/rustsec):

```bash
cargo install cargo-audit
cargo audit
```

`cargo audit` is expected to report zero vulnerabilities. Resolved advisories are logged
in [docs/advisories/resolved.md](docs/advisories/resolved.md); any knowingly accepted
advisories are documented in [docs/advisories/accepted.md](docs/advisories/accepted.md).

## Hardening Notes

- Veridion defaults to `default_policy = "deny"` — a deny-by-default posture.
- The upstream API key is read from an environment variable, never stored in the config
  file.
- Do not expose the proxy directly to untrusted networks without an authenticating
  reverse proxy in front of it.
