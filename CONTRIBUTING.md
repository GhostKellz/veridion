# Contributing to Veridion

Thanks for your interest in improving Veridion. This guide covers local setup, the
checks we expect before a pull request, and our code and documentation conventions.

## Prerequisites

- Rust 1.96+ (edition 2024) via [rustup](https://rustup.rs/)
- `cargo-audit` for dependency checks: `cargo install cargo-audit`

## Local Setup

```bash
git clone https://github.com/ghostkellz/veridion.git
cd veridion

cargo build
cargo test
```

To run the firewall locally, create a `veridion.toml` (see
[docs/getting-started/configuration.md](docs/getting-started/configuration.md)) and:

```bash
VERIDION_CONFIG=./veridion.toml cargo run
```

## Before You Open a PR

Run the same gates CI enforces, and make sure each passes:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo audit
```

- **Formatting** — code is formatted with `cargo fmt`; do not hand-format.
- **Lints** — clippy runs with warnings denied. Fix warnings rather than suppressing
  them, unless there is a clear, commented justification.
- **Tests** — add or update tests for behavior changes. The pipeline test in
  `tests/proxy.rs` is a good template for end-to-end coverage.
- **Audit** — `cargo audit` must report zero vulnerabilities. If a fix requires a
  dependency bump, include it and note it in
  [docs/advisories/resolved.md](docs/advisories/resolved.md).

## Project Layout

| Path | Purpose |
|------|---------|
| `src/config.rs` | Typed configuration and TOML loading |
| `src/firewall.rs` | Orchestrator wiring subsystems together |
| `src/server.rs` | Axum router and request handlers |
| `src/policy.rs` | Policy loading, compilation, evaluation |
| `src/filters.rs` | Input/output filter engine |
| `src/upstream.rs` | Upstream provider client |
| `src/storage.rs` | SQLite audit persistence |
| `src/telemetry.rs` | Tracing initialization |
| `tests/` | Integration tests |
| `docs/` | Documentation (see [docs/README.md](docs/README.md)) |

See [docs/internals/architecture.md](docs/internals/architecture.md) for the module map
and request lifecycle.

## Coding Conventions

- Keep changes focused — the smallest change that solves the problem.
- Prefer clear names; no `v2`/`_new` suffixes.
- Comments explain **why**, not **what**. Avoid static version numbers in comments.
- Return typed `thiserror` errors from subsystems; avoid `unwrap()` outside tests.
- Match the existing module structure rather than introducing new abstractions for
  one-off needs.

## Documentation Conventions

Documentation lives under `docs/` in topic folders with lowercase, kebab-case filenames
(e.g. `getting-started/quickstart.md`). Follow the existing pattern:

- One `H1` title, a short intro, then `H2` sections.
- Describe **actual** behavior. Mark unbuilt features as planned or reserved rather than
  documenting them as working.
- Cross-link related docs with relative paths.
- Update `docs/README.md` when adding a new page.

## Commit and PR Guidelines

- Write imperative, descriptive commit subjects (e.g. "Add token-count policy condition").
- Explain the "why" in the body when it isn't obvious.
- Keep PRs scoped to a single concern; note any follow-ups explicitly.
- Ensure the four gates above pass before requesting review.

## Reporting Security Issues

Do not file security problems as public issues — follow [SECURITY.md](SECURITY.md).
