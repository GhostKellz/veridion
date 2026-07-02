# Resolved Advisories

Advisories that once affected Veridion's dependency tree and have since been cleared.
`cargo audit` currently reports zero vulnerabilities across 281 dependencies.

## Cleared by dependency updates

Most were resolved by a `cargo update` that floated transitive crates to patched
versions; the `sqlx` advisory required a minor-version bump in `Cargo.toml`.

| Advisory ID | Crate | Issue | Resolved by | Date |
|-------------|-------|-------|-------------|------|
| RUSTSEC-2026-0007 | bytes | Integer overflow in `BytesMut::reserve` | `cargo update` → `bytes` ≥ 1.11.1 | 2026-07-02 |
| RUSTSEC-2026-0037 | quinn-proto | Denial of service in Quinn endpoints | `cargo update` → `quinn-proto` ≥ 0.11.15 | 2026-07-02 |
| RUSTSEC-2026-0185 | quinn-proto | Memory exhaustion from out-of-order stream reassembly | `cargo update` → `quinn-proto` ≥ 0.11.15 | 2026-07-02 |
| RUSTSEC-2026-0049 | rustls-webpki | CRLs not treated as authoritative | `cargo update` → `rustls-webpki` ≥ 0.103.13 | 2026-07-02 |
| RUSTSEC-2026-0098 | rustls-webpki | URI name constraints incorrectly accepted | `cargo update` → `rustls-webpki` ≥ 0.103.13 | 2026-07-02 |
| RUSTSEC-2026-0099 | rustls-webpki | Wildcard name constraints accepted | `cargo update` → `rustls-webpki` ≥ 0.103.13 | 2026-07-02 |
| RUSTSEC-2026-0104 | rustls-webpki | Reachable panic in CRL parsing | `cargo update` → `rustls-webpki` ≥ 0.103.13 | 2026-07-02 |
| RUSTSEC-2024-0363 | sqlx | Binary protocol misinterpretation via truncating casts | Bumped `sqlx` 0.7 → 0.8 in `Cargo.toml` | 2026-07-02 |

## Warnings cleared

| Advisory ID | Crate | Warning | Resolved by | Date |
|-------------|-------|---------|-------------|------|
| RUSTSEC-2026-0097 | rand | Unsound with a custom logger using `rand::rng()` | `cargo update` (transitive via `reqwest`/`quinn`) | 2026-07-02 |
| RUSTSEC-2024-0436 | paste | Crate unmaintained | Dropped from the tree by `sqlx` 0.8 | 2026-07-02 |
| RUSTSEC-2025-0052 | async-std | Crate discontinued | Dropped from the tree by `httpmock` 0.8 (dev-dependency) | 2026-07-02 |

## Notes

- **rustls-webpki**: `reqwest` uses `rustls-tls`, so four CRL/name-constraint advisories
  landed at once through the TLS stack. A single `cargo update` pulled `rustls-webpki`
  past all four fixed versions (≥ 0.103.13).
- **sqlx 0.7 → 0.8**: the only change requiring a manifest edit. Veridion's storage layer
  uses `SqlitePool`, `SqliteConnectOptions`, and the `query`/`bind`/`fetch` APIs, which
  are source-compatible across the bump — the build and full test suite pass unchanged.
  Upgrading also removed the unmaintained `paste` crate.
- **async-std**: only reached the tree through the `httpmock` dev-dependency, so it never
  shipped in the binary; bumping `httpmock` to 0.8 removed it.

Verification: `cargo audit` reports zero vulnerabilities, and `cargo test` passes (2 unit
tests + 1 integration test).
