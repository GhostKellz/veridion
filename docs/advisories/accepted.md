# Accepted Advisories

This file tracks advisories that Veridion knowingly accepts — cases where a reported
issue does not apply to how a dependency is used, or where no fixed version is yet
available and the risk is understood.

**Currently: none.** `cargo audit` reports zero vulnerabilities and zero warnings.

When an advisory must be accepted rather than fixed, record it here with:

| Advisory ID | Crate | Reason for acceptance | Reviewed |
|-------------|-------|-----------------------|----------|
| — | — | — | — |

Acceptances are configured in `audit.toml` (`[advisories] ignore = [...]`) with a matching
justification entry in this file, and are re-reviewed whenever dependencies change.
