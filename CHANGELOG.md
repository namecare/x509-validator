# Changelog

## [0.1.0] - 2026-08-12

### Added
- RFC 5280 chain validation: signature, validity, key usage, basic
  constraints, name constraints, policy constraints.
- Server-identity policy (`ServerIdentityPolicy`) for TLS-style hostname
  verification.
- Policy composition primitives: `AllOfPolicies`, `AnyPolicy`,
  `OneOfPolicies`.
- Pluggable crypto backends: `aws_lc` (aws-lc-rs), `ring`, and
  `rust_crypto` (RustCrypto crates), selected via Cargo feature flags.
- Backend-independent certificate types and chain-building primitives,
  re-exporting `x509-parser`.
- `x509-validator-testkit`: certificate-building test helpers (dev-only).
- Benchmark suite (`x509-validator-bench`): `compare` (cross-backend/parser
  benchmarks via divan) and `measure` (regression tracking via criterion),
  including a real-world Apple receipt-signing chain fixture.
