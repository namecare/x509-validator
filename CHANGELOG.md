# Changelog

## [0.2.0] - 2026-08-12

### Added
- `Validator::validate(leaf, intermediates)`, a diagnostic-free entry point
  for callers that do not need to observe chain building. 

### Changed
- **Breaking:** the callback taken by `validate_with_diagnostics` is now
  `&mut dyn FnMut(VerificationDiagnostic<'a>)` instead of
  `&mut dyn FnMut(VerificationDiagnostic<'_>)`.

### Internal
- Reorganized the `x509-validator-bench` comparison suite into four groups
  (`internals`, `parsers`, `verifiers`, `rust_vs_swift`) with a `run.sh`
  driver. The bench crates are unpublished and do not affect the public API.

## [0.1.0] - 2026-08-11

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
