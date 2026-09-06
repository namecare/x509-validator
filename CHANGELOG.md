# Changelog

## [0.3.0] - 2026-09-06

### Added
- `EkuPolicy`, a `ValidationPolicy` for the extendedKeyUsage extension
  (RFC 5280 §4.2.1.12). Requires any one of a set of key purposes, with
  `server_auth()` and `client_auth()` shortcuts and the well-known purpose
  OIDs in `eku_oids`. `applies_to(CertificateRole)` narrows the requirement
  to the end entity, the issuers, or the whole chain; `require_extension()`
  rejects certificates that omit the extension instead of treating them as
  unrestricted.
- `CertificateRole`, naming a certificate's position in a chain for policies
  that apply per position.

### Changed
- Examples rewritten as self-contained files starting from DER bytes:
  `webpki`, `apple_x5c`, `client_certificate`, `pinned_root`, `diagnostics`
  and `custom_crypto_backend`, with real captured chains in `examples/mocks`.
- `aws_lc` backend: bumped `aws-lc-rs` to 1.18.1 and `aws-lc-sys` to 0.45.0.

### Internal
- Fuzzing moved to its own workspace under `fuzz/`, with an
  `x509-validator-fuzzing-provider` crate so the fuzzers build without a
  crypto backend. Four targets: `parse_certificate`, `validate_chain`,
  `server_identity`, `name_constraints`.

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
