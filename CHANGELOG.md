# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- `AllOfPolicies` and `OneOfPolicies` are now generic, static wrappers (no heap allocation); compose
  policies with the new `policy!` macro instead of `Vec<Box<dyn ValidationPolicy>>`. `AnyPolicy` is
  unchanged and remains the explicit type-erasure escape hatch.
- `OneOfPolicies` composition now uses the new `one_of!` macro instead of `policy!`'s `if`/`else`
  syntax, and is built on the new `OneOfTuple2`/`OneOfWrappedOptional` combinators rather than `Either`.
  This reproduces the original `Vec`-based version's try-until-success behavior exactly (first
  alternative that succeeds wins, extensions claimed as understood are the *intersection* of every
  alternative's claims, and both failure reasons are joined if every alternative fails) — a fix to
  this same unreleased branch's work, not a new behavioral change relative to what shipped in 0.1.0.

## [0.1.0] - 2026-08-08

### Added
- RFC 5280 chain validation: signature, validity, key usage, basic
  constraints, name constraints, policy constraints.
- Server-identity policy (`ServerIdentityPolicy`) for TLS-style hostname
  verification.
- Policy composition primitives: `AllOfPolicies`, `AnyPolicy`,
  `OneOfPolicies`.
- Pluggable crypto backends: `aws_lc` (aws-lc-rs), `ring`, and
  `rust_crypto` (RustCrypto crates), selected via Cargo feature flags.
- `x509-validator-core`: backend-independent certificate types and
  chain-building primitives, re-exporting `x509-parser`.
- `x509-validator-testkit`: certificate-building test helpers (dev-only).
- Benchmark suite (`x509-validator-bench`): `compare` (cross-backend/parser
  benchmarks via divan) and `measure` (regression tracking via criterion),
  including a real-world Apple receipt-signing chain fixture.
