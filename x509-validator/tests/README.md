# Tests

## Layout

Unit tests live in `#[cfg(test)] mod tests` blocks beside the code they
exercise. Integration tests live here, in files named after the upstream
suite they were ported from.

A test belongs in `src/` when it needs a fake — a stub crypto provider or
digest — or when it reaches a private item. It belongs here when it drives
the public API. Certificate-building helpers for both come from the
`x509-validator-testkit` crate, which is a dev-dependency only and never
enters the shipped dependency graph.

Run everything with:

    cargo test --workspace --all-features

`--all-features` matters: tests behind an optional backend feature compile
to zero tests without it and pass silently.

## Integration tests (98)

| File | Upstream suite | Tests |
|---|---|---:|
| `server_identity_policy.rs` | `ServerIdentityPolicyTests` | 48 |
| `rfc5280_policy.rs` | `RFC5280PolicyTests` | 41 |
| `certificate_store.rs` | `CertificateStore` | 4 |
| `certificate_display.rs` | *(ours — no upstream counterpart)* | 4 |
| `policy_composition.rs` | `PolicyBuilderTests` | 1 |

`rfc5280_policy.rs` keeps the two-module split it had in `src/`: `tests`
covers composition wiring, `conformance` drives each rule from both the
composed policy and its owning sub-policy.

## Unit tests in `src/` (110)

| Module | Upstream suite | Tests | Why not an integration test |
|---|---|---:|---|
| `verifier.rs` | `VerifierTests` | 23 | Injects a fake crypto provider to control issuer ranking |
| `diagnostic.rs` | *(ours)* | 17 | Constructs 12 private diagnostic types |
| `rfc5280/uri_constraints.rs` | *(ours)* | 14 | Private URI matching |
| `rfc5280/dns_names.rs` | `DNSNamesTests` | 14 | Private `dns_name_matches_constraint`, `ReverseDnsLabels` |
| `rfc5280/name_constraints_policy.rs` | `NameConstraintsTests` | 8 | Sub-policy internals |
| `rfc5280/ip_constraints.rs` | `IPAddressTests` | 8 | Private IP/subnet matching |
| `rfc5280/basic_constraints_policy.rs` | *(ours)* | 8 | Sub-policy internals |
| `rfc5280/expiry_policy.rs` | *(ours)* | 5 | Sub-policy internals |
| `crypto/ring.rs` | *(ours)* | 5 | Backend internals |
| `crypto/aws_lc.rs` | *(ours)* | 4 | Backend internals |
| `rfc5280/version_policy.rs` | *(ours)* | 2 | Sub-policy internals |
| `crypto/mod.rs` | *(ours)* | 2 | Fake `KeyProvider` dispatch |

## Deliberately not ported

This library ports the **Verifier** only. These upstream suites cover areas
outside that scope and have no counterpart here:

`CMSTests`, `CSRTests`, `OCSPTests`, `OCSPPolicyVerifierTests`, `PEMTests`,
`SignatureTests`, `CertificateDERTests`, `CertificateTests`,
`DistinguishedNameTests`, `DistinguishedNameBuilderTests`, `TimeTests`,
`ExtendedKeyUsageTests`, `ExtensionBuilderTests`, `CustomPrivateKeyTests`,
`SecKeyWrapperTests`.

## Backend tests

Real-signature chain verification lives in
`x509-validator-awc-lc/tests/verify_chain.rs` (5 tests), which exercises the
aws-lc backend against captured production certificate chains.
`x509-validator-core` carries 4 unit tests of its own.

## Totals

110 unit + 98 integration + 5 backend + 4 core = **217**.
