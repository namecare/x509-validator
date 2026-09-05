# Tests

## Layout

Integration tests live here, in files named after the upstream suite they
were ported from. Unit tests live in `#[cfg(test)] mod tests` blocks beside
the code they exercise.

The rule: a test belongs in `src/` only when it exercises a **private
algorithm** — byte-level matching, internal dispatch. Everything that drives
a public API belongs here, running against a real crypto backend.

Certificate-building helpers for both come from the `x509-validator-testkit`
crate, a dev-dependency that never enters the shipped dependency graph. It
provides the canonical `cert`, `leak` and `chain_of` helpers; test files
must not define their own.

Run everything with:

    cargo test --workspace --all-features

`--all-features` matters: `tests/verifier.rs` is gated on a crypto backend
being enabled and compiles to zero tests without one.

## Integration tests (162)

| File | Upstream suite | Tests |
|---|---|---:|
| `server_identity_policy.rs` | `ServerIdentityPolicyTests` | 48 |
| `rfc5280_policy.rs` | `RFC5280PolicyTests` | 41 |
| `verifier.rs` | `VerifierTests` | 24 |
| `diagnostics.rs` | *(ours)* | 17 |
| `name_constraints_policy.rs` | `NameConstraintsTests` | 8 |
| `basic_constraints_policy.rs` | *(ours)* | 8 |
| `expiry_policy.rs` | *(ours)* | 5 |
| `certificate_store.rs` | `CertificateStore` | 4 |
| `certificate_display.rs` | *(ours)* | 4 |
| `version_policy.rs` | *(ours)* | 2 |
| `policy_composition.rs` | *(ours)* | 1 |

`rfc5280_policy.rs` keeps a two-module split: `tests` covers composition
wiring, `conformance` drives each rule from both the composed policy and
its owning sub-policy via a `PolicyUnderTest` selector.

`verifier.rs` runs against whichever backend feature is enabled, selected by
`#![cfg(any(feature = "aws_lc", feature = "ring"))]`. It uses genuinely
signed certificates throughout — no stub verifier.

## Unit tests in `src/` (47)

Only private algorithms remain:

| Module | Upstream suite | Tests |
|---|---|---:|
| `rfc5280/uri_constraints.rs` | *(ours)* | 14 |
| `rfc5280/dns_names.rs` | `DNSNamesTests` | 14 |
| `rfc5280/ip_constraints.rs` | `IPAddressTests` | 8 |
| `crypto/ring.rs` | *(ours)* | 5 |
| `crypto/aws_lc.rs` | *(ours)* | 4 |
| `crypto/mod.rs` | *(ours)* | 2 |

The name-matching modules mirror upstream suites that are table-driven over
reference corpora: a handful of upstream functions iterate large fixture
tables, which port here as one test per corpus.

## On upstream test counts

Raw `func test` counts overstate the number of distinct behaviours. Upstream
writes many behaviours once per policy variant (`…Base`, `…BasePolicy`) and,
in `VerifierTests`, once per API overload (`…Deprecated`). Measured as
unique behaviours:

| Suite | Raw | Unique | Here |
|---|---:|---:|---:|
| `RFC5280PolicyTests` | 126 | 41 | 41 |
| `ServerIdentityPolicyTests` | 56 | 28 | 48 |
| `VerifierTests` | 37 | 19 | 24 |
| `CertificateStore` | 6 | 4 | 4 |

Compare behaviours, not function counts, before treating a number as a
parity target.

## Deliberately not ported

This library ports the **Verifier** only. These upstream suites cover areas
outside that scope:

`CMSTests`, `CSRTests`, `OCSPTests`, `OCSPPolicyVerifierTests`, `PEMTests`,
`SignatureTests`, `CertificateDERTests`, `CertificateTests`,
`DistinguishedNameTests`, `DistinguishedNameBuilderTests`, `TimeTests`,
`ExtendedKeyUsageTests`, `ExtensionBuilderTests`, `CustomPrivateKeyTests`,
`SecKeyWrapperTests`.

`PolicyBuilderTests` is also out of scope: it exercises a result-builder DSL
that has no counterpart in this port.

## Totals

47 unit + 162 integration + 4 core = **213**.

## Vendored suite: rustls/webpki

`tests/rustls_webpki/` holds the portable part of a second upstream's
integration tests, ported to run against this library. It has its own
`README.md` recording the upstream revision, what was ported, and where this
library diverges.

Its counts are not comparable with the parity tables above: it is a different
upstream with a different notion of what one test covers, and it is kept for
the divergences it surfaces rather than for coverage parity.
