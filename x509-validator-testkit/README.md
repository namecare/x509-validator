<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".local/logo-dark.png">
  <source media="(prefers-color-scheme: light)" srcset=".local/logo-light.png">
  <img width="20%" alt="X509-validator" src=".local/logo-light.png">
</picture>
</p>

# X509Validator TestKit

Provides helpers for building real DER-encoded certificates in tests.

Fixtures are generated with [rcgen](https://github.com/rustls/rcgen) and signed
for real. 

> NOTE: rcgen cannot express a shape — an omitted `subjectKeyIdentifier`, an unsupported `GeneralName`, an undecodable extension
body — the DER is hand-encoded instead, so negative tests can reach cases a well-behaved generator never produces.

## Requirements

- Rust 1.88 or newer, edition 2024.

## Installation

This crate is unpublished: it exists for this workspace's own test, benchmark
and fuzz targets. Depend on it by path, as a dev-dependency:

```toml
[dev-dependencies]
x509-validator-testkit = { path = "../x509-validator-testkit" }
```

## Example code

Build a root, issue a leaf under it, and validate the chain:

```rust
use x509_validator_testkit::{chain_of, issue_leaf, self_signed_ca_with};

let root = self_signed_ca_with("Test Root", |_| {});
let leaf = issue_leaf("localhost", &["localhost"], &root);

let chain = chain_of(vec![leaf, root.der.clone()]);
```

Deeper chains come from issuing intermediates, and `configure` closures reach
any `CertificateParams` field the shorthand does not cover:

```rust
use x509_validator_testkit::{issue_ca, issue_leaf, name_constraints, dns_subtree, self_signed_ca_with};

let root = self_signed_ca_with("Constrained Root", |params| {
    params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
});
let intermediate = issue_ca("Intermediate", &root, Some(0), |_| {});
let leaf = issue_leaf("host", &["host.example.com"], &intermediate);
```

When the defaults for key algorithm and validity window need pinning, use the
builders instead of the shorthand helpers:

```rust
use x509_validator_testkit::rcgen::{KeyPair, PKCS_ECDSA_P384_SHA384};
use x509_validator_testkit::time::{Duration, OffsetDateTime};
use x509_validator_testkit::{CaSpec, LeafSpec};

let now = OffsetDateTime::UNIX_EPOCH + Duration::days(10_000);
let root = CaSpec::new("P-384 Root")
    .key_pair(KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("key"))
    .validity(now - Duration::days(365), now + Duration::days(365))
    .self_signed();

let leaf = LeafSpec::new("localhost")
    .dns_sans(&["localhost"])
    .validity(now - Duration::days(365), now + Duration::days(365))
    .signed_by(&root);
```

## Structure

| Module | Contents |
|---|---|
| `ca` | Root and intermediate issuance: `self_signed_ca`, `issue_ca`, `issue_self_issued_ca`, `Ca::cross_signed_by`, and the `CaSpec` builder. `Ski` controls whether a `subjectKeyIdentifier` is derived, fixed to exact bytes, or absent entirely; `signing_identity` signs *as* a name before any certificate for that name exists, for building cyclic PKIs. |
| `leaf` | Leaf issuance with DNS, IP, email or caller-built distinguished names, plus the `LeafSpec` builder for pinned validity and unrecognised critical extensions. |
| `constraints` | `nameConstraints` subtrees rcgen can model: DNS, IPv4 CIDR, directoryName. |
| `raw` | Hand-encoded DER for what rcgen cannot model — URI, otherName, x400Address, ediPartyName and registeredID subtrees, raw `subjectAltName` extensions, and deliberately undecodable `nameConstraints`/`subjectAltName` bodies. |
| `parse` | `cert` and `chain_of` turn owned DER into borrowed `Certificate` values by leaking the bytes; tests are short-lived, so the leak is deliberate and bounded. |
| `roots` | The vendored Mozilla CA bundle, embedded at compile time as `ROOTS`. One list shared by the benchmark crates and the fuzz corpus, so they cannot drift apart. |
| `real_chain` | A real, publicly-issued chain (Apple receipt signing: leaf → WWDR G6 → Apple Root CA - G3), carrying policy OIDs and revocation pointers that generated fixtures do not. |
| `bench_fixtures` | The parity certificate set the benchmarks validate against, built once behind a `OnceLock` and pinned to a fixed `REFERENCE_TIME`. |

## License

x509-validator-testkit is distributed under the following two licenses:

- Apache License version 2.0.
- MIT license.

These are included as LICENSE-APACHE and LICENSE-MIT respectively.  
You may use this software under the terms of any of these licenses, at your option.