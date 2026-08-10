<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".local/logo-dark.png">
  <source media="(prefers-color-scheme: light)" srcset=".local/logo-light.png">
  <img width="33%" alt="X509-validator" src=".local/logo-light.png">
</picture>
</p>

# X509Validator 

[![Tests](https://github.com/namecare/x509-validator/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/namecare/x509-validator/actions/workflows/tests.yml?query=branch%3Amaster)
[![Documentation](https://docs.rs/x509-validator/badge.svg)](https://docs.rs/x509-validator/)
[![Crates.io](https://img.shields.io/crates/v/x509-validator.svg)](https://crates.io/crates/x509-validator)

X.509 certificate chain validator.   

## Overview

This library validates an X.509 certificate chain against a set of root certificates and a policy. This is an essential building block for a wide range
of PKI applications. It ships with a default verifier and a number of built-in verifier policies.

> This library is heavily inspired by, and follows the design of, the [verifier from the swift-certificates library][ref]. Some pragmatic ideas and project structure has been taking from [rustls](https://github.com/rustls/rustls/tree/main).

## Requirements

- Rust 1.85 or newer, edition 2024.

## Installation

Add the dependency and pick a crypto backend:

```toml
x509-validator = { version = "0.1.0", features = ["aws_lc"] }
```

| Feature | Backend | Notes                   |
|---|---|-------------------------|
| `aws_lc` | [aws-lc-rs](https://github.com/aws/aws-lc-rs) | Fastest.                |
| `ring` | [ring](https://github.com/briansmith/ring) | Close to awc_lc.        |
| `rust_crypto` | [RustCrypto](https://github.com/RustCrypto) | Pure Rust. The slowest. |

There is no default backend: without one of these features the crate compiles
but verifies nothing. You can also provide your own by implementing
`SignatureVerifier` — see the [`custom_crypto_backend`][custom-backend] example.

## Example code

```rust
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::validator::ChainValidationResult;
use x509_validator::Validator;

// Roots are trusted a priori. Intermediates are only available to build
// through — each still has to be signed by something leading back to a root.
let roots = CertificateStore::from_iter([root]);
let intermediates = CertificateStore::from_iter([intermediate]);

let policy = RFC5280Policy::new(now);
let validator = Validator::with_policy(roots, policy);

match validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {}) {
    ChainValidationResult::ValidCertificate(chain) => {
        // Leaf first, root last.
        for cert in chain.iter() {
            println!("{}", cert.tbs_certificate.subject);
        }
    }
    ChainValidationResult::CouldNotValidate(reasons) => {
        // Empty means no candidate chain reached a root, so the policy was
        // never asked.
        for reason in reasons {
            println!("rejected: {reason}");
        }
    }
}
```

The closure is the diagnostic channel: chain building reports every issuer it
considers and every candidate it discards through it. Pass `&mut |_| {}` to
ignore it.

Runnable versions of this and more are in [examples]:

| Example | Shows |
|---|---|
| `validate_chain` | The above, end to end |
| `server_identity` | Hostname validation, and combining two policies |
| `diagnostics` | Reading the diagnostic callback to find out *why* a chain failed |
| `custom_crypto_backend` | Implementing `SignatureVerifier` over OpenSSL |

    cargo run -p x509-validator-examples --example validate_chain

## Approach

Parsing is done by [x509-parser]. `x509_validator::Certificate` is a re-export
of its `X509Certificate`.

Crypto is swappable via the feature flags above, or you can supply your own
`SignatureVerifier`.

Policy is where the actual rules live. A `ValidationPolicy` receives each candidate chain and
accepts or rejects it.

## Benchmarks

Two crates, in [x509-validator-bench]:

- [`measure`][bench-measure] — Regression benchmarks.
- [`compare`][bench-compare] — Compare backends and parsers ([results][bench-results]).

## Contributing

Thanks for your help improving the project! We are so happy to have you! We have a [contributing guide][contribute] to help you get involved in the X509Validator project, and everyone taking part is expected to follow our [Code of Conduct][coc].

## License

X509Validator is distributed under the following two licenses:

- Apache License version 2.0.
- MIT license.

These are included as LICENSE-APACHE and LICENSE-MIT respectively.  
You may use this software under the terms of any of these licenses, at your option.

[ref]: https://github.com/apple/swift-certificates/tree/main/Sources/X509/Verifier
[x509-parser]: https://github.com/rusticata/x509-parser
[examples]: examples/examples
[custom-backend]: examples/examples/custom_crypto_backend.rs
[x509-validator-bench]: x509-validator-bench
[bench-measure]: x509-validator-bench/measure/README.md
[bench-compare]: x509-validator-bench/compare/README.md
[bench-results]: x509-validator-bench/compare/README.md#results
[coc]: CODE_OF_CONDUCT.md
[contribute]: CONTRIBUTING.md