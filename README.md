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

Validates an X.509 certificate chain against a set of root certificates and verifier policy.

    This library was havily inspired and follows the design of [swift-certificates].

## Requirements

- Rust 2021 edition. Tested against stable; no MSRV is declared yet.

## Installation

Add the dependency and pick a crypto backend:

```toml
x509-validator = { version = "0.1.0", features = ["aws_lc"] }
```

| Feature | Backend | Notes                                      |
|---|---|--------------------------------------------|
| `aws_lc` | [aws-lc-rs](https://github.com/aws/aws-lc-rs) | Fastest of the three. Needs a C toolchain. |
| `ring` | [ring](https://github.com/briansmith/ring) | Close behind, except at ECDSA P-384.       |
| `rust_crypto` | [RustCrypto](https://github.com/RustCrypto) | Pure Rust. Slowest.                        |

    You can provide your own backend <link to example>

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

Parsing is [x509-parser]'s. `x509_validator_core::Certificate` is a re-export
of its `X509Certificate`, so certificates borrow their input buffer rather than
being copied into an owned tree.

Crypto is yours to choose, via the feature flags above or your own
`SignatureVerifier`.

Policy is where the actual rules live. The validator finds paths; it does not
decide what a good path is. A `ValidationPolicy` gets each candidate chain and
accepts or rejects it, and the built-in policies are ordinary implementations
of that same trait with no privileged access.

## Benchmarks

Two crates, in [x509-validator-bench]:

- [`measure`][bench-measure] — did *our* code get slower? One backend, one
  fixed reference time, criterion tracking history between runs.
- [`compare`][bench-compare] — which is faster? Backend against backend,
  parser against parser, with [results][bench-results] for Apple Silicon.

## Contributing

Contributions are welcome. Please read the [Code of Conduct][coc] first.

## License

X509Validator is distributed under the following two licenses:

- Apache License version 2.0.
- MIT license.

These are included as LICENSE-APACHE and LICENSE-MIT respectively.  
You may use this software under the terms of any of these licenses, at your option.

[swift-certificates]: https://github.com/apple/swift-certificates/tree/main/Sources/X509/Verifier
[x509-parser]: https://github.com/rusticata/x509-parser
[examples]: examples/examples
[x509-validator-bench]: x509-validator-bench
[bench-measure]: x509-validator-bench/measure/README.md
[bench-compare]: x509-validator-bench/compare/README.md
[bench-results]: x509-validator-bench/compare/README.md#results
[coc]: CODE_OF_CONDUCT.md
