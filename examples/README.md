<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../.local/logo-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="../.local/logo-light.png">
  <img width="140" alt="X509-validator" src="../.local/logo-light.png">
</picture>
</p>

# X509Validator Examples

Examples for the [x509-validator][crate] crate.

## Overview

This directory contains a number of examples showcasing various capabilities of the x509-validator(todo: add link to crate) crate.

todo: list of all examples with small desc

| Example | Notes |
|---|---|
| [`validate_chain`][validate-chain] | The core flow: a store of trusted roots, a store of intermediates to build through, and `RFC5280Policy`. Also shows what rejection looks like when no chain reaches a root. |
| [`server_identity`][server-identity] | Hostname validation with `ServerIdentityPolicy`, and combining it with `RFC5280Policy` by implementing `ValidationPolicy` over both. |
| [`diagnostics`][diagnostics] | Using the diagnostic callback to find out *why* a chain was rejected — every issuer considered and every candidate discarded. |
| [`custom_crypto_backend`][custom-backend] | Implementing `SignatureVerifier` over a crypto library the crate knows nothing about — OpenSSL here. |

## Requirements

- Rust 1.88 or newer, edition 2024.

## Usage

All examples can be executed with:

```
cargo run -p x509-validator-examples --example $name
```

For instance:

```
cargo run -p x509-validator-examples --example validate_chain
```

A good starting point would be `validate_chain` and `custom_crypto_backend`.

## Contributing

If you've got an example you'd like to see here, please feel free to open an issue. Otherwise if you've got an example you'd like to add, please feel free to make a PR!

## License

X509Validator is distributed under the following two licenses:

- Apache License version 2.0.
- MIT license.

These are included as LICENSE-APACHE and LICENSE-MIT respectively.  
You may use this software under the terms of any of these licenses, at your option.

[crate]: https://crates.io/crates/x509-validator
[lib]: src/lib.rs
[manifest]: Cargo.toml
[validate-chain]: examples/validate_chain.rs
[server-identity]: examples/server_identity.rs
[diagnostics]: examples/diagnostics.rs
[custom-backend]: examples/custom_crypto_backend.rs