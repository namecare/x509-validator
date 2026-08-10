<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".local/logo-dark.png">
  <source media="(prefers-color-scheme: light)" srcset=".local/logo-light.png">
  <img width="33%" alt="X509-validator" src=".local/logo-light.png">
</picture>
</p>

# X509Validator TestKit

[![Tests](https://github.com/namecare/x509-validator/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/namecare/x509-validator/actions/workflows/tests.yml?query=branch%3Amaster)
[![Documentation](https://docs.rs/x509-validator/badge.svg)](https://docs.rs/x509-validator/)
[![Crates.io](https://img.shields.io/crates/v/x509-validator.svg)](https://crates.io/crates/x509-validator)

Provides helpers for building real DER-encoded certificates in tests.

## Requirements

- Rust 1.85 or newer, edition 2024.

## Installation

Add the dependency and pick a crypto backend:

```toml
x509-validator = { version = "0.1.0", features = ["aws_lc"] }
```

## Example code

## License

x509-validator-testkit is distributed under the following two licenses:

- Apache License version 2.0.
- MIT license.

These are included as LICENSE-APACHE and LICENSE-MIT respectively.  
You may use this software under the terms of any of these licenses, at your option.