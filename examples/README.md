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

Each example is a single self-contained file that starts where a real
application starts: with DER bytes.

| Example | Shows |
|---|---|
| [`apple_x5c`][apple-x5c] | Validating the `x5c` chain carried by an App Store signed transaction, against a pinned root. |
| [`webpki`][webpki] | What a TLS client checks: the platform trust store, serverAuth, and the hostname. |
| [`client_certificate`][client-certificate] | The mutual-TLS server side — clientAuth, and identity taken from the subject. |
| [`pinned_root`][pinned-root] | Trusting one private CA instead of the public web PKI. |
| [`diagnostics`][diagnostics] | Reading the diagnostic callback to find out *why* a chain was rejected. |
| [`custom_crypto_backend`][custom-backend] | Implementing `SignatureVerifier` over OpenSSL. |

A good starting point is `webpki`, then `apple_x5c`.

## Certificates

Real certificates live in [`mocks/`](mocks): a TLS chain captured from a
handshake with example.com, and a signed transaction from Apple's own test
suite, whose `x5c` header carries a real chain.
The examples that need a chain shaped a particular way — a private CA, a
client credential, a deliberately broken chain — generate one with
[rcgen][rcgen] instead, so the shape being demonstrated is visible in the
example itself.

Public roots come from the operating system's own trust store, via
[rustls-native-certs][native-certs]. Every crate these examples use is
published, so an example can be copied into your own project as it stands.

Because the vendored certificates are real, they expire. `webpki` validates
against the current time and will start failing once the example.com chain
expires; re-capture it with:

```sh
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null
```

`apple_x5c` checks expiry against its transaction's `signedDate`, so it keeps
working regardless of the wall clock.

## Requirements

- Rust 1.88 or newer.
- OpenSSL, for the `custom_crypto_backend` example.
- A platform trust store, for `webpki` and `pinned_root`.

## Usage

```sh
cargo run -p x509-validator-examples --example $name
```

For instance:

```sh
cargo run -p x509-validator-examples --example webpki
```

## Contributing

If you've got an example you'd like to see here, please feel free to open an issue. Otherwise if you've got an example you'd like to add, please feel free to make a PR!

## License

X509Validator is distributed under the following two licenses:

- Apache License version 2.0.
- MIT license.

These are included as LICENSE-APACHE and LICENSE-MIT respectively.  
You may use this software under the terms of any of these licenses, at your option.

[crate]: https://crates.io/crates/x509-validator
[rcgen]: https://github.com/rustls/rcgen
[native-certs]: https://github.com/rustls/rustls-native-certs
[apple-x5c]: apple_x5c.rs
[webpki]: webpki.rs
[client-certificate]: client_certificate.rs
[pinned-root]: pinned_root.rs
[diagnostics]: diagnostics.rs
[custom-backend]: custom_crypto_backend.rs
