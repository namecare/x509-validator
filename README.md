<picture align="center">
  <source media="(prefers-color-scheme: dark)" srcset=".local/logo-dark.png">
  <source media="(prefers-color-scheme: light)" srcset=".local/logo-light.png">
  <img width="33%" height="160" alt="Your Image Description" src=".local/logo-light.png">
</picture>

# X509Validator 

[![Build Status](https://github.com/namecare/x509-validator/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/namecare/x509-validator/actions/workflows/build.yml?query=branch%3Amain)
[![Documentation](https://docs.rs/rustls/badge.svg)](https://docs.rs/x509-validator/)
[![Crates.io](https://img.shields.io/crates/v/tokio.svg)](https://crates.io/crates/x509-validator)

Validates an X.509 certificate chain against a set of root certificates and verifier policy.
