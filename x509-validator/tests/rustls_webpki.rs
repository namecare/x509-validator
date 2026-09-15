//! The portable part of the `rustls/webpki` integration test suite, run
//! against this library.
//!
//! Vendored from `rustls/webpki` at `0.104.0-alpha.7`, commit
//! `68f08541c43374b9fae1c401528b3ef0b5711839`, under the ISC licence; see
//! `rustls_webpki/NOTICE`.
//!
//! Each ported test keeps the upstream test's name, its inputs and its
//! outcome assertion. The calls between them are ours: upstream builds a
//! path and checks subject names in two separate calls, while a `Validator`
//! here runs one composed policy over the whole chain. As upstream does,
//! each suite owns the `check_cert` that spans that difference.
//!
//! Cargo only auto-discovers top-level files in `tests/`, so the suites are
//! declared here as modules rather than found on their own.

#![cfg(any(feature = "aws_lc", feature = "ring", feature = "rust_crypto"))]
// The suite modules live under a private module, so the workspace's
// `unreachable_pub` lint fires on every helper the suites share between
// themselves. Within a test binary there is nothing for them to be
// reachable from, so the visibility is right and the lint is not.
#![allow(unreachable_pub)]

mod rustls_webpki {
    mod amazon;
    mod client_auth;
    pub mod common;
    mod custom_ekus;
    mod integration;
    mod tls_server_certs;
}
