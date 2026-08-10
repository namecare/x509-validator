//! Fixtures for the comparison suite.
//!
//! The generated parity set and the vendored real chain both live in
//! `x509-validator-testkit` because both benchmark crates build against the
//! same certificates; they are re-exported here so call sites keep reading
//! `fixtures::parity()` and `fixtures::apple::chain()`.

pub use x509_validator_testkit::bench_fixtures::{parity, Parity, REFERENCE_TIME};
pub use x509_validator_testkit::real_chain::apple;
