//! Fixtures for the regression suite.
//!
//! The parity set lives in `x509-validator-testkit` because both benchmark
//! crates build against the same certificates; it is re-exported here so
//! call sites read `fixtures::parity()`.

pub use x509_validator_testkit::bench_fixtures::{parity, Parity, REFERENCE_TIME};
