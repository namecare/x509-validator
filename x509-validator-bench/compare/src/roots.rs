//! The vendored Mozilla CA bundle roots.
//!
//! The DER files and the list itself live in `x509-validator-testkit`, which
//! is where their provenance is recorded; both benchmark crates and the fuzz
//! corpus draw from that one copy.

pub use x509_validator_testkit::roots::ROOTS;
