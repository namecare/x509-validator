//! Regression benchmarks for `x509-validator`.
//!
//! Where the `compare` crate asks "which backend or parser is faster?", this
//! one asks "did our own code get slower?" — so it holds every axis it can
//! still. One backend, one fixed reference time, and benchmark names that
//! are meant never to change: a renamed benchmark is a new benchmark with no
//! history, which is the one way a regression suite can quietly stop working.
//!
//! Certificate generation is expensive and must never land inside a timed
//! region, so the fixtures are built once and reused.

pub mod fixtures;
pub mod roots;

use x509_validator::crypto::CryptoProvider;

/// The single backend these benchmarks run against.
///
/// aws-lc-rs when compiled in, otherwise whichever backend is. Crypto is the
/// dominant cost of validation, so the choice sets the absolute scale of
/// every number here — but the suite is read as a trend against its own
/// history, and switching backends restarts that history. Treat this as
/// fixed unless you mean to reset the baseline.
#[cfg(feature = "aws_lc")]
pub const BACKEND: &CryptoProvider = &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER;
#[cfg(all(feature = "ring", not(feature = "aws_lc")))]
pub const BACKEND: &CryptoProvider = &x509_validator::crypto::ring::DEFAULT_PROVIDER;
#[cfg(all(feature = "rust_crypto", not(feature = "aws_lc"), not(feature = "ring")))]
pub const BACKEND: &CryptoProvider = &x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER;
#[cfg(not(any(feature = "aws_lc", feature = "ring", feature = "rust_crypto")))]
compile_error!("x509-validator-bench-measure requires exactly one crypto backend feature: aws_lc, ring, or rust_crypto");
