//! Regression benchmarks for `x509-validator`.

pub mod fixtures;
pub mod roots;

use x509_validator::crypto::SignatureVerifier;

/// The single backend these benchmarks run against.
#[cfg(feature = "aws_lc")]
pub const BACKEND: &dyn SignatureVerifier = &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER;
#[cfg(all(feature = "ring", not(feature = "aws_lc")))]
pub const BACKEND: &dyn SignatureVerifier = &x509_validator::crypto::ring::DEFAULT_PROVIDER;
#[cfg(all(
    feature = "rust_crypto",
    not(feature = "aws_lc"),
    not(feature = "ring")
))]
pub const BACKEND: &dyn SignatureVerifier = &x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER;
#[cfg(not(any(feature = "aws_lc", feature = "ring", feature = "rust_crypto")))]
compile_error!("x509-validator-bench-measure requires exactly one crypto backend feature: aws_lc, ring, or rust_crypto");
