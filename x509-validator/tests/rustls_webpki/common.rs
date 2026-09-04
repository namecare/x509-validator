//! Shared helpers for the ported suites.
//!
//! Upstream's `tests/common/mod.rs` holds only certificate generation and
//! the signature algorithm those generated certificates use. This module
//! keeps that surface, plus the crypto provider selection each suite's
//! `check_cert` needs — a `Validator` takes a provider explicitly, so the
//! feature cascade that picks one has to live somewhere shared.

#![allow(dead_code)]

#[cfg(feature = "aws_lc")]
pub use x509_validator::crypto::aws_lc::DEFAULT_PROVIDER;
#[cfg(all(feature = "ring", not(feature = "aws_lc")))]
pub use x509_validator::crypto::ring::DEFAULT_PROVIDER;
#[cfg(all(
    feature = "rust_crypto",
    not(feature = "aws_lc"),
    not(feature = "ring")
))]
pub use x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER;
use x509_validator::store::CertificateStore;
use x509_validator::{Certificate, CertificateExt};

/// Inside the validity window the generator gives certificates by default,
/// which is epoch seconds 1000 to 2000. Upstream validates at a fixed
/// `0x1fed_f00d`; every certificate here is generated rather than committed,
/// so the window is this repo's.
pub const NOW: i64 = 1_500;

pub fn parse<'a>(bytes: &'a [u8]) -> Certificate<'a> {
    Certificate::parse(bytes).expect("certificate parses")
}

pub fn store<'a>(ders: &[&'a [u8]]) -> CertificateStore<'a> {
    CertificateStore::from_iter(ders.iter().copied().map(parse))
}

/// Joins the reasons a failed validation collected, so a caller can match a
/// substring against the whole set rather than guess which chain failed last.
pub fn reasons(reasons: &[impl ToString]) -> String {
    reasons
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Asserts a validation failed, and failed for the expected reason.
///
/// Matching the reason is the point: a chain rejected for the wrong reason
/// is a bug that an `is_err()` assertion cannot see.
#[track_caller]
pub fn assert_reason(result: Result<(), String>, expected: &str) {
    match result {
        Ok(()) => panic!("expected failure {expected:?}, but validation succeeded"),
        Err(reasons) => assert!(
            reasons.contains(expected),
            "expected a failure containing {expected:?}, got {reasons:?}"
        ),
    }
}

/// The substrings the suites match failure reasons against.
///
/// Upstream asserts on `webpki::Error` variants. Failure reasons here are
/// strings, so the assertions match on substrings, and every substring the
/// suites depend on lives here — a reworded diagnostic is then a one-line
/// fix rather than a sweep.
pub mod reason {
    pub const EXPIRED: &str = "certificate has expired";
    pub const NOT_YET_VALID: &str = "is not yet valid";
    pub const NAME_MISMATCH: &str = "none of the names in the SAN extension matched";
    pub const NO_SAN_NO_CN: &str = "no SAN extension and no common name";
    pub const V1_WITH_EXTENSIONS: &str = "contains extensions but should not";
    pub const NOT_A_CA: &str = "is not marked as a CA";
    pub const PATH_LEN: &str = "has maximum path length";
    pub const EKU_ABSENT: &str = "carries no extended key usage extension";
    pub const EKU_MISMATCH: &str = "names none of the accepted extended key usages";
    pub const EXCLUDED_SUBTREE: &str = "name is in an excluded subtree";
    pub const PERMITTED_SUBTREE: &str = "unable to validate permitted subtree, no matches";
    pub const UNHANDLED_CRITICAL: &str = "leaf certificate has unhandled critical extension";
    /// A nameConstraints subtree of a kind this library does not evaluate
    /// (anything but dNSName, iPAddress, URI or directoryName), shared by
    /// both the permitted- and excluded-subtree checks.
    pub const UNSUPPORTED_CONSTRAINT_KIND: &str = "unsupported constraint kind";
    /// A directoryName nameConstraints subtree, which this library rejects
    /// outright rather than evaluating with the full RFC 5280 comparison
    /// algorithm.
    pub const DIRECTORY_NAME_UNSUPPORTED: &str = "directoryName name constraints are not supported";
}
