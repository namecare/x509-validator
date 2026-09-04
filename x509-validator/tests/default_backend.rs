//! What `crypto::default_provider` resolves to for a given set of enabled
//! backend features.
//!
//! A backend is determined only when exactly one backend feature is enabled.
//! Zero enabled backends, or several with no basis to prefer one, leave no
//! single default, and using the resulting provider panics rather than failing
//! verification quietly — a chain that cannot be checked at all must not be
//! reported the same way as one that was checked and found wanting.

use x509_validator::crypto::default_provider;
use x509_validator::{Certificate, CertificateExt};
use x509_validator_testkit::rcgen::{CertificateParams, KeyPair};

/// The DER of a real self-signed certificate, giving the tests a genuine
/// signature to hand the default provider. rcgen's default algorithm is
/// ECDSA P-256 / SHA-256, which every backend supports.
///
/// The DER is returned rather than a parsed `Certificate`, because a
/// `Certificate` borrows the bytes it was parsed from: the caller owns the
/// DER for as long as it holds the certificate.
fn self_signed_der() -> Vec<u8> {
    let key_pair = KeyPair::generate().expect("generate key pair");
    CertificateParams::default()
        .self_signed(&key_pair)
        .expect("self-sign")
        .der()
        .to_vec()
}

/// With exactly one backend enabled, the default provider is that backend and
/// really verifies, rather than being a placeholder that defers a panic.
#[cfg(any(
    all(
        feature = "aws_lc",
        not(feature = "ring"),
        not(feature = "rust_crypto")
    ),
    all(
        feature = "ring",
        not(feature = "aws_lc"),
        not(feature = "rust_crypto")
    ),
    all(
        feature = "rust_crypto",
        not(feature = "aws_lc"),
        not(feature = "ring")
    ),
))]
#[test]
fn single_backend_feature_determines_a_working_provider() {
    let der = self_signed_der();
    let cert = Certificate::parse(&der).expect("parse certificate");

    let result = default_provider().verify_signature(
        &cert.signature_algorithm,
        cert.public_key(),
        cert.tbs_certificate.as_ref(),
        cert.signature_value.as_ref(),
    );

    assert!(
        result.is_ok(),
        "expected the self-signature to verify, got {result:?}"
    );
}

/// With no backend enabled, or several, the default provider panics on use.
/// The message names the features to choose from, so the panic diagnoses the
/// build misconfiguration that caused it.
#[cfg(not(any(
    all(
        feature = "aws_lc",
        not(feature = "ring"),
        not(feature = "rust_crypto")
    ),
    all(
        feature = "ring",
        not(feature = "aws_lc"),
        not(feature = "rust_crypto")
    ),
    all(
        feature = "rust_crypto",
        not(feature = "aws_lc"),
        not(feature = "ring")
    ),
)))]
#[test]
fn undetermined_backend_panics_naming_the_features() {
    let der = self_signed_der();
    let cert = Certificate::parse(&der).expect("parse certificate");

    // `AssertUnwindSafe`: the certificate is only read, and the test ends
    // with the catch, so no witnessed broken invariant can escape.
    let panic = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        default_provider().verify_signature(
            &cert.signature_algorithm,
            cert.public_key(),
            cert.tbs_certificate.as_ref(),
            cert.signature_value.as_ref(),
        )
    }))
    .expect_err("expected a panic, got a verification result");

    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("panic payload should be a string");

    for feature in ["aws_lc", "ring", "rust_crypto"] {
        assert!(
            message.contains(feature),
            "panic message should name the `{feature}` feature, got: {message}"
        );
    }
}
