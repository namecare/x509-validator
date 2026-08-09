//! What `crypto::default_provider` resolves to for a given set of enabled
//! backend features.
//!
//! A backend is determined only when exactly one backend feature is enabled.
//! Zero enabled backends, or several with no basis to prefer one, leave no
//! single default, and using the resulting provider panics rather than failing
//! verification quietly — a chain that cannot be checked at all must not be
//! reported the same way as one that was checked and found wanting.

use x509_validator::crypto::default_provider;

/// With exactly one backend enabled, the default provider is that backend and
/// really computes, rather than being a placeholder that defers a panic.
#[cfg(any(
    all(feature = "aws_lc", not(feature = "ring"), not(feature = "rust_crypto")),
    all(feature = "ring", not(feature = "aws_lc"), not(feature = "rust_crypto")),
    all(feature = "rust_crypto", not(feature = "aws_lc"), not(feature = "ring")),
))]
#[test]
fn single_backend_feature_determines_a_working_provider() {
    // SHA-256 of the empty input, from FIPS 180-4. Any real backend produces
    // it; the undetermined-backend provider panics instead.
    let expected = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93,
        0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    ];
    assert_eq!(default_provider().sha256.hash(b""), expected);
}

/// With no backend enabled, or several, the default provider panics on use.
/// The message names the features to choose from, so the panic diagnoses the
/// build misconfiguration that caused it.
#[cfg(not(any(
    all(feature = "aws_lc", not(feature = "ring"), not(feature = "rust_crypto")),
    all(feature = "ring", not(feature = "aws_lc"), not(feature = "rust_crypto")),
    all(feature = "rust_crypto", not(feature = "aws_lc"), not(feature = "ring")),
)))]
#[test]
fn undetermined_backend_panics_naming_the_features() {
    let panic = std::panic::catch_unwind(|| default_provider().sha256.hash(b"")).expect_err("expected a panic, got a digest");

    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("panic payload should be a string");

    for feature in ["aws_lc", "ring", "rust_crypto"] {
        assert!(message.contains(feature), "panic message should name the `{feature}` feature, got: {message}");
    }
}