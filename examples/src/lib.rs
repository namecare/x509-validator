//! Shared setup for the runnable examples.
//!
//! Every example needs a certificate chain to validate. Rather than ship DER
//! fixtures — which would need regenerating each time their validity window
//! lapsed — each example generates its own chain at startup, so the code an
//! example is actually demonstrating is the only thing a reader has to look
//! at, and `cargo run --example <name>` works from a clean checkout.
//!
//! The generator lives in `x509-validator-testkit`, an unpublished internal
//! crate. It stands in for whatever a real caller's certificates arrive
//! from — a TLS handshake, a PEM file on disk, a bundle fetched from a
//! peer. Nothing below is part of `x509-validator`'s public API.

use time::{Duration, OffsetDateTime};
use x509_validator::crypto::SignatureVerifier;
use x509_validator::Certificate;
use x509_validator_testkit::{cert, rcgen, CaSpec, LeafSpec};

/// The crypto backend the examples verify signatures with.
///
/// A backend is chosen at compile time by feature; this crate enables
/// `aws_lc`. Swapping to `ring` or `rust_crypto` means changing the feature
/// and this one constant — no other line in any example moves.
pub const BACKEND: &dyn SignatureVerifier = &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER;

/// A freshly generated root → intermediate → leaf chain.
///
/// `Certificate` borrows the DER it was parsed from, so these are backed by
/// leaked buffers and live for the whole process. That suits a short example
/// binary; a real caller would own the DER and keep it alive itself.
pub struct DemoChain {
    pub root: Certificate<'static>,
    pub intermediate: Certificate<'static>,
    pub leaf: Certificate<'static>,
}

/// Generates a chain whose leaf is valid for `dns_names`, with every
/// validity window comfortably spanning `now`.
pub fn demo_chain(dns_names: &[&str]) -> DemoChain {
    demo_chain_with(dns_names, &rcgen::PKCS_ECDSA_P256_SHA256)
}

/// As [`demo_chain`], with every certificate in the chain signed using
/// `algorithm`.
pub fn demo_chain_with(
    dns_names: &[&str],
    algorithm: &'static rcgen::SignatureAlgorithm,
) -> DemoChain {
    let now = OffsetDateTime::now_utc();
    let window = (now - Duration::days(1), now + Duration::days(365));
    let key = || key_pair_for(algorithm);

    let root = CaSpec::new("Example Root CA")
        .key_pair(key())
        .validity(window.0, window.1)
        .self_signed();

    let intermediate = CaSpec::new("Example Intermediate CA")
        .key_pair(key())
        .validity(window.0, window.1)
        .signed_by(&root);

    let leaf = LeafSpec::new(
        dns_names
            .first()
            .copied()
            .unwrap_or("example.com"),
    )
    .key_pair(key())
    .dns_sans(dns_names)
    .validity(window.0, window.1)
    .signed_by(&intermediate);

    DemoChain {
        root: cert(root.der),
        intermediate: cert(intermediate.der),
        leaf: cert(leaf),
    }
}

/// A key pair for `algorithm`.
///
/// The certificate generator cannot itself generate RSA keys, so those are
/// generated with OpenSSL and handed over as PEM.
fn key_pair_for(algorithm: &'static rcgen::SignatureAlgorithm) -> rcgen::KeyPair {
    if algorithm == &rcgen::PKCS_RSA_SHA256 {
        let rsa = openssl::rsa::Rsa::generate(2048).expect("generate RSA key");
        let pem = openssl::pkey::PKey::from_rsa(rsa)
            .expect("wrap RSA key")
            .private_key_to_pem_pkcs8()
            .expect("encode RSA key");
        let pem = String::from_utf8(pem).expect("PEM is UTF-8");
        return rcgen::KeyPair::from_pem_and_sign_algo(&pem, algorithm).expect("load RSA key");
    }

    rcgen::KeyPair::generate_for(algorithm).expect("generate key pair")
}

/// The instant the examples validate against. Kept in one place so the
/// certificates above and the policies below cannot disagree about "now".
pub fn validation_time() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}
