//! Shared setup for the runnable examples.

use time::{Duration, OffsetDateTime};
use x509_validator::crypto::SignatureVerifier;
use x509_validator::Certificate;
use x509_validator_testkit::{cert, rcgen, CaSpec, LeafSpec};

/// The crypto backend the examples verify signatures with.
pub const BACKEND: &dyn SignatureVerifier = &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER;

/// A freshly generated root → intermediate → leaf chain.
pub struct DemoChain {
    pub root: Certificate<'static>,
    pub intermediate: Certificate<'static>,
    pub leaf: Certificate<'static>,
}

/// Generates a chain whose leaf is valid for `dns_names` and carries the
/// serverAuth key purpose, with every validity window comfortably spanning
/// `now`.
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
    .extended_key_usages(&[rcgen::ExtendedKeyUsagePurpose::ServerAuth])
    .validity(window.0, window.1)
    .signed_by(&intermediate);

    DemoChain {
        root: cert(root.der),
        intermediate: cert(intermediate.der),
        leaf: cert(leaf),
    }
}

/// Generates a chain whose leaf and intermediate carry the given key
/// purposes, for showing how an extendedKeyUsage policy reacts to each shape.
/// An empty slice leaves the extension off that certificate entirely.
pub fn demo_chain_with_ekus(
    dns_names: &[&str],
    leaf_ekus: &[rcgen::ExtendedKeyUsagePurpose],
    intermediate_ekus: &[rcgen::ExtendedKeyUsagePurpose],
) -> DemoChain {
    let now = OffsetDateTime::now_utc();
    let window = (now - Duration::days(1), now + Duration::days(365));
    let algorithm = &rcgen::PKCS_ECDSA_P256_SHA256;
    let key = || key_pair_for(algorithm);

    let root = CaSpec::new("Example Root CA")
        .key_pair(key())
        .validity(window.0, window.1)
        .self_signed();

    let intermediate_ekus = intermediate_ekus.to_vec();
    let intermediate = x509_validator_testkit::issue_ca(
        "Example Intermediate CA",
        &root,
        None,
        move |params: &mut rcgen::CertificateParams| {
            params.not_before = window.0;
            params.not_after = window.1;
            params.extended_key_usages = intermediate_ekus;
        },
    );

    let leaf = LeafSpec::new(
        dns_names
            .first()
            .copied()
            .unwrap_or("example.com"),
    )
    .key_pair(key())
    .dns_sans(dns_names)
    .extended_key_usages(leaf_ekus)
    .validity(window.0, window.1)
    .signed_by(&intermediate);

    DemoChain {
        root: cert(root.der),
        intermediate: cert(intermediate.der),
        leaf: cert(leaf),
    }
}

/// A key pair for `algorithm`.
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
