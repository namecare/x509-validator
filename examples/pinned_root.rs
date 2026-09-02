//! Trusting one private CA instead of the public web PKI.
//!
//! Internal services are usually issued by a company's own CA, which no
//! public trust store knows about. Pinning that root — and only that root —
//! is what makes the check meaningful: the same certificate that your own CA
//! vouches for is rejected outright by the public bundle.
//!
//!     cargo run -p x509-validator-examples --example pinned_root

use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::{Certificate, CertificateExt, ServerIdentityPolicy, Validator};

/// The platform's trust store, as DER. This is where a browser or a TLS
/// client gets its roots.
fn native_roots() -> Vec<Vec<u8>> {
    let result = rustls_native_certs::load_native_certs();
    assert!(
        result.errors.is_empty(),
        "could not read the platform trust store: {:?}",
        result.errors
    );
    result
        .certs
        .into_iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect()
}

fn parse(der: &[u8]) -> Certificate<'_> {
    Certificate::parse(der).expect("certificate parses")
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_secs() as i64
}

/// The corporate CA and a certificate it issued for an internal host, both as
/// DER — the form they would arrive in from a file or a handshake.
fn issue_internal_service() -> (Vec<u8>, Vec<u8>) {
    let mut ca_params = CertificateParams::new(vec![]).expect("CA parameters");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Example Corp Internal CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let ca_key = KeyPair::generate().expect("CA key");
    let ca = ca_params
        .self_signed(&ca_key)
        .expect("self-signed CA");
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let mut leaf_params =
        CertificateParams::new(vec!["service.internal".to_string()]).expect("leaf parameters");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "service.internal");
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("issued leaf");

    (ca.der().to_vec(), leaf.der().to_vec())
}

fn main() {
    let (ca_der, leaf_der) = issue_internal_service();
    let leaf = parse(&leaf_der);

    // The corporate root is the only anchor. Nothing else is trusted, which is
    // the point: a certificate from any public CA cannot satisfy this check.
    let pinned = CertificateStore::from_iter([parse(&ca_der)]);
    let native = native_roots();
    let public = CertificateStore::from_iter(native.iter().map(|der| parse(der)));

    for (name, roots) in [
        ("pinned corporate root", pinned),
        ("platform trust store", public),
    ] {
        let policy = x509_validator::policy! {
            RFC5280Policy::new(now());
            ServerIdentityPolicy::new(Some("service.internal"), None)
        };

        let validator = Validator::with_policy(roots, policy);

        let verdict = match validator.validate(&leaf, &CertificateStore::new()) {
            Ok(_) => "accepted".to_string(),
            Err(failures) if failures.is_empty() => {
                "rejected — no chain reached a trusted root".to_string()
            }
            Err(failures) => format!("rejected — {}", failures[0]),
        };

        println!("{name:<24} {verdict}");
    }
}
