//! Validating a server certificate the way a TLS client does.
//!
//! The three checks a browser makes: the chain obeys RFC 5280 and reaches a
//! root in the trust store, the leaf is allowed to authenticate a server, and
//! the leaf actually names the host that was connected to.
//!
//! The trust store is the Mozilla CA bundle and the certificates were taken
//! from a real handshake with example.com, so this is the check a TLS client
//! performs.
//!
//!     cargo run -p x509-validator-examples --example webpki

use std::time::{SystemTime, UNIX_EPOCH};

use x509_validator::rfc5280::{EkuPolicy, RFC5280Policy};
use x509_validator::store::CertificateStore;
use x509_validator::{Certificate, CertificateExt, ServerIdentityPolicy, Validator};

const LEAF: &[u8] = include_bytes!("mocks/example_com_leaf.der");
const INTERMEDIATES: &[&[u8]] = &[
    include_bytes!("mocks/example_com_intermediate_1.der"),
    include_bytes!("mocks/example_com_intermediate_2.der"),
    include_bytes!("mocks/example_com_intermediate_3.der"),
];

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

fn main() {
    let leaf = parse(LEAF);

    // The server sends every certificate it thinks might help. They are
    // candidates to build through, not trusted: each still has to be signed by
    // something that leads back to a root.
    let intermediates = CertificateStore::from_iter(
        INTERMEDIATES
            .iter()
            .map(|der| parse(der)),
    );

    let native = native_roots();

    // Only the identity check differs between these two — the chain is the
    // same one either way.
    for hostname in ["example.com", "attacker.test"] {
        let roots = CertificateStore::from_iter(native.iter().map(|der| parse(der)));

        let policy = x509_validator::policy! {
            RFC5280Policy::new(now());
            EkuPolicy::server_auth();
            ServerIdentityPolicy::new(Some(hostname), None)
        };

        let validator = Validator::with_policy(roots, policy);

        let verdict = match validator.validate(&leaf, &intermediates) {
            Ok(chain) => format!("accepted — {} certificates", chain.iter().count()),
            Err(failures) if failures.is_empty() => {
                "rejected — no chain reached a trusted root".to_string()
            }
            Err(failures) => format!("rejected — {}", failures[0]),
        };

        println!("{hostname:<16} {verdict}");
    }
}
