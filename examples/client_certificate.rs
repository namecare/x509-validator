//! Checking a client certificate, the way a server does in mutual TLS.
//!
//! The chain rules are the same as for a server certificate, but the key
//! purpose is clientAuth rather than serverAuth, and there is no hostname to
//! check: the caller's identity is the subject of the certificate, which the
//! server reads once the chain has been accepted.
//!
//!     cargo run -p x509-validator-examples --example client_certificate

use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use x509_validator::rfc5280::{EkuPolicy, RFC5280Policy};
use x509_validator::store::CertificateStore;
use x509_validator::{Certificate, CertificateExt, Validator};

fn parse(der: &[u8]) -> Certificate<'_> {
    Certificate::parse(der).expect("certificate parses")
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_secs() as i64
}

/// The CA that issues client credentials, as DER.
fn client_ca() -> (CertificateParams, KeyPair, Vec<u8>) {
    let mut params = CertificateParams::new(vec![]).expect("CA parameters");
    params
        .distinguished_name
        .push(DnType::CommonName, "Example Corp Client CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let key = KeyPair::generate().expect("CA key");
    let der = params
        .self_signed(&key)
        .expect("self-signed CA")
        .der()
        .to_vec();

    (params, key, der)
}

/// A credential for `common_name`, carrying `purpose`.
fn issue_client(
    common_name: &str,
    purpose: ExtendedKeyUsagePurpose,
    ca_params: &CertificateParams,
    ca_key: &KeyPair,
) -> Vec<u8> {
    let mut params = CertificateParams::new(vec![]).expect("client parameters");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.extended_key_usages = vec![purpose];

    let key = KeyPair::generate().expect("client key");
    params
        .signed_by(&key, &Issuer::from_params(ca_params, ca_key))
        .expect("issued client certificate")
        .der()
        .to_vec()
}

fn main() {
    let (ca_params, ca_key, ca_der) = client_ca();

    // The second certificate is a well-formed credential from the same CA,
    // but issued for authenticating a server. Presented by a client it must
    // be refused, which is the whole job of the key purpose check.
    let credentials = [
        (
            "clientAuth",
            issue_client(
                "alice@example.com",
                ExtendedKeyUsagePurpose::ClientAuth,
                &ca_params,
                &ca_key,
            ),
        ),
        (
            "serverAuth",
            issue_client(
                "service.internal",
                ExtendedKeyUsagePurpose::ServerAuth,
                &ca_params,
                &ca_key,
            ),
        ),
    ];

    for (purpose, der) in &credentials {
        let client = parse(der);
        let roots = CertificateStore::from_iter([parse(&ca_der)]);

        let policy = x509_validator::policy! {
            RFC5280Policy::new(now());
            EkuPolicy::client_auth()
        };

        let validator = Validator::with_policy(roots, policy);

        match validator.validate(&client, &CertificateStore::new()) {
            Ok(chain) => println!(
                "{purpose:<12} accepted — caller is {}",
                chain.leaf().tbs_certificate.subject
            ),
            Err(failures) if failures.is_empty() => {
                println!("{purpose:<12} rejected — no chain reached a trusted root");
            }
            // The reason names the offending certificate in full; the last
            // clause is the part worth showing.
            Err(failures) => {
                let reason = failures[0].to_string();
                let summary = match reason.rsplit_once("} ") {
                    Some((_, tail)) => tail,
                    None => &reason,
                };
                println!("{purpose:<12} rejected — {summary}");
            }
        }
    }
}
