//! Finding out why a chain was rejected.
//!
//! A rejection on its own says little: an empty failure list means no
//! candidate chain ever reached a trusted root, so no policy was ever
//! consulted. The diagnostic callback reports each step of the search —
//! every issuer considered and every candidate discarded — which is what
//! tells you whether the problem is a missing intermediate, the wrong root,
//! or a policy that refused a chain that was otherwise fine.
//!
//! The chain here is valid; the trust store simply holds an unrelated root.
//!
//!     cargo run -p x509-validator-examples --example diagnostics

use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use x509_validator::rfc5280::RFC5280Policy;
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

fn ca(common_name: &str) -> (CertificateParams, KeyPair, Vec<u8>) {
    let mut params = CertificateParams::new(vec![]).expect("CA parameters");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
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

fn main() {
    let (ca_params, ca_key, _ca_der) = ca("Example Issuing CA");
    let (_, _, unrelated_der) = ca("Unrelated Root CA");

    let mut leaf_params =
        CertificateParams::new(vec!["service.example".to_string()]).expect("leaf parameters");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "service.example");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_der = leaf_params
        .signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))
        .expect("issued leaf")
        .der()
        .to_vec();

    let leaf = parse(&leaf_der);

    // The issuing CA is not among the roots, so the search runs out of places
    // to look.
    let roots = CertificateStore::from_iter([parse(&unrelated_der)]);
    let validator = Validator::with_policy(roots, RFC5280Policy::new(now()));

    let mut trace = Vec::new();
    let result =
        validator.validate_with_diagnostics(&leaf, &CertificateStore::new(), &mut |diagnostic| {
            trace.push(diagnostic.to_string())
        });

    println!("{} events:", trace.len());
    for (step, event) in trace.iter().enumerate() {
        println!("  {}. {event}", step + 1);
    }

    match result {
        Ok(chain) => println!("\naccepted — {} certificates", chain.iter().count()),
        Err(failures) if failures.is_empty() => {
            println!("\nrejected — no chain reached a trusted root, so no policy ran")
        }
        Err(failures) => {
            println!("\nrejected:");
            for failure in failures {
                println!("  {failure}");
            }
        }
    }
}
