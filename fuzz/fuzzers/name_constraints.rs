#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate x509_validator;

mod common;

use x509_validator::rfc5280::NameConstraintsPolicy;
use x509_validator::unverified_chain::UnverifiedCertificateChain;
use x509_validator::{Certificate, CertificateExt, ValidationPolicy};

fuzz_target!(|data: &[u8]| {
    let certs: Vec<Certificate<'_>> = common::frames(data, 6)
        .iter()
        .filter_map(|der| Certificate::parse(der).ok())
        .collect();

    if certs.is_empty() {
        return;
    }

    let chain = UnverifiedCertificateChain::new(certs);

    let _ = NameConstraintsPolicy.chain_meets_policy_requirements(&chain);
});
