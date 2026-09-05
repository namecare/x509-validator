#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate x509_validator;

mod common;

use x509_validator::unverified_chain::UnverifiedCertificateChain;
use x509_validator::{Certificate, CertificateExt, ServerIdentityPolicy, ValidationPolicy};

fuzz_target!(|data: &[u8]| {
    let frames = common::frames(data, 3);
    let [cert_der, hostname, ip] = frames.as_slice() else {
        return;
    };

    let Ok(cert) = Certificate::parse(cert_der) else {
        return;
    };

    let (Ok(hostname), Ok(ip)) = (str::from_utf8(hostname), str::from_utf8(ip)) else {
        return;
    };

    let policy = ServerIdentityPolicy::new(Some(hostname), Some(ip));
    let chain = UnverifiedCertificateChain::new(vec![cert]);

    let _ = policy.chain_meets_policy_requirements(&chain);
});
