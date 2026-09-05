#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate x509_validator;

mod common;

use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::{Certificate, CertificateExt, Validator};

const VALIDATION_TIME: i64 = 1_760_000_000;

fuzz_target!(|data: &[u8]| {
    let frames = common::frames(data, 8);
    let Some((leaf_der, rest)) = frames.split_first() else {
        return;
    };

    let Ok(leaf) = Certificate::parse(leaf_der) else {
        return;
    };

    let parsed: Vec<Certificate<'_>> = rest
        .iter()
        .filter_map(|der| Certificate::parse(der).ok())
        .collect();

    let roots: CertificateStore<'_> = parsed.iter().cloned().collect();
    let intermediates: CertificateStore<'_> = parsed.into_iter().collect();

    let validator = Validator::with_policy_and_backend(
        roots,
        RFC5280Policy::new(VALIDATION_TIME),
        &x509_validator_fuzzing_provider::PROVIDER,
    );

    let _ = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
});
