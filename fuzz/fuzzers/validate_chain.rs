#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use x509_validator::crypto::{CryptoError, SignatureVerifier};
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::{
    AlgorithmIdentifier, Certificate, CertificateExt, SubjectPublicKeyInfo, Validator,
};

#[derive(Debug)]
struct AcceptEverySignature;

impl SignatureVerifier for AcceptEverySignature {
    fn verify_signature(
        &self,
        _algorithm: &AlgorithmIdentifier<'_>,
        _public_key: &SubjectPublicKeyInfo<'_>,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, data)) = data.split_first() else {
        return;
    };

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

    let policy = RFC5280Policy::new(1_760_000_000);

    let stub = AcceptEverySignature;
    let crypto: &dyn SignatureVerifier = if selector & 1 == 0 {
        &stub
    } else {
        x509_validator::crypto::default_provider()
    };

    let validator = Validator::with_policy_and_backend(roots, policy, crypto);

    let _ = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
});
