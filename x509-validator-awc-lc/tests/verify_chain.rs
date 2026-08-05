use x509_parser::prelude::FromDer;
use x509_validator_awc_lc::Verifier;
use x509_validator_core::{ChainValidationResult, Verifier as _};

macro_rules! fixture {
    ($path:literal) => {
        include_bytes!(concat!("resources/", $path))
    };
}

#[test]
fn validates_digicert_rsa_chain() {
    let root = fixture!("root.der");
    let intermediate = fixture!("intermediate.der");
    let leaf = fixture!("leaf.der");

    let (_, root_cert) = x509_parser::certificate::X509Certificate::from_der(root).unwrap();
    let roots = [root_cert];
    let verifier = Verifier::new(&roots);
    let intermediates: [&[u8]; 1] = [intermediate.as_slice()];

    let result = verifier.validate_raw(leaf, &intermediates);

    match result {
        ChainValidationResult::ValidCertificate(chain) => {
            assert_eq!(chain.iter().count(), 3);
        }
        ChainValidationResult::CouldNotValidate(failure) => {
            panic!("expected valid chain, got failure: {}", failure.policy_failure_reason);
        }
    }
}

#[test]
fn validates_apple_ecdsa_chain() {
    let root = fixture!("apple/root.der");
    let intermediate = fixture!("apple/intermediate.der");
    let leaf = fixture!("apple/leaf.der");

    let (_, root_cert) = x509_parser::certificate::X509Certificate::from_der(root).unwrap();
    let roots = [root_cert];
    let verifier = Verifier::new(&roots);
    let intermediates: [&[u8]; 1] = [intermediate.as_slice()];

    let result = verifier.validate_raw(leaf, &intermediates);

    match result {
        ChainValidationResult::ValidCertificate(chain) => {
            assert_eq!(chain.iter().count(), 3);
        }
        ChainValidationResult::CouldNotValidate(failure) => {
            panic!("expected valid chain, got failure: {}", failure.policy_failure_reason);
        }
    }
}

#[test]
fn rejects_chain_with_untrusted_root() {
    // DigiCert leaf/intermediate against the Apple root: same shape of
    // chain, but no matching issuer, so the walk must fail to find a
    // trusted root.
    let root = fixture!("apple/root.der");
    let intermediate = fixture!("intermediate.der");
    let leaf = fixture!("leaf.der");

    let (_, root_cert) = x509_parser::certificate::X509Certificate::from_der(root).unwrap();
    let roots = [root_cert];
    let verifier = Verifier::new(&roots);
    let intermediates: [&[u8]; 1] = [intermediate.as_slice()];

    let result = verifier.validate_raw(leaf, &intermediates);

    assert!(matches!(result, ChainValidationResult::CouldNotValidate(_)));
}

#[test]
fn rejects_tampered_leaf_signature() {
    let root = fixture!("root.der");
    let intermediate = fixture!("intermediate.der");
    let mut leaf = fixture!("leaf.der").to_vec();

    // Flip a byte inside the signature value at the tail of the DER
    // encoding, invalidating the leaf's signature without touching its
    // structure enough to fail parsing.
    let last = leaf.len() - 1;
    leaf[last] ^= 0xFF;

    let (_, root_cert) = x509_parser::certificate::X509Certificate::from_der(root).unwrap();
    let roots = [root_cert];
    let verifier = Verifier::new(&roots);
    let intermediates: [&[u8]; 1] = [intermediate.as_slice()];

    let result = verifier.validate_raw(&leaf, &intermediates);

    assert!(matches!(result, ChainValidationResult::CouldNotValidate(_)));
}

#[test]
fn with_raw_certificates_accepts_concatenated_der_roots() {
    let root = fixture!("root.der");
    let intermediate = fixture!("intermediate.der");
    let leaf = fixture!("leaf.der");

    let verifier = Verifier::with_raw_certificates(root);
    let intermediates: [&[u8]; 1] = [intermediate.as_slice()];

    let result = verifier.validate_raw(leaf, &intermediates);

    assert!(matches!(result, ChainValidationResult::ValidCertificate(_)));
}
