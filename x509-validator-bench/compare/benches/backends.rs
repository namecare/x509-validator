//! End-to-end chain validation, per backend.
//!
//! The number a user actually experiences, and the counterpart to the atomic
//! crypto tier: comparing the two shows what fraction of real validation time
//! is signature verification rather than parsing and policy evaluation.

use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::validator::ChainValidationResultOwned;
use x509_validator::BaseValidator;
use x509_validator_bench_compare::{fixtures, Backend, BACKENDS};

fn main() {
    divan::main();
}

/// leaf → intermediate → root, the common case.
#[divan::bench(args = BACKENDS)]
fn validate_three_cert_chain(bencher: divan::Bencher, backend: Backend) {
    let parity = fixtures::parity();

    // Confirm the chain actually validates before timing anything: if this
    // silently failed, the benchmark below would measure the (much cheaper)
    // error path and every number would be meaningless.
    let roots = CertificateStore::from_iter(vec![parity.ca1.clone()]);
    let intermediates = CertificateStore::from_iter(vec![parity.intermediate1.clone()]);
    let mut validator = BaseValidator::with_policy_and_backend(roots, RFC5280Policy::new(fixtures::REFERENCE_TIME), backend.provider);
    let result = validator.validate_with_diagnostics(&parity.localhost_leaf, &intermediates, &mut |_| {});
    assert!(
        matches!(result, ChainValidationResultOwned::ValidCertificate(_)),
        "three-cert chain must validate successfully for {}, but validation failed",
        backend.name,
    );

    bencher
        .with_inputs(|| {
            // Cloned fresh every iteration so each run validates against a
            // fully populated root store; `CertificateStore` is `Clone`, and
            // the clone happens outside the timed region.
            let roots = CertificateStore::from_iter(vec![parity.ca1.clone()]);
            let intermediates = CertificateStore::from_iter(vec![parity.intermediate1.clone()]);
            (roots, intermediates)
        })
        .bench_values(|(roots, intermediates)| {
            let mut validator = BaseValidator::with_policy_and_backend(roots, RFC5280Policy::new(fixtures::REFERENCE_TIME), backend.provider);
            divan::black_box(validator.validate_with_diagnostics(divan::black_box(&parity.localhost_leaf), &intermediates, &mut |_| {}))
        });
}

/// A real, publicly-issued chain: Apple's receipt-signing leaf → WWDR G6 →
/// Apple Root CA - G3, validated at the `signedDate` of a payload these
/// certificates actually signed.
///
/// Both verifications in this chain are ECDSA-P384, where the spread between
/// backends is widest — so this is the pessimistic real-world case, not the
/// average one. It also parses real certificates, which carry policy OIDs and
/// CRL/OCSP pointers the generated fixtures do not.
#[divan::bench(args = BACKENDS)]
fn validate_apple_receipt_chain(bencher: divan::Bencher, backend: Backend) {
    let chain = fixtures::apple::chain();

    let roots = CertificateStore::from_iter(vec![chain.root.clone()]);
    let intermediates = CertificateStore::from_iter(vec![chain.intermediate.clone()]);
    let mut validator = BaseValidator::with_policy_and_backend(roots, RFC5280Policy::new(fixtures::apple::SIGNED_DATE), backend.provider);
    let result = validator.validate_with_diagnostics(&chain.leaf, &intermediates, &mut |_| {});
    assert!(
        matches!(result, ChainValidationResultOwned::ValidCertificate(_)),
        "the Apple receipt chain must validate successfully for {}, but validation failed",
        backend.name,
    );

    bencher
        .with_inputs(|| {
            let roots = CertificateStore::from_iter(vec![chain.root.clone()]);
            let intermediates = CertificateStore::from_iter(vec![chain.intermediate.clone()]);
            (roots, intermediates)
        })
        .bench_values(|(roots, intermediates)| {
            let mut validator = BaseValidator::with_policy_and_backend(roots, RFC5280Policy::new(fixtures::apple::SIGNED_DATE), backend.provider);
            divan::black_box(validator.validate_with_diagnostics(divan::black_box(&chain.leaf), &intermediates, &mut |_| {}))
        });
}

/// The same chain where the intermediate store also holds decoys that must be
/// rejected — the cost of issuer search rather than the happy path alone.
#[divan::bench(args = BACKENDS)]
fn validate_with_cross_signed_candidates(bencher: divan::Bencher, backend: Backend) {
    let parity = fixtures::parity();

    let roots = CertificateStore::from_iter(vec![parity.ca1.clone(), parity.ca2.clone()]);
    let intermediates = CertificateStore::from_iter(vec![
        parity.intermediate1.clone(),
        parity.ca1_cross_signed_by_ca2.clone(),
        parity.ca2_cross_signed_by_ca1.clone(),
    ]);
    let mut validator = BaseValidator::with_policy_and_backend(roots, RFC5280Policy::new(fixtures::REFERENCE_TIME), backend.provider);
    let result = validator.validate_with_diagnostics(&parity.localhost_leaf, &intermediates, &mut |_| {});
    assert!(
        matches!(result, ChainValidationResultOwned::ValidCertificate(_)),
        "chain with cross-signed decoys must validate successfully for {}, but validation failed",
        backend.name,
    );

    bencher
        .with_inputs(|| {
            let roots = CertificateStore::from_iter(vec![parity.ca1.clone(), parity.ca2.clone()]);
            let intermediates = CertificateStore::from_iter(vec![
                parity.intermediate1.clone(),
                parity.ca1_cross_signed_by_ca2.clone(),
                parity.ca2_cross_signed_by_ca1.clone(),
            ]);
            (roots, intermediates)
        })
        .bench_values(|(roots, intermediates)| {
            let mut validator = BaseValidator::with_policy_and_backend(roots, RFC5280Policy::new(fixtures::REFERENCE_TIME), backend.provider);
            divan::black_box(validator.validate_with_diagnostics(divan::black_box(&parity.localhost_leaf), &intermediates, &mut |_| {}))
        });
}
