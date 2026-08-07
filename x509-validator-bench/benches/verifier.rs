//! The parity benchmark: every validation scenario in one measurement.
//!
//! This mirrors the reference implementation's verifier benchmark, which runs
//! its whole scenario set as a single measured blob rather than as separate
//! benchmarks. The coarseness is deliberate — this is a regression canary, and
//! one number that moves is easier to notice than sixteen that jitter.
//!
//! Unlike the other tiers there is no backend axis, because the reference has
//! none; splitting it three ways would make the comparison meaningless.

use x509_validator::policy::{PolicyEvaluationResult, PolicyFailureReason, VerifierPolicy};
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::verifier::ChainValidationResultOwned;
use x509_validator::BaseVerifier;
use x509_validator_bench::{fixtures, DEFAULT_BACKEND};
use x509_validator_core::der_parser::Oid;
use x509_validator_core::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

fn main() {
    divan::main();
}

/// Rejects any chain containing a specific certificate, so that a scenario can
/// force the search past the shortest path onto a longer one.
struct FailIfCertInChainPolicy {
    forbidden: Vec<u8>,
    inner: RFC5280Policy,
}

impl VerifierPolicy for FailIfCertInChainPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![OID_X509_EXT_BASIC_CONSTRAINTS]
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        if chain.iter().any(|cert| cert.as_ref() == self.forbidden.as_slice()) {
            return Err(PolicyFailureReason::new("chain contains forbidden certificate"));
        }
        self.inner.chain_meets_policy_requirements(chain)
    }
}

/// Accepts every chain, so an outcome is decided purely by chain building.
struct IgnoreBasicConstraintsPolicy;

impl VerifierPolicy for IgnoreBasicConstraintsPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![OID_X509_EXT_BASIC_CONSTRAINTS]
    }

    fn chain_meets_policy_requirements(&mut self, _chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        Ok(())
    }
}

/// Runs one scenario and returns the chain length (or failure count), so no
/// scenario can be optimised away as dead code.
fn run(roots: Vec<x509_validator_core::Certificate<'static>>, intermediates: Vec<x509_validator_core::Certificate<'static>>, leaf: &x509_validator_core::Certificate<'static>) -> usize {
    let mut verifier = BaseVerifier::with_policy_and_backend(
        CertificateStore::from_iter(roots),
        RFC5280Policy::new(fixtures::REFERENCE_TIME),
        DEFAULT_BACKEND.provider,
    );
    match verifier.validate_with_diagnostics(leaf, &CertificateStore::from_iter(intermediates), &mut |_| {}) {
        ChainValidationResultOwned::ValidCertificate(chain) => chain.iter().count(),
        ChainValidationResultOwned::CouldNotValidate(reasons) => reasons.len(),
    }
}

/// All sixteen scenarios, measured together.
#[divan::bench]
fn verifier(bencher: divan::Bencher) {
    let p = fixtures::parity();

    bencher.bench(|| {
        let mut count = 0usize;

        // --- successful validations (12) ---

        // trivial chain building
        count += run(vec![p.ca1.clone()], vec![p.intermediate1.clone()], &p.localhost_leaf);
        // extra roots are ignored
        count += run(vec![p.ca1.clone(), p.ca2.clone()], vec![p.intermediate1.clone()], &p.localhost_leaf);
        // roots in the intermediate store are not a problem
        count += run(
            vec![p.ca1.clone(), p.ca2.clone()],
            vec![p.intermediate1.clone(), p.ca1.clone(), p.ca2.clone()],
            &p.localhost_leaf,
        );
        // cross-signed root
        count += run(
            vec![p.ca2.clone()],
            vec![p.intermediate1.clone(), p.ca1_cross_signed_by_ca2.clone()],
            &p.localhost_leaf,
        );
        // builds the shorter path when both cross-signed roots are present
        count += run(
            vec![p.ca1.clone(), p.ca2.clone()],
            vec![
                p.intermediate1.clone(),
                p.ca2_cross_signed_by_ca1.clone(),
                p.ca1_cross_signed_by_ca2.clone(),
            ],
            &p.localhost_leaf,
        );
        // prefers an intermediate whose SKI matches
        count += run(
            vec![p.ca1.clone()],
            vec![p.intermediate1.clone(), p.intermediate1_without_ski_aki.clone()],
            &p.localhost_leaf,
        );
        // prefers no SKI over a non-matching one
        count += run(
            vec![p.ca1.clone()],
            vec![
                p.intermediate1_with_incorrect_ski_aki.clone(),
                p.intermediate1_without_ski_aki.clone(),
            ],
            &p.localhost_leaf,
        );
        // rejects a root that did not sign the certificate below it
        count += run(
            vec![p.ca1_with_alternative_private_key.clone(), p.ca2.clone()],
            vec![
                p.ca1_cross_signed_by_ca2.clone(),
                p.ca2_cross_signed_by_ca1.clone(),
                p.intermediate1.clone(),
            ],
            &p.localhost_leaf,
        );
        // a policy failure sends the search down a longer path
        {
            let mut verifier = BaseVerifier::with_policy_and_backend(
                CertificateStore::from_iter(vec![p.ca1.clone(), p.ca2.clone()]),
                FailIfCertInChainPolicy {
                    forbidden: p.ca1.as_ref().to_vec(),
                    inner: RFC5280Policy::new(fixtures::REFERENCE_TIME),
                },
                DEFAULT_BACKEND.provider,
            );
            let intermediates = CertificateStore::from_iter(vec![
                p.intermediate1.clone(),
                p.ca2_cross_signed_by_ca1.clone(),
                p.ca1_cross_signed_by_ca2.clone(),
            ]);
            count += match verifier.validate_with_diagnostics(&p.localhost_leaf, &intermediates, &mut |_| {}) {
                ChainValidationResultOwned::ValidCertificate(chain) => chain.iter().count(),
                ChainValidationResultOwned::CouldNotValidate(reasons) => reasons.len(),
            };
        }
        // a self-signed certificate in the trust store validates
        count += run(
            vec![p.ca1.clone(), p.isolated_self_signed.clone()],
            vec![p.intermediate1.clone()],
            &p.isolated_self_signed,
        );
        // a trust root may be a non-self-signed leaf
        {
            let mut verifier = BaseVerifier::with_policy_and_backend(
                CertificateStore::from_iter(vec![p.localhost_leaf.clone()]),
                IgnoreBasicConstraintsPolicy,
                DEFAULT_BACKEND.provider,
            );
            let intermediates = CertificateStore::from_iter(vec![p.intermediate1.clone()]);
            count += match verifier.validate_with_diagnostics(&p.localhost_leaf, &intermediates, &mut |_| {}) {
                ChainValidationResultOwned::ValidCertificate(chain) => chain.iter().count(),
                ChainValidationResultOwned::CouldNotValidate(reasons) => reasons.len(),
            };
        }
        // a trust root may be a non-self-signed intermediate
        count += run(vec![p.intermediate1.clone()], vec![p.intermediate1.clone()], &p.localhost_leaf);

        // --- unsuccessful validations (4) ---

        // an unhandled critical extension on the leaf is policed
        count += run(
            vec![p.ca1.clone(), p.isolated_self_signed_weird_critical.clone()],
            vec![p.intermediate1.clone()],
            &p.isolated_self_signed_weird_critical,
        );
        // a missing intermediate cannot build
        count += run(vec![p.ca1.clone()], vec![], &p.localhost_leaf);
        // a self-signed certificate outside the trust store is rejected
        count += run(vec![p.ca1.clone()], vec![p.intermediate1.clone()], &p.isolated_self_signed);
        // a missing root cannot build
        count += run(vec![], vec![p.intermediate1.clone()], &p.localhost_leaf);

        divan::black_box(count)
    });
}
