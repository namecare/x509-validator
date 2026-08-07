//! The parity benchmark: every validation scenario from the reference
//! implementation's verifier benchmark, case for case.
//!
//! The reference runs its whole scenario set as a single measured blob. That
//! is a fine canary but a poor gate — sixteen scenarios summed into one
//! number tell you something moved without telling you what. So each
//! scenario is its own benchmark here, and the blob is kept as one extra
//! rollup (`verifier/all_scenarios`) so the reference number stays
//! comparable.
//!
//! Benchmark ids are the tracked metric names. **Renaming one starts a new
//! metric with no history**, so treat the strings below as fixed.
//!
//! Scenario outcomes are asserted in `tests/verifier_scenarios.rs`, not here:
//! this file has `harness = false`, so an in-file `#[test]` fn would never
//! run. A scenario that quietly produces the wrong result still benchmarks
//! something — just not the thing it is named after.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use x509_validator::policy::{PolicyEvaluationResult, PolicyFailureReason, VerifierPolicy};
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::verifier::ChainValidationResultOwned;
use x509_validator::BaseVerifier;
use x509_validator_bench_measure::{fixtures, BACKEND};
use x509_validator_core::der_parser::Oid;
use x509_validator_core::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use x509_validator_core::Certificate;

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

/// One scenario: the roots and intermediates to build the stores from, and
/// the leaf to validate.
struct Scenario {
    roots: Vec<Certificate<'static>>,
    intermediates: Vec<Certificate<'static>>,
    leaf: &'static Certificate<'static>,
}

/// Validates `leaf` against freshly built stores, returning the chain length
/// (or failure count) so nothing can be optimised away as dead code.
///
/// The stores are passed in rather than built here: `CertificateStore::from_iter`
/// allocates a `HashMap` and a subject key per certificate, which is setup
/// cost, not validation cost, and does not belong in the timed region.
fn validate(roots: CertificateStore<'static>, intermediates: &CertificateStore<'static>, leaf: &Certificate<'static>) -> usize {
    let mut verifier = BaseVerifier::with_policy_and_backend(roots, RFC5280Policy::new(fixtures::REFERENCE_TIME), BACKEND);
    match verifier.validate_with_diagnostics(leaf, intermediates, &mut |_| {}) {
        ChainValidationResultOwned::ValidCertificate(chain) => chain.iter().count(),
        ChainValidationResultOwned::CouldNotValidate(reasons) => reasons.len(),
    }
}

/// Registers one scenario as its own benchmark, with store construction in
/// the setup phase so only validation is measured.
fn bench_scenario(c: &mut Criterion, id: &str, scenario: impl Fn() -> Scenario) {
    c.bench_function(id, |b| {
        b.iter_batched(
            || {
                let s = scenario();
                (
                    CertificateStore::from_iter(s.roots),
                    CertificateStore::from_iter(s.intermediates),
                    s.leaf,
                )
            },
            |(roots, intermediates, leaf)| validate(roots, &intermediates, leaf),
            BatchSize::SmallInput,
        )
    });
}

// --- successful validations (12) ---

fn successful(c: &mut Criterion) {
    let p = fixtures::parity();

    bench_scenario(c, "verifier/trivial_chain_building", || Scenario {
        roots: vec![p.ca1.clone()],
        intermediates: vec![p.intermediate1.clone()],
        leaf: &p.localhost_leaf,
    });

    bench_scenario(c, "verifier/extra_roots_are_ignored", || Scenario {
        roots: vec![p.ca1.clone(), p.ca2.clone()],
        intermediates: vec![p.intermediate1.clone()],
        leaf: &p.localhost_leaf,
    });

    bench_scenario(c, "verifier/roots_in_intermediate_store_are_not_a_problem", || Scenario {
        roots: vec![p.ca1.clone(), p.ca2.clone()],
        intermediates: vec![p.intermediate1.clone(), p.ca1.clone(), p.ca2.clone()],
        leaf: &p.localhost_leaf,
    });

    bench_scenario(c, "verifier/cross_signed_root", || Scenario {
        roots: vec![p.ca2.clone()],
        intermediates: vec![p.intermediate1.clone(), p.ca1_cross_signed_by_ca2.clone()],
        leaf: &p.localhost_leaf,
    });

    bench_scenario(c, "verifier/builds_shorter_path_when_both_cross_signed_roots_present", || Scenario {
        roots: vec![p.ca1.clone(), p.ca2.clone()],
        intermediates: vec![
            p.intermediate1.clone(),
            p.ca2_cross_signed_by_ca1.clone(),
            p.ca1_cross_signed_by_ca2.clone(),
        ],
        leaf: &p.localhost_leaf,
    });

    bench_scenario(c, "verifier/prefers_intermediate_whose_ski_matches", || Scenario {
        roots: vec![p.ca1.clone()],
        intermediates: vec![p.intermediate1.clone(), p.intermediate1_without_ski_aki.clone()],
        leaf: &p.localhost_leaf,
    });

    bench_scenario(c, "verifier/prefers_no_ski_over_non_matching_ski", || Scenario {
        roots: vec![p.ca1.clone()],
        intermediates: vec![
            p.intermediate1_with_incorrect_ski_aki.clone(),
            p.intermediate1_without_ski_aki.clone(),
        ],
        leaf: &p.localhost_leaf,
    });

    bench_scenario(c, "verifier/rejects_root_that_did_not_sign", || Scenario {
        roots: vec![p.ca1_with_alternative_private_key.clone(), p.ca2.clone()],
        intermediates: vec![
            p.ca1_cross_signed_by_ca2.clone(),
            p.ca2_cross_signed_by_ca1.clone(),
            p.intermediate1.clone(),
        ],
        leaf: &p.localhost_leaf,
    });

    // Uses a custom policy, so it cannot go through `bench_scenario`.
    c.bench_function("verifier/policy_failure_sends_search_down_longer_path", |b| {
        b.iter_batched(
            || {
                (
                    CertificateStore::from_iter(vec![p.ca1.clone(), p.ca2.clone()]),
                    CertificateStore::from_iter(vec![
                        p.intermediate1.clone(),
                        p.ca2_cross_signed_by_ca1.clone(),
                        p.ca1_cross_signed_by_ca2.clone(),
                    ]),
                )
            },
            |(roots, intermediates)| {
                let mut verifier = BaseVerifier::with_policy_and_backend(
                    roots,
                    FailIfCertInChainPolicy {
                        forbidden: p.ca1.as_ref().to_vec(),
                        inner: RFC5280Policy::new(fixtures::REFERENCE_TIME),
                    },
                    BACKEND,
                );
                match verifier.validate_with_diagnostics(&p.localhost_leaf, &intermediates, &mut |_| {}) {
                    ChainValidationResultOwned::ValidCertificate(chain) => chain.iter().count(),
                    ChainValidationResultOwned::CouldNotValidate(reasons) => reasons.len(),
                }
            },
            BatchSize::SmallInput,
        )
    });

    bench_scenario(c, "verifier/self_signed_certificate_in_trust_store_validates", || Scenario {
        roots: vec![p.ca1.clone(), p.isolated_self_signed.clone()],
        intermediates: vec![p.intermediate1.clone()],
        leaf: &p.isolated_self_signed,
    });

    // Also a custom policy: the trust root is a leaf whose basic constraints
    // would otherwise disqualify it.
    c.bench_function("verifier/trust_root_may_be_non_self_signed_leaf", |b| {
        b.iter_batched(
            || {
                (
                    CertificateStore::from_iter(vec![p.localhost_leaf.clone()]),
                    CertificateStore::from_iter(vec![p.intermediate1.clone()]),
                )
            },
            |(roots, intermediates)| {
                let mut verifier = BaseVerifier::with_policy_and_backend(roots, IgnoreBasicConstraintsPolicy, BACKEND);
                match verifier.validate_with_diagnostics(&p.localhost_leaf, &intermediates, &mut |_| {}) {
                    ChainValidationResultOwned::ValidCertificate(chain) => chain.iter().count(),
                    ChainValidationResultOwned::CouldNotValidate(reasons) => reasons.len(),
                }
            },
            BatchSize::SmallInput,
        )
    });

    bench_scenario(c, "verifier/trust_root_may_be_non_self_signed_intermediate", || Scenario {
        roots: vec![p.intermediate1.clone()],
        intermediates: vec![p.intermediate1.clone()],
        leaf: &p.localhost_leaf,
    });
}

// --- unsuccessful validations (4) ---

fn unsuccessful(c: &mut Criterion) {
    let p = fixtures::parity();

    bench_scenario(c, "verifier/unhandled_critical_extension_on_leaf_is_policed", || Scenario {
        roots: vec![p.ca1.clone(), p.isolated_self_signed_weird_critical.clone()],
        intermediates: vec![p.intermediate1.clone()],
        leaf: &p.isolated_self_signed_weird_critical,
    });

    bench_scenario(c, "verifier/missing_intermediate_cannot_build", || Scenario {
        roots: vec![p.ca1.clone()],
        intermediates: vec![],
        leaf: &p.localhost_leaf,
    });

    bench_scenario(c, "verifier/self_signed_certificate_outside_trust_store_is_rejected", || Scenario {
        roots: vec![p.ca1.clone()],
        intermediates: vec![p.intermediate1.clone()],
        leaf: &p.isolated_self_signed,
    });

    bench_scenario(c, "verifier/missing_root_cannot_build", || Scenario {
        roots: vec![],
        intermediates: vec![p.intermediate1.clone()],
        leaf: &p.localhost_leaf,
    });
}

/// All sixteen scenarios in one measurement, as the reference implementation
/// runs them. Kept so that number stays comparable; the per-scenario
/// benchmarks above are what actually localises a regression.
fn all_scenarios(c: &mut Criterion) {
    let p = fixtures::parity();

    c.bench_function("verifier/all_scenarios", |b| {
        b.iter(|| {
            let mut count = 0usize;
            let stores = |roots: Vec<Certificate<'static>>, intermediates: Vec<Certificate<'static>>| {
                (CertificateStore::from_iter(roots), CertificateStore::from_iter(intermediates))
            };

            // successful (12)
            let (r, i) = stores(vec![p.ca1.clone()], vec![p.intermediate1.clone()]);
            count += validate(r, &i, &p.localhost_leaf);
            let (r, i) = stores(vec![p.ca1.clone(), p.ca2.clone()], vec![p.intermediate1.clone()]);
            count += validate(r, &i, &p.localhost_leaf);
            let (r, i) = stores(
                vec![p.ca1.clone(), p.ca2.clone()],
                vec![p.intermediate1.clone(), p.ca1.clone(), p.ca2.clone()],
            );
            count += validate(r, &i, &p.localhost_leaf);
            let (r, i) = stores(
                vec![p.ca2.clone()],
                vec![p.intermediate1.clone(), p.ca1_cross_signed_by_ca2.clone()],
            );
            count += validate(r, &i, &p.localhost_leaf);
            let (r, i) = stores(
                vec![p.ca1.clone(), p.ca2.clone()],
                vec![
                    p.intermediate1.clone(),
                    p.ca2_cross_signed_by_ca1.clone(),
                    p.ca1_cross_signed_by_ca2.clone(),
                ],
            );
            count += validate(r, &i, &p.localhost_leaf);
            let (r, i) = stores(
                vec![p.ca1.clone()],
                vec![p.intermediate1.clone(), p.intermediate1_without_ski_aki.clone()],
            );
            count += validate(r, &i, &p.localhost_leaf);
            let (r, i) = stores(
                vec![p.ca1.clone()],
                vec![
                    p.intermediate1_with_incorrect_ski_aki.clone(),
                    p.intermediate1_without_ski_aki.clone(),
                ],
            );
            count += validate(r, &i, &p.localhost_leaf);
            let (r, i) = stores(
                vec![p.ca1_with_alternative_private_key.clone(), p.ca2.clone()],
                vec![
                    p.ca1_cross_signed_by_ca2.clone(),
                    p.ca2_cross_signed_by_ca1.clone(),
                    p.intermediate1.clone(),
                ],
            );
            count += validate(r, &i, &p.localhost_leaf);
            {
                let (roots, intermediates) = stores(
                    vec![p.ca1.clone(), p.ca2.clone()],
                    vec![
                        p.intermediate1.clone(),
                        p.ca2_cross_signed_by_ca1.clone(),
                        p.ca1_cross_signed_by_ca2.clone(),
                    ],
                );
                let mut verifier = BaseVerifier::with_policy_and_backend(
                    roots,
                    FailIfCertInChainPolicy {
                        forbidden: p.ca1.as_ref().to_vec(),
                        inner: RFC5280Policy::new(fixtures::REFERENCE_TIME),
                    },
                    BACKEND,
                );
                count += match verifier.validate_with_diagnostics(&p.localhost_leaf, &intermediates, &mut |_| {}) {
                    ChainValidationResultOwned::ValidCertificate(chain) => chain.iter().count(),
                    ChainValidationResultOwned::CouldNotValidate(reasons) => reasons.len(),
                };
            }
            let (r, i) = stores(
                vec![p.ca1.clone(), p.isolated_self_signed.clone()],
                vec![p.intermediate1.clone()],
            );
            count += validate(r, &i, &p.isolated_self_signed);
            {
                let (roots, intermediates) = stores(vec![p.localhost_leaf.clone()], vec![p.intermediate1.clone()]);
                let mut verifier = BaseVerifier::with_policy_and_backend(roots, IgnoreBasicConstraintsPolicy, BACKEND);
                count += match verifier.validate_with_diagnostics(&p.localhost_leaf, &intermediates, &mut |_| {}) {
                    ChainValidationResultOwned::ValidCertificate(chain) => chain.iter().count(),
                    ChainValidationResultOwned::CouldNotValidate(reasons) => reasons.len(),
                };
            }
            let (r, i) = stores(vec![p.intermediate1.clone()], vec![p.intermediate1.clone()]);
            count += validate(r, &i, &p.localhost_leaf);

            // unsuccessful (4)
            let (r, i) = stores(
                vec![p.ca1.clone(), p.isolated_self_signed_weird_critical.clone()],
                vec![p.intermediate1.clone()],
            );
            count += validate(r, &i, &p.isolated_self_signed_weird_critical);
            let (r, i) = stores(vec![p.ca1.clone()], vec![]);
            count += validate(r, &i, &p.localhost_leaf);
            let (r, i) = stores(vec![p.ca1.clone()], vec![p.intermediate1.clone()]);
            count += validate(r, &i, &p.isolated_self_signed);
            let (r, i) = stores(vec![], vec![p.intermediate1.clone()]);
            count += validate(r, &i, &p.localhost_leaf);

            count
        })
    });
}

criterion_group!(benches, successful, unsuccessful, all_scenarios);
criterion_main!(benches);
