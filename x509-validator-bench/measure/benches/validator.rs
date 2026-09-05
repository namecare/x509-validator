use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use x509_validator::der_parser::Oid;
use x509_validator::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS;
use x509_validator::policy::{PolicyEvaluationResult, PolicyFailureReason, ValidationPolicy};
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::unverified_chain::UnverifiedCertificateChain;
use x509_validator::{Certificate, Validator};
use x509_validator_bench_measure::{fixtures, BACKEND};

/// Rejects any chain containing a specific certificate, so that a scenario can
/// force the search past the shortest path onto a longer one.
struct FailIfCertInChainPolicy {
    forbidden: Vec<u8>,
    inner: RFC5280Policy,
}

impl ValidationPolicy for FailIfCertInChainPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![OID_X509_EXT_BASIC_CONSTRAINTS]
    }

    fn chain_meets_policy_requirements(
        &self,
        chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        if chain
            .iter()
            .any(|cert| cert.as_ref() == self.forbidden.as_slice())
        {
            return Err(PolicyFailureReason::new(
                "chain contains forbidden certificate",
            ));
        }
        self.inner
            .chain_meets_policy_requirements(chain)
    }
}

/// Accepts every chain, so an outcome is decided purely by chain building.
struct IgnoreBasicConstraintsPolicy;

impl ValidationPolicy for IgnoreBasicConstraintsPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![OID_X509_EXT_BASIC_CONSTRAINTS]
    }

    fn chain_meets_policy_requirements(
        &self,
        _chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        Ok(())
    }
}

/// One scenario: the roots and intermediates to build the stores from, and
/// the leaf to validate.
struct Scenario<'a> {
    roots: Vec<Certificate<'a>>,
    intermediates: Vec<Certificate<'a>>,
    /// Owned rather than borrowed: the fixture parses a fresh certificate on
    /// each access, so there is no long-lived one to point at.
    leaf: Certificate<'a>,
}

/// Validates `leaf` against freshly built stores, returning the chain length
/// (or failure count) so nothing can be optimised away as dead code.
fn validate(
    roots: CertificateStore<'_>,
    intermediates: &CertificateStore<'_>,
    leaf: &Certificate<'_>,
) -> usize {
    let validator = Validator::with_policy_and_backend(
        roots,
        RFC5280Policy::new(fixtures::REFERENCE_TIME),
        BACKEND,
    );
    match validator.validate_with_diagnostics(leaf, intermediates, &mut |_| {}) {
        Ok(chain) => chain.iter().count(),
        Err(reasons) => reasons.len(),
    }
}

/// Registers one scenario as its own benchmark, with store construction in
/// the setup phase so only validation is measured.
fn bench_scenario<'a>(c: &mut Criterion, id: &str, scenario: impl Fn() -> Scenario<'a>) {
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
            |(roots, intermediates, leaf)| validate(roots, &intermediates, &leaf),
            BatchSize::SmallInput,
        )
    });
}

// --- successful validations (12) ---

fn successful(c: &mut Criterion) {
    let p = fixtures::parity();

    bench_scenario(c, "validator/trivial_chain_building", || Scenario {
        roots: vec![p.ca1().clone()],
        intermediates: vec![p.intermediate1().clone()],
        leaf: p.localhost_leaf(),
    });

    bench_scenario(c, "validator/extra_roots_are_ignored", || Scenario {
        roots: vec![p.ca1().clone(), p.ca2().clone()],
        intermediates: vec![p.intermediate1().clone()],
        leaf: p.localhost_leaf(),
    });

    bench_scenario(
        c,
        "validator/roots_in_intermediate_store_are_not_a_problem",
        || Scenario {
            roots: vec![p.ca1().clone(), p.ca2().clone()],
            intermediates: vec![p.intermediate1().clone(), p.ca1().clone(), p.ca2().clone()],
            leaf: p.localhost_leaf(),
        },
    );

    bench_scenario(c, "validator/cross_signed_root", || Scenario {
        roots: vec![p.ca2().clone()],
        intermediates: vec![
            p.intermediate1().clone(),
            p.ca1_cross_signed_by_ca2().clone(),
        ],
        leaf: p.localhost_leaf(),
    });

    bench_scenario(
        c,
        "validator/builds_shorter_path_when_both_cross_signed_roots_present",
        || Scenario {
            roots: vec![p.ca1().clone(), p.ca2().clone()],
            intermediates: vec![
                p.intermediate1().clone(),
                p.ca2_cross_signed_by_ca1().clone(),
                p.ca1_cross_signed_by_ca2().clone(),
            ],
            leaf: p.localhost_leaf(),
        },
    );

    bench_scenario(
        c,
        "validator/prefers_intermediate_whose_ski_matches",
        || Scenario {
            roots: vec![p.ca1().clone()],
            intermediates: vec![
                p.intermediate1().clone(),
                p.intermediate1_without_ski_aki()
                    .clone(),
            ],
            leaf: p.localhost_leaf(),
        },
    );

    bench_scenario(c, "validator/prefers_no_ski_over_non_matching_ski", || {
        Scenario {
            roots: vec![p.ca1().clone()],
            intermediates: vec![
                p.intermediate1_with_incorrect_ski_aki()
                    .clone(),
                p.intermediate1_without_ski_aki()
                    .clone(),
            ],
            leaf: p.localhost_leaf(),
        }
    });

    bench_scenario(c, "validator/rejects_root_that_did_not_sign", || Scenario {
        roots: vec![
            p.ca1_with_alternative_private_key()
                .clone(),
            p.ca2().clone(),
        ],
        intermediates: vec![
            p.ca1_cross_signed_by_ca2().clone(),
            p.ca2_cross_signed_by_ca1().clone(),
            p.intermediate1().clone(),
        ],
        leaf: p.localhost_leaf(),
    });

    // Uses a custom policy, so it cannot go through `bench_scenario`.
    c.bench_function(
        "validator/policy_failure_sends_search_down_longer_path",
        |b| {
            b.iter_batched(
                || {
                    (
                        CertificateStore::from_iter(vec![p.ca1().clone(), p.ca2().clone()]),
                        CertificateStore::from_iter(vec![
                            p.intermediate1().clone(),
                            p.ca2_cross_signed_by_ca1().clone(),
                            p.ca1_cross_signed_by_ca2().clone(),
                        ]),
                    )
                },
                |(roots, intermediates)| {
                    let validator = Validator::with_policy_and_backend(
                        roots,
                        FailIfCertInChainPolicy {
                            forbidden: p.ca1().as_ref().to_vec(),
                            inner: RFC5280Policy::new(fixtures::REFERENCE_TIME),
                        },
                        BACKEND,
                    );
                    match validator.validate_with_diagnostics(
                        &p.localhost_leaf(),
                        &intermediates,
                        &mut |_| {},
                    ) {
                        Ok(chain) => chain.iter().count(),
                        Err(reasons) => reasons.len(),
                    }
                },
                BatchSize::SmallInput,
            )
        },
    );

    bench_scenario(
        c,
        "validator/self_signed_certificate_in_trust_store_validates",
        || Scenario {
            roots: vec![p.ca1().clone(), p.isolated_self_signed().clone()],
            intermediates: vec![p.intermediate1().clone()],
            leaf: p.isolated_self_signed(),
        },
    );

    // Also a custom policy: the trust root is a leaf whose basic constraints
    // would otherwise disqualify it.
    // Parsed outside the timed closure, as above.
    let trust_root_leaf = p.localhost_leaf();
    c.bench_function("validator/trust_root_may_be_non_self_signed_leaf", |b| {
        b.iter_batched(
            || {
                (
                    CertificateStore::from_iter(vec![p.localhost_leaf().clone()]),
                    CertificateStore::from_iter(vec![p.intermediate1().clone()]),
                )
            },
            |(roots, intermediates)| {
                let validator = Validator::with_policy_and_backend(
                    roots,
                    IgnoreBasicConstraintsPolicy,
                    BACKEND,
                );
                match validator.validate_with_diagnostics(
                    &trust_root_leaf,
                    &intermediates,
                    &mut |_| {},
                ) {
                    Ok(chain) => chain.iter().count(),
                    Err(reasons) => reasons.len(),
                }
            },
            BatchSize::SmallInput,
        )
    });

    bench_scenario(
        c,
        "validator/trust_root_may_be_non_self_signed_intermediate",
        || Scenario {
            roots: vec![p.intermediate1().clone()],
            intermediates: vec![p.intermediate1().clone()],
            leaf: p.localhost_leaf(),
        },
    );
}

// --- unsuccessful validations (4) ---

fn unsuccessful(c: &mut Criterion) {
    let p = fixtures::parity();

    bench_scenario(
        c,
        "validator/unhandled_critical_extension_on_leaf_is_policed",
        || Scenario {
            roots: vec![
                p.ca1().clone(),
                p.isolated_self_signed_weird_critical()
                    .clone(),
            ],
            intermediates: vec![p.intermediate1().clone()],
            leaf: p.isolated_self_signed_weird_critical(),
        },
    );

    bench_scenario(c, "validator/missing_intermediate_cannot_build", || {
        Scenario {
            roots: vec![p.ca1().clone()],
            intermediates: vec![],
            leaf: p.localhost_leaf(),
        }
    });

    bench_scenario(
        c,
        "validator/self_signed_certificate_outside_trust_store_is_rejected",
        || Scenario {
            roots: vec![p.ca1().clone()],
            intermediates: vec![p.intermediate1().clone()],
            leaf: p.isolated_self_signed(),
        },
    );

    bench_scenario(c, "validator/missing_root_cannot_build", || Scenario {
        roots: vec![],
        intermediates: vec![p.intermediate1().clone()],
        leaf: p.localhost_leaf(),
    });
}

/// All sixteen scenarios in one measurement, as the reference implementation
/// runs them. Kept so that number stays comparable; the per-scenario
/// benchmarks above are what actually localises a regression.
fn all_scenarios(c: &mut Criterion) {
    let p = fixtures::parity();
    // Parsed once, above the timed closure: the fixture parses its DER on
    // each access, and only validation is being measured.
    let ca1 = p.ca1();
    let ca1_cross_signed_by_ca2 = p.ca1_cross_signed_by_ca2();
    let ca1_with_alternative_private_key = p.ca1_with_alternative_private_key();
    let ca2 = p.ca2();
    let ca2_cross_signed_by_ca1 = p.ca2_cross_signed_by_ca1();
    let intermediate1 = p.intermediate1();
    let intermediate1_with_incorrect_ski_aki = p.intermediate1_with_incorrect_ski_aki();
    let intermediate1_without_ski_aki = p.intermediate1_without_ski_aki();
    let isolated_self_signed = p.isolated_self_signed();
    let isolated_self_signed_weird_critical = p.isolated_self_signed_weird_critical();
    let localhost_leaf = p.localhost_leaf();

    c.bench_function("validator/all_scenarios", |b| {
        b.iter(|| {
            let mut count = 0usize;
            let stores = |roots: Vec<Certificate<'static>>,
                          intermediates: Vec<Certificate<'static>>| {
                (
                    CertificateStore::from_iter(roots),
                    CertificateStore::from_iter(intermediates),
                )
            };

            // successful (12)
            let (r, i) = stores(vec![ca1.clone()], vec![intermediate1.clone()]);
            count += validate(r, &i, &localhost_leaf);
            let (r, i) = stores(vec![ca1.clone(), ca2.clone()], vec![intermediate1.clone()]);
            count += validate(r, &i, &localhost_leaf);
            let (r, i) = stores(
                vec![ca1.clone(), ca2.clone()],
                vec![intermediate1.clone(), ca1.clone(), ca2.clone()],
            );
            count += validate(r, &i, &localhost_leaf);
            let (r, i) = stores(
                vec![ca2.clone()],
                vec![intermediate1.clone(), ca1_cross_signed_by_ca2.clone()],
            );
            count += validate(r, &i, &localhost_leaf);
            let (r, i) = stores(
                vec![ca1.clone(), ca2.clone()],
                vec![
                    intermediate1.clone(),
                    ca2_cross_signed_by_ca1.clone(),
                    ca1_cross_signed_by_ca2.clone(),
                ],
            );
            count += validate(r, &i, &localhost_leaf);
            let (r, i) = stores(
                vec![ca1.clone()],
                vec![intermediate1.clone(), intermediate1_without_ski_aki.clone()],
            );
            count += validate(r, &i, &localhost_leaf);
            let (r, i) = stores(
                vec![ca1.clone()],
                vec![
                    intermediate1_with_incorrect_ski_aki.clone(),
                    intermediate1_without_ski_aki.clone(),
                ],
            );
            count += validate(r, &i, &localhost_leaf);
            let (r, i) = stores(
                vec![ca1_with_alternative_private_key.clone(), ca2.clone()],
                vec![
                    ca1_cross_signed_by_ca2.clone(),
                    ca2_cross_signed_by_ca1.clone(),
                    intermediate1.clone(),
                ],
            );
            count += validate(r, &i, &localhost_leaf);
            {
                let (roots, intermediates) = stores(
                    vec![ca1.clone(), ca2.clone()],
                    vec![
                        intermediate1.clone(),
                        ca2_cross_signed_by_ca1.clone(),
                        ca1_cross_signed_by_ca2.clone(),
                    ],
                );
                let validator = Validator::with_policy_and_backend(
                    roots,
                    FailIfCertInChainPolicy {
                        forbidden: ca1.as_ref().to_vec(),
                        inner: RFC5280Policy::new(fixtures::REFERENCE_TIME),
                    },
                    BACKEND,
                );
                count += match validator.validate_with_diagnostics(
                    &localhost_leaf,
                    &intermediates,
                    &mut |_| {},
                ) {
                    Ok(chain) => chain.iter().count(),
                    Err(reasons) => reasons.len(),
                };
            }
            let (r, i) = stores(
                vec![ca1.clone(), isolated_self_signed.clone()],
                vec![intermediate1.clone()],
            );
            count += validate(r, &i, &isolated_self_signed);
            {
                let (roots, intermediates) =
                    stores(vec![localhost_leaf.clone()], vec![intermediate1.clone()]);
                let validator = Validator::with_policy_and_backend(
                    roots,
                    IgnoreBasicConstraintsPolicy,
                    BACKEND,
                );
                count += match validator.validate_with_diagnostics(
                    &localhost_leaf,
                    &intermediates,
                    &mut |_| {},
                ) {
                    Ok(chain) => chain.iter().count(),
                    Err(reasons) => reasons.len(),
                };
            }
            let (r, i) = stores(vec![intermediate1.clone()], vec![intermediate1.clone()]);
            count += validate(r, &i, &localhost_leaf);

            // unsuccessful (4)
            let (r, i) = stores(
                vec![ca1.clone(), isolated_self_signed_weird_critical.clone()],
                vec![intermediate1.clone()],
            );
            count += validate(r, &i, &isolated_self_signed_weird_critical);
            let (r, i) = stores(vec![ca1.clone()], vec![]);
            count += validate(r, &i, &localhost_leaf);
            let (r, i) = stores(vec![ca1.clone()], vec![intermediate1.clone()]);
            count += validate(r, &i, &isolated_self_signed);
            let (r, i) = stores(vec![], vec![intermediate1.clone()]);
            count += validate(r, &i, &localhost_leaf);

            count
        })
    });
}

criterion_group!(benches, successful, unsuccessful, all_scenarios);
criterion_main!(benches);
