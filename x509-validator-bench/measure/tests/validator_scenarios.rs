use x509_validator::der_parser::Oid;
use x509_validator::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS;
use x509_validator::policy::{PolicyEvaluationResult, PolicyFailureReason, ValidationPolicy};
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::unverified_chain::UnverifiedCertificateChain;
use x509_validator::validator::ChainValidationResult;
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

/// Whether a validation attempt is expected to succeed or fail.
#[derive(Debug, PartialEq, Eq)]
enum Expect {
    Valid,
    Invalid,
}

/// Runs one scenario with the plain `RFC5280Policy` and asserts the outcome
/// matches what the scenario's name in `benches/validator.rs` claims.
fn assert_scenario(
    name: &str,
    roots: Vec<Certificate<'static>>,
    intermediates: Vec<Certificate<'static>>,
    leaf: &Certificate<'static>,
    expect: Expect,
) {
    let validator = Validator::with_policy_and_backend(
        CertificateStore::from_iter(roots),
        RFC5280Policy::new(fixtures::REFERENCE_TIME),
        BACKEND,
    );
    let result = validator.validate_with_diagnostics(
        leaf,
        &CertificateStore::from_iter(intermediates),
        &mut |_| {},
    );
    assert_outcome(name, &result, expect);
}

fn assert_outcome(name: &str, result: &ChainValidationResult<'_>, expect: Expect) {
    match (result, expect) {
        (Ok(_), Expect::Valid) => {}
        (Err(_), Expect::Invalid) => {}
        (Ok(_), Expect::Invalid) => {
            panic!(
                "scenario `{name}` was expected to fail validation but produced ValidCertificate"
            );
        }
        (Err(reasons), Expect::Valid) => {
            panic!("scenario `{name}` was expected to validate but produced CouldNotValidate({reasons:?})");
        }
    }
}

#[test]
fn trivial_chain_building() {
    let p = fixtures::parity();
    assert_scenario(
        "trivial chain building",
        vec![p.ca1().clone()],
        vec![p.intermediate1().clone()],
        &p.localhost_leaf(),
        Expect::Valid,
    );
}

#[test]
fn extra_roots_are_ignored() {
    let p = fixtures::parity();
    assert_scenario(
        "extra roots are ignored",
        vec![p.ca1().clone(), p.ca2().clone()],
        vec![p.intermediate1().clone()],
        &p.localhost_leaf(),
        Expect::Valid,
    );
}

#[test]
fn roots_in_intermediate_store_are_not_a_problem() {
    let p = fixtures::parity();
    assert_scenario(
        "roots in the intermediate store are not a problem",
        vec![p.ca1().clone(), p.ca2().clone()],
        vec![p.intermediate1().clone(), p.ca1().clone(), p.ca2().clone()],
        &p.localhost_leaf(),
        Expect::Valid,
    );
}

#[test]
fn cross_signed_root() {
    let p = fixtures::parity();
    assert_scenario(
        "cross-signed root",
        vec![p.ca2().clone()],
        vec![
            p.intermediate1().clone(),
            p.ca1_cross_signed_by_ca2().clone(),
        ],
        &p.localhost_leaf(),
        Expect::Valid,
    );
}

#[test]
fn builds_shorter_path_when_both_cross_signed_roots_present() {
    let p = fixtures::parity();
    assert_scenario(
        "builds the shorter path when both cross-signed roots are present",
        vec![p.ca1().clone(), p.ca2().clone()],
        vec![
            p.intermediate1().clone(),
            p.ca2_cross_signed_by_ca1().clone(),
            p.ca1_cross_signed_by_ca2().clone(),
        ],
        &p.localhost_leaf(),
        Expect::Valid,
    );
}

#[test]
fn prefers_intermediate_whose_ski_matches() {
    let p = fixtures::parity();
    assert_scenario(
        "prefers an intermediate whose SKI matches",
        vec![p.ca1().clone()],
        vec![
            p.intermediate1().clone(),
            p.intermediate1_without_ski_aki()
                .clone(),
        ],
        &p.localhost_leaf(),
        Expect::Valid,
    );
}

#[test]
fn prefers_no_ski_over_non_matching_ski() {
    let p = fixtures::parity();
    assert_scenario(
        "prefers no SKI over a non-matching one",
        vec![p.ca1().clone()],
        vec![
            p.intermediate1_with_incorrect_ski_aki()
                .clone(),
            p.intermediate1_without_ski_aki()
                .clone(),
        ],
        &p.localhost_leaf(),
        Expect::Valid,
    );
}

#[test]
fn rejects_root_that_did_not_sign() {
    let p = fixtures::parity();
    assert_scenario(
        "rejects a root that did not sign the certificate below it",
        vec![
            p.ca1_with_alternative_private_key()
                .clone(),
            p.ca2().clone(),
        ],
        vec![
            p.ca1_cross_signed_by_ca2().clone(),
            p.ca2_cross_signed_by_ca1().clone(),
            p.intermediate1().clone(),
        ],
        &p.localhost_leaf(),
        Expect::Valid,
    );
}

#[test]
fn policy_failure_sends_search_down_longer_path() {
    let p = fixtures::parity();
    let validator = Validator::with_policy_and_backend(
        CertificateStore::from_iter(vec![p.ca1().clone(), p.ca2().clone()]),
        FailIfCertInChainPolicy {
            forbidden: p.ca1().as_ref().to_vec(),
            inner: RFC5280Policy::new(fixtures::REFERENCE_TIME),
        },
        BACKEND,
    );
    let intermediates = CertificateStore::from_iter(vec![
        p.intermediate1().clone(),
        p.ca2_cross_signed_by_ca1().clone(),
        p.ca1_cross_signed_by_ca2().clone(),
    ]);
    let result =
        validator.validate_with_diagnostics(&p.localhost_leaf(), &intermediates, &mut |_| {});
    assert_outcome(
        "a policy failure sends the search down a longer path",
        &result,
        Expect::Valid,
    );
}

#[test]
fn self_signed_certificate_in_trust_store_validates() {
    let p = fixtures::parity();
    assert_scenario(
        "a self-signed certificate in the trust store validates",
        vec![p.ca1().clone(), p.isolated_self_signed().clone()],
        vec![p.intermediate1().clone()],
        &p.isolated_self_signed(),
        Expect::Valid,
    );
}

#[test]
fn trust_root_may_be_non_self_signed_leaf() {
    let p = fixtures::parity();
    let validator = Validator::with_policy_and_backend(
        CertificateStore::from_iter(vec![p.localhost_leaf().clone()]),
        IgnoreBasicConstraintsPolicy,
        BACKEND,
    );
    let intermediates = CertificateStore::from_iter(vec![p.intermediate1().clone()]);
    let result =
        validator.validate_with_diagnostics(&p.localhost_leaf(), &intermediates, &mut |_| {});
    assert_outcome(
        "a trust root may be a non-self-signed leaf",
        &result,
        Expect::Valid,
    );
}

#[test]
fn trust_root_may_be_non_self_signed_intermediate() {
    let p = fixtures::parity();
    assert_scenario(
        "a trust root may be a non-self-signed intermediate",
        vec![p.intermediate1().clone()],
        vec![p.intermediate1().clone()],
        &p.localhost_leaf(),
        Expect::Valid,
    );
}

#[test]
fn unhandled_critical_extension_on_leaf_is_policed() {
    let p = fixtures::parity();
    assert_scenario(
        "an unhandled critical extension on the leaf is policed",
        vec![
            p.ca1().clone(),
            p.isolated_self_signed_weird_critical()
                .clone(),
        ],
        vec![p.intermediate1().clone()],
        &p.isolated_self_signed_weird_critical(),
        Expect::Invalid,
    );
}

#[test]
fn missing_intermediate_cannot_build() {
    let p = fixtures::parity();
    assert_scenario(
        "a missing intermediate cannot build",
        vec![p.ca1().clone()],
        vec![],
        &p.localhost_leaf(),
        Expect::Invalid,
    );
}

#[test]
fn self_signed_certificate_outside_trust_store_is_rejected() {
    let p = fixtures::parity();
    assert_scenario(
        "a self-signed certificate outside the trust store is rejected",
        vec![p.ca1().clone()],
        vec![p.intermediate1().clone()],
        &p.isolated_self_signed(),
        Expect::Invalid,
    );
}

#[test]
fn missing_root_cannot_build() {
    let p = fixtures::parity();
    assert_scenario(
        "a missing root cannot build",
        vec![],
        vec![p.intermediate1().clone()],
        &p.localhost_leaf(),
        Expect::Invalid,
    );
}
