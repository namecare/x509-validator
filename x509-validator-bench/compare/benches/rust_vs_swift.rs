//! The sixteen validation scenarios, ours against the reference original.

use divan::{black_box, Bencher};
use x509_validator::policy::ValidationPolicy;
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::{Certificate, Validator};
use x509_validator_bench_compare::{
    parity, FailIfCertInChain, IgnoreBasicConstraints, DEFAULT_BACKEND, REFERENCE_TIME,
};

fn main() {
    eprintln!(
        "note: this binary measures the Rust side only. The other side of \
         this comparison is a separate Swift package under `compare/swift`; \
         run it with `swift package benchmark` from that directory, or let \
         the suite runner start both."
    );
    divan::main();
}

/// Validates `leaf` under `policy` against fresh stores built from `roots`
/// and `intermediates`, asserting the expected verdict once before timing.
fn scenario<P: ValidationPolicy>(
    bencher: Bencher<'_, '_>,
    roots: Vec<Certificate<'static>>,
    intermediates: Vec<Certificate<'static>>,
    leaf: &Certificate<'static>,
    policy: impl Fn() -> P + Sync,
    expect_valid: bool,
) {
    let validate = || {
        let validator = Validator::with_policy_and_backend(
            CertificateStore::from_iter(roots.clone()),
            policy(),
            DEFAULT_BACKEND.provider,
        );
        validator.validate_with_diagnostics(
            leaf,
            &CertificateStore::from_iter(intermediates.clone()),
            &mut |_| {},
        )
    };

    assert_eq!(
        validate().is_ok(),
        expect_valid,
        "scenario must reach its expected verdict before being timed",
    );

    bencher.bench(|| black_box(validate()));
}

/// The plain policy fifteen of the sixteen scenarios run under.
fn rfc5280() -> RFC5280Policy {
    RFC5280Policy::new(REFERENCE_TIME)
}

#[divan::bench]
fn trivial_chain_building(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![p.ca1.clone()],
        vec![p.intermediate1.clone()],
        &p.localhost_leaf,
        rfc5280,
        true,
    );
}

#[divan::bench]
fn extra_roots_are_ignored(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![p.ca1.clone(), p.ca2.clone()],
        vec![p.intermediate1.clone()],
        &p.localhost_leaf,
        rfc5280,
        true,
    );
}

#[divan::bench]
fn roots_in_the_intermediate_store_are_not_a_problem(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![p.ca1.clone(), p.ca2.clone()],
        vec![p.intermediate1.clone(), p.ca1.clone(), p.ca2.clone()],
        &p.localhost_leaf,
        rfc5280,
        true,
    );
}

#[divan::bench]
fn cross_signed_root(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![p.ca2.clone()],
        vec![p.intermediate1.clone(), p.ca1_cross_signed_by_ca2.clone()],
        &p.localhost_leaf,
        rfc5280,
        true,
    );
}

#[divan::bench]
fn builds_the_shorter_path_when_both_cross_signed_roots_are_present(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![p.ca1.clone(), p.ca2.clone()],
        vec![
            p.intermediate1.clone(),
            p.ca2_cross_signed_by_ca1.clone(),
            p.ca1_cross_signed_by_ca2.clone(),
        ],
        &p.localhost_leaf,
        rfc5280,
        true,
    );
}

#[divan::bench]
fn prefers_an_intermediate_whose_ski_matches(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![p.ca1.clone()],
        vec![
            p.intermediate1.clone(),
            p.intermediate1_without_ski_aki.clone(),
        ],
        &p.localhost_leaf,
        rfc5280,
        true,
    );
}

#[divan::bench]
fn prefers_no_ski_over_a_non_matching_one(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![p.ca1.clone()],
        vec![
            p.intermediate1_with_incorrect_ski_aki
                .clone(),
            p.intermediate1_without_ski_aki.clone(),
        ],
        &p.localhost_leaf,
        rfc5280,
        true,
    );
}

#[divan::bench]
fn rejects_a_root_that_did_not_sign_the_certificate_below_it(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![
            p.ca1_with_alternative_private_key
                .clone(),
            p.ca2.clone(),
        ],
        vec![
            p.ca1_cross_signed_by_ca2.clone(),
            p.ca2_cross_signed_by_ca1.clone(),
            p.intermediate1.clone(),
        ],
        &p.localhost_leaf,
        rfc5280,
        true,
    );
}

/// The one scenario whose policy rejects a specific certificate, forcing the
/// search past the shortest path onto a longer one.
#[divan::bench]
fn a_policy_failure_sends_the_search_down_a_longer_path(bencher: Bencher<'_, '_>) {
    let p = parity();
    let forbidden = p.ca1.as_raw().to_vec();
    scenario(
        bencher,
        vec![p.ca1.clone(), p.ca2.clone()],
        vec![
            p.intermediate1.clone(),
            p.ca2_cross_signed_by_ca1.clone(),
            p.ca1_cross_signed_by_ca2.clone(),
        ],
        &p.localhost_leaf,
        || FailIfCertInChain::new(forbidden.clone(), REFERENCE_TIME),
        true,
    );
}

#[divan::bench]
fn a_self_signed_certificate_in_the_trust_store_validates(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![p.ca1.clone(), p.isolated_self_signed.clone()],
        vec![p.intermediate1.clone()],
        &p.isolated_self_signed,
        rfc5280,
        true,
    );
}

/// The one scenario that ignores the leaf's critical basic-constraints
/// extension, so the outcome is decided purely by chain building.
#[divan::bench]
fn a_trust_root_may_be_a_non_self_signed_leaf(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![p.localhost_leaf.clone()],
        vec![p.intermediate1.clone()],
        &p.localhost_leaf,
        || IgnoreBasicConstraints,
        true,
    );
}

#[divan::bench]
fn a_trust_root_may_be_a_non_self_signed_intermediate(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![p.intermediate1.clone()],
        vec![p.intermediate1.clone()],
        &p.localhost_leaf,
        rfc5280,
        true,
    );
}

#[divan::bench]
fn an_unhandled_critical_extension_on_the_leaf_is_policed(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![
            p.ca1.clone(),
            p.isolated_self_signed_weird_critical
                .clone(),
        ],
        vec![p.intermediate1.clone()],
        &p.isolated_self_signed_weird_critical,
        rfc5280,
        false,
    );
}

#[divan::bench]
fn a_missing_intermediate_cannot_build(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![p.ca1.clone()],
        vec![],
        &p.localhost_leaf,
        rfc5280,
        false,
    );
}

#[divan::bench]
fn a_self_signed_certificate_outside_the_trust_store_is_rejected(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![p.ca1.clone()],
        vec![p.intermediate1.clone()],
        &p.isolated_self_signed,
        rfc5280,
        false,
    );
}

#[divan::bench]
fn a_missing_root_cannot_build(bencher: Bencher<'_, '_>) {
    let p = parity();
    scenario(
        bencher,
        vec![],
        vec![p.intermediate1.clone()],
        &p.localhost_leaf,
        rfc5280,
        false,
    );
}
