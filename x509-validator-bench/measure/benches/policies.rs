//! Policy evaluation cost, measured against a prebuilt chain.
//!
//! No crypto is involved: these call `chain_meets_policy_requirements`
//! directly rather than going through the validator. Policy work is a rounding
//! error next to signature verification, which is exactly why it belongs
//! here — a policy regression would be invisible in an end-to-end number.
//!
//! `dns_names`, `ip_constraints`, and `uri_constraints` have no policy
//! implementations of their own — they are helpers reached through
//! `NameConstraintsPolicy` and `ServerIdentityPolicy`, and are benchmarked
//! through those.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use x509_validator::policy::ValidationPolicy;
use x509_validator::rfc5280::{BasicConstraintsPolicy, ExpiryPolicy, NameConstraintsPolicy, RFC5280Policy, VersionPolicy};
use x509_validator::{AllOfPolicies, AnyPolicy, OneOfPolicies, OneOfTuple2, ServerIdentityPolicy};
use x509_validator_bench_measure::fixtures;
use x509_validator::unverified_chain::UnverifiedCertificateChain;

/// The leaf → intermediate → root chain every policy here is evaluated
/// against.
fn chain() -> UnverifiedCertificateChain<'static> {
    let parity = fixtures::parity();
    UnverifiedCertificateChain::new(vec![
        parity.localhost_leaf.clone(),
        parity.intermediate1.clone(),
        parity.ca1.clone(),
    ])
}

/// Registers one policy benchmark. The policy is rebuilt per iteration
/// because `chain_meets_policy_requirements` takes `&mut self` and some
/// policies carry state across calls; construction happens in the setup
/// phase so it is not timed.
fn bench_policy<P: ValidationPolicy>(c: &mut Criterion, id: &str, make: impl Fn() -> P) {
    let chain = chain();
    c.bench_function(id, |b| {
        b.iter_batched_ref(
            &make,
            |policy| policy.chain_meets_policy_requirements(&chain).is_ok(),
            BatchSize::SmallInput,
        )
    });
}

fn policies(c: &mut Criterion) {
    bench_policy(c, "policy/version", || VersionPolicy);
    bench_policy(c, "policy/expiry", || ExpiryPolicy::new(fixtures::REFERENCE_TIME));
    bench_policy(c, "policy/basic_constraints", || BasicConstraintsPolicy);
    bench_policy(c, "policy/name_constraints", || NameConstraintsPolicy);
    bench_policy(c, "policy/rfc5280", || RFC5280Policy::new(fixtures::REFERENCE_TIME));
    bench_policy(c, "policy/all_of", || AllOfPolicies::new(RFC5280Policy::new(fixtures::REFERENCE_TIME)));
    bench_policy(c, "policy/any", || AnyPolicy::new(RFC5280Policy::new(fixtures::REFERENCE_TIME)));
    bench_policy(c, "policy/one_of", || OneOfPolicies::new(OneOfTuple2::new(VersionPolicy, BasicConstraintsPolicy)));
}

/// `ServerIdentityPolicy`'s three matching paths, benched separately.
///
/// The exact-DNS path is the cheap common case. Wildcard matching is the one
/// the implementation itself calls expensive, and IP matching is a different
/// code path again — both were unmeasured before, which made them the most
/// likely places for a regression to go unnoticed.
fn server_identity(c: &mut Criterion) {
    bench_policy(c, "policy/server_identity_dns", || ServerIdentityPolicy::new(Some("localhost"), None));
    bench_policy(c, "policy/server_identity_wildcard", || {
        ServerIdentityPolicy::new(Some("host.example.com"), None)
    });
    bench_policy(c, "policy/server_identity_ip", || ServerIdentityPolicy::new(None, Some("192.0.2.1")));
}

criterion_group!(benches, policies, server_identity);
criterion_main!(benches);
