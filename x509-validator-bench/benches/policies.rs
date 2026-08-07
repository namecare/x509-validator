//! Policy evaluation cost, measured against a prebuilt chain.
//!
//! No crypto is involved: these benchmarks call
//! `chain_meets_policy_requirements` directly rather than going through the
//! verifier, so the numbers are backend-independent.
//!
//! `dns_names`, `ip_constraints`, and `uri_constraints` have no policy
//! implementations of their own — they are helpers reached through
//! `NameConstraintsPolicy` and `ServerIdentityPolicy`, and are benchmarked
//! through those.

use x509_validator::policy::VerifierPolicy;
use x509_validator::rfc5280::{
    BasicConstraintsPolicy, ExpiryPolicy, NameConstraintsPolicy, RFC5280Policy, VersionPolicy,
};
use x509_validator::{AllOfPolicies, AnyPolicy, OneOfPolicies, ServerIdentityPolicy};
use x509_validator_bench::fixtures;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

fn main() {
    divan::main();
}

/// The leaf → intermediate → root chain every policy here is evaluated
/// against, built once.
fn chain() -> UnverifiedCertificateChain<'static> {
    let parity = fixtures::parity();
    UnverifiedCertificateChain::new(vec![
        parity.localhost_leaf.clone(),
        parity.intermediate1.clone(),
        parity.ca1.clone(),
    ])
}

macro_rules! policy_bench {
    ($name:ident, $make:expr) => {
        #[divan::bench]
        fn $name(bencher: divan::Bencher) {
            let chain = chain();
            bencher.with_inputs(|| $make).bench_refs(|policy| {
                divan::black_box(policy.chain_meets_policy_requirements(divan::black_box(&chain))).is_ok()
            });
        }
    };
}

policy_bench!(version_policy, VersionPolicy);
policy_bench!(expiry_policy, ExpiryPolicy::new(fixtures::REFERENCE_TIME));
policy_bench!(basic_constraints_policy, BasicConstraintsPolicy);
policy_bench!(name_constraints_policy, NameConstraintsPolicy);
policy_bench!(rfc5280_policy, RFC5280Policy::new(fixtures::REFERENCE_TIME));
policy_bench!(
    server_identity_dns,
    ServerIdentityPolicy::new(Some("localhost"), None)
);
policy_bench!(
    all_of_policies,
    AllOfPolicies::new(RFC5280Policy::new(fixtures::REFERENCE_TIME))
);
policy_bench!(
    any_policy,
    AnyPolicy::new(RFC5280Policy::new(fixtures::REFERENCE_TIME))
);
policy_bench!(
    one_of_policies,
    OneOfPolicies::new(vec![
        Box::new(VersionPolicy) as Box<dyn VerifierPolicy>,
        Box::new(BasicConstraintsPolicy),
    ])
);
