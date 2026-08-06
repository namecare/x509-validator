//! Policy trait composition and object safety.

use x509_validator::unverified_chain::UnverifiedCertificateChain;
use x509_validator::{Oid, PolicyEvaluationResult, VerifierPolicy};
use x509_validator_testkit::{chain_of, self_signed_ca};

struct AlwaysMeetsPolicy;

impl VerifierPolicy for AlwaysMeetsPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![]
    }
    fn chain_meets_policy_requirements(&mut self, _chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        Ok(())
    }
}

// Compile-only proof that VerifierPolicy is usable as a trait object.
fn _assert_object_safe(_: Box<dyn VerifierPolicy>) {}

#[test]
fn test_unverified_chain_with_policy() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let mut policy = AlwaysMeetsPolicy;

    let result = policy.chain_meets_policy_requirements(&chain);
    assert_eq!(result, Ok(()));
}
