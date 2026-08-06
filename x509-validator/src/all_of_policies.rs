use crate::policy::{PolicyEvaluationResult, VerifierPolicy};
use x509_validator_core::der_parser::Oid;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

/// Use this to build a policy where all of the sub-policies must be met for the overall policy to be met.
/// This is only useful within a [`OneOfPolicies`] block, because at the top-level, it is already required for all
/// policies to be met, so adding this at the top-level is redundant.
/// For example, the following policy requires that `RFC5280Policy` is always met, and then either policy C is met, or
/// A and B are both met. If A and B are both met, then C does not have to be met. If C is met, then neither A nor B
/// need to be met.
///
/// [`OneOfPolicies`]: crate::one_of_policies::OneOfPolicies
pub struct AllOfPolicies<P> {
    policy: P,
}

impl<P> AllOfPolicies<P> {
    pub fn new(policy: P) -> Self {
        Self { policy }
    }
}

impl<P: VerifierPolicy> VerifierPolicy for AllOfPolicies<P> {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        self.policy.verifying_critical_extensions()
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        self.policy.chain_meets_policy_requirements(chain)
    }
}