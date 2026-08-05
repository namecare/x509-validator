use crate::policy::{PolicyEvaluationResult, VerifierPolicy};
use x509_parser::der_parser::Oid;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

/// Use this to build a policy where all of the sub-policies must be met for the overall policy to be met.
/// This is only useful within a `OneOfPolicies`, because at the top level, it is already required for all
/// policies to be met, so adding this at the top level is redundant.
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