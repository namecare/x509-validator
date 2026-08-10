use crate::der_parser::Oid;
use crate::policy::{PolicyEvaluationResult, ValidationPolicy};
use crate::unverified_chain::UnverifiedCertificateChain;

/// Use this to build a policy where at least one of the sub-policies must be met for the overall policy
/// to be met.
///
/// Compose alternatives with the [`one_of!`](crate::one_of) macro, which builds the appropriate nested
/// [`OneOfTuple2`](crate::policy_builder::OneOfTuple2) chain to pass here: the first alternative is tried,
/// and only if it fails is the second tried, with both failure reasons reported if both fail. Extensions
/// claimed as understood are the intersection of every alternative's claims — a critical extension is only
/// considered handled here if every alternative would have handled it.
pub struct OneOfPolicies<P> {
    policy: P,
}

impl<P> OneOfPolicies<P> {
    pub fn new(policy: P) -> Self {
        Self { policy }
    }
}

impl<P: ValidationPolicy> ValidationPolicy for OneOfPolicies<P> {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        self.policy
            .verifying_critical_extensions()
    }

    fn chain_meets_policy_requirements(
        &self,
        chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        self.policy
            .chain_meets_policy_requirements(chain)
    }
}
