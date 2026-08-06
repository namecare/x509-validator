use crate::policy::{PolicyEvaluationResult, PolicyFailureReason, VerifierPolicy};
use x509_validator_core::der_parser::Oid;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

/// Use this to build a policy where any one of the sub-policies must be met for the overall
/// policy to be met. For example, requiring either `PolicyA` or `PolicyB` to be met (but not
/// necessarily both).
pub struct OneOfPolicies {
    policies: Vec<Box<dyn VerifierPolicy>>,
}

impl OneOfPolicies {
    pub fn new(policies: Vec<Box<dyn VerifierPolicy>>) -> Self {
        Self { policies }
    }
}

impl VerifierPolicy for OneOfPolicies {
    /// Intersection, not union: only one sub-policy's checks actually run
    /// for a given chain (the first one that meets policy, or none), so an
    /// extension is only safe to claim as handled here if every sub-policy
    /// independently understands it.
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        let mut policies = self.policies.iter();
        let Some(first) = policies.next() else {
            return Vec::new();
        };
        let mut common = first.verifying_critical_extensions();
        for policy in policies {
            let handled = policy.verifying_critical_extensions();
            common.retain(|oid| handled.contains(oid));
        }
        common
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        if self.policies.is_empty() {
            return Err(PolicyFailureReason::new("no policies specified in OneOfPolicies"));
        }

        let mut reasons = Vec::new();
        for policy in &mut self.policies {
            match policy.chain_meets_policy_requirements(chain) {
                Ok(()) => return Ok(()),
                Err(reason) => reasons.push(reason.to_string()),
            }
        }

        Err(PolicyFailureReason::new(reasons.join(" and ")))
    }
}