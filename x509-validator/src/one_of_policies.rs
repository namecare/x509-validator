use crate::policy::{PolicyEvaluationResult, PolicyFailureReason, VerifierPolicy};
use x509_validator_core::{CertificateView, Oid};
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

/// Use this to build a policy where any one of the sub-policies must be met for the overall
/// policy to be met. For example, requiring either `PolicyA` or `PolicyB` to be met (but not
/// necessarily both).
pub struct OneOfPolicies<C: CertificateView> {
    policies: Vec<Box<dyn VerifierPolicy<C>>>,
}

impl<C: CertificateView> OneOfPolicies<C> {
    pub fn new(policies: Vec<Box<dyn VerifierPolicy<C>>>) -> Self {
        Self { policies }
    }
}

impl<C: CertificateView> VerifierPolicy<C> for OneOfPolicies<C> {
    fn verifying_critical_extensions(&self) -> Vec<Oid> {
        self.policies
            .iter()
            .flat_map(|policy| policy.verifying_critical_extensions())
            .collect()
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain<C>) -> PolicyEvaluationResult {
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
