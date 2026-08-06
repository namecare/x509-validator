use crate::policy::{PolicyEvaluationResult, VerifierPolicy};
use x509_validator_core::der_parser::Oid;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

/// `AnyPolicy` can be used to erase the concrete type of some `VerifierPolicy`.
/// Only use `AnyPolicy` if type erasure is necessary; prefer keeping policies
/// as their concrete types wherever possible.
pub struct AnyPolicy {
    policy: Box<dyn VerifierPolicy>,
}

impl AnyPolicy {
    /// Erases the type of some `VerifierPolicy` to `AnyPolicy`.
    pub fn new(policy: impl VerifierPolicy + 'static) -> Self {
        Self { policy: Box::new(policy) }
    }
}

impl VerifierPolicy for AnyPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        self.policy.verifying_critical_extensions()
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        self.policy.chain_meets_policy_requirements(chain)
    }
}