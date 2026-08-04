use crate::policy::{PolicyEvaluationResult, VerifierPolicy};
use x509_validator_core::{CertificateView, Oid};
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

/// `AnyPolicy` can be used to erase the concrete type of some `VerifierPolicy`.
/// Only use `AnyPolicy` if type erasure is necessary; prefer keeping policies
/// as their concrete types wherever possible.
pub struct AnyPolicy<C: CertificateView> {
    policy: Box<dyn VerifierPolicy<C>>,
}

impl<C: CertificateView> AnyPolicy<C> {
    /// Erases the type of some `VerifierPolicy` to `AnyPolicy`.
    pub fn new(policy: impl VerifierPolicy<C> + 'static) -> Self {
        Self { policy: Box::new(policy) }
    }
}

impl<C: CertificateView> VerifierPolicy<C> for AnyPolicy<C> {
    fn verifying_critical_extensions(&self) -> Vec<Oid> {
        self.policy.verifying_critical_extensions()
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain<C>) -> PolicyEvaluationResult {
        self.policy.chain_meets_policy_requirements(chain)
    }
}
