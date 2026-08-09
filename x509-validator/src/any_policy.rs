use crate::policy::{PolicyEvaluationResult, ValidationPolicy};
use x509_validator_core::der_parser::Oid;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

/// [`AnyPolicy`] can be used to erase the concrete type of some [`ValidationPolicy`].
/// Only use [`AnyPolicy`] if type erasure is necessary.
/// Instead try to use conditional inclusion of different policies through their concrete types.
///
/// Use [`AnyPolicy`] at the top level during construction of a validator to get a validator of type
pub struct AnyPolicy {
    policy: Box<dyn ValidationPolicy>,
}

impl AnyPolicy {
    /// Erases the type of some [`ValidationPolicy`] to [`AnyPolicy`].
    /// - Parameter policy: the concrete [`ValidationPolicy`]
    pub fn new(policy: impl ValidationPolicy + 'static) -> Self {
        Self { policy: Box::new(policy) }
    }
}

impl ValidationPolicy for AnyPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        self.policy.verifying_critical_extensions()
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        self.policy.chain_meets_policy_requirements(chain)
    }
}