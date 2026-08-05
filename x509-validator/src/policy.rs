use std::fmt;
use x509_parser::der_parser::Oid;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

/// Result of evaluating a certificate chain against a policy. `Ok(())` indicates
/// the chain meets policy requirements; `Err(reason)` indicates policy failure.
pub type PolicyEvaluationResult = Result<(), PolicyFailureReason>;

#[derive(Clone)]
pub struct PolicyFailureReason(String);

impl PolicyFailureReason {
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

impl fmt::Display for PolicyFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for PolicyFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for PolicyFailureReason {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// Evaluates certificate chains against custom policies. Sync (no async).
pub trait VerifierPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>>;
    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::self_signed_ca;
    use x509_parser::prelude::FromDer;
    use x509_validator_core::Certificate;

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
        let der = self_signed_ca("root");
        let (_, cert) = Certificate::from_der(&der).unwrap();

        let chain = UnverifiedCertificateChain::new(vec![cert]);
        let mut policy = AlwaysMeetsPolicy;

        let result = policy.chain_meets_policy_requirements(&chain);
        assert_eq!(result, Ok(()));
    }
}