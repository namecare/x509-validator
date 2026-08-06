use std::fmt;
use x509_validator_core::der_parser::Oid;
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
