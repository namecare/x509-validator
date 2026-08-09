use crate::unverified_chain::UnverifiedCertificateChain;
use std::fmt;

/// Why a chain was rejected by policy evaluation.
#[derive(Clone, PartialEq, Eq, Hash)]
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

/// A chain that was built but rejected by policy, and why.
#[derive(Clone)]
pub struct PolicyFailure<'a> {
    pub chain: UnverifiedCertificateChain<'a>,
    pub policy_failure_reason: PolicyFailureReason,
}

impl<'a> PolicyFailure<'a> {
    pub fn new(chain: UnverifiedCertificateChain<'a>, policy_failure_reason: PolicyFailureReason) -> Self {
        Self {
            chain,
            policy_failure_reason,
        }
    }
}

impl fmt::Display for PolicyFailure<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.policy_failure_reason)
    }
}

impl fmt::Debug for PolicyFailure<'_> {
    /// Shows the reason and the chain's length, but not every certificate:
    /// a chain's full `Debug` output is large enough to bury the reason,
    /// which is what a failed assertion is usually reporting.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (chain of {})", self.policy_failure_reason, self.chain.len())
    }
}
