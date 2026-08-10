use std::fmt;
use crate::der_parser::Oid;
use crate::unverified_chain::UnverifiedCertificateChain;

/// The result of evaluating a [`ValidationPolicy`] against a candidate certificate chain.
///
/// `Ok(())` means the chain meets the policy requirements; `Err(reason)` means the chain
/// fails to meet the policy requirements, with the associated reason.
pub type PolicyEvaluationResult = Result<(), PolicyFailureReason>;

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

/// A [`ValidationPolicy`] implements a series of checks on an [`UnverifiedCertificateChain`] to determine
/// whether that chain should be trusted.
///
/// Certificate verification is split into two parts: chain building and policy enforcement. Chain building is general:
/// regardless of policy, we use the same chain building algorithm. This will generate a sequence of candidate chains in
/// the form of [`UnverifiedCertificateChain`].
///
/// Each of these candidate chains is then handed to a [`ValidationPolicy`] to be checked against the certificate policy.
/// The reason for this is to allow different use cases to share the same chain building code, but to enforce
/// different requirements on the chain.
///
/// Some [`ValidationPolicy`] objects are used frequently and are very common, such as `RFC5280Policy` which implements
/// the basic checks from that RFC. Other objects are less common, such as an OCSP policy, which performs live
/// revocation checking. Users can also implement their own policies to enable this crate to support other
/// use cases.
pub trait ValidationPolicy {
    /// The X.509 extension types that this policy understands and enforces.
    ///
    /// X.509 certificates can have extensions marked as `critical`. These extensions _must_ be understood and enforced by the
    /// validator. If they aren't understood or processed, then verifying the chain must fail.
    ///
    /// The validator uses [`ValidationPolicy::verifying_critical_extensions`] to determine what extensions are understood by a given
    /// [`ValidationPolicy`]. A [`ValidationPolicy`] understands the union of all the understood extensions of its contained
    /// [`ValidationPolicy`] objects.
    ///
    /// This may be an empty vector, if the policy does not concern itself with any particular extensions. Users must only put
    /// an extension value in this space if they are actually enforcing the rules of that particular extension value.
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>>;

    /// Called to determine whether a given [`UnverifiedCertificateChain`] meets the requirements of this policy.
    ///
    /// Certificate verification is split into two parts: chain building and policy enforcement. Chain building is general:
    /// regardless of policy, we use the same chain building algorithm. This will generate a sequence of candidate chains in
    /// the form of [`UnverifiedCertificateChain`].
    ///
    /// Each of these candidate chains is then handed to a [`ValidationPolicy`] to be checked against the certificate policy.
    /// The checking is done in this method.
    fn chain_meets_policy_requirements(&self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult;
}
