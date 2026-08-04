use x509_validator_core::{CertificateView, Oid};
use crate::PolicyFailureReason;

/// Verification progress/failure events, useful for debugging and detailed
/// error reporting. Case names describe what happened during chain
/// building; payloads carry the certs/OIDs/reasons involved.
#[derive(Debug)]
pub enum VerificationDiagnostic<C: CertificateView> {
    LeafCertificateHasUnhandledCriticalExtension { oid: Oid },
    LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy { reason: PolicyFailureReason },
    ChainFailsToMeetPolicy { chain: Vec<C>, reason: PolicyFailureReason },
    IssuerHasUnhandledCriticalExtension { issuer: C, oid: Oid },
    IssuerHasNotSignedCertificate { issuer: C, subject: C },
    SearchingForIssuerOfPartialChain { partial_chain: Vec<C> },
    FoundCandidateIssuersOfPartialChainInRootStore { partial_chain: Vec<C>, candidates: Vec<C> },
    FoundCandidateIssuersOfPartialChainInIntermediateStore { partial_chain: Vec<C>, candidates: Vec<C> },
    FoundValidCertificateChain { chain: Vec<C> },
    CouldNotValidateLeafCertificate { reasons: Vec<PolicyFailureReason> },
    IssuerIsAlreadyInTheChain { issuer: C },
    LoadingTrustRootsFailed { reason: String },
}
