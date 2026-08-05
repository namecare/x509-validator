use crate::PolicyFailureReason;
use x509_parser::der_parser::Oid;
use x509_validator_core::Certificate;

/// Verification progress/failure events, useful for debugging and detailed
/// error reporting. Case names describe what happened during chain
/// building; payloads carry the certs/OIDs/reasons involved.
#[derive(Debug)]
pub enum VerificationDiagnostic<'a> {
    LeafCertificateHasUnhandledCriticalExtension { oid: Oid<'static> },
    LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy { reason: PolicyFailureReason },
    ChainFailsToMeetPolicy { chain: Vec<Certificate<'a>>, reason: PolicyFailureReason },
    IssuerHasUnhandledCriticalExtension { issuer: Certificate<'a>, oid: Oid<'static> },
    IssuerHasNotSignedCertificate { issuer: Certificate<'a>, subject: Certificate<'a> },
    SearchingForIssuerOfPartialChain { partial_chain: Vec<Certificate<'a>> },
    FoundCandidateIssuersOfPartialChainInRootStore { partial_chain: Vec<Certificate<'a>>, candidates: Vec<Certificate<'a>> },
    FoundCandidateIssuersOfPartialChainInIntermediateStore { partial_chain: Vec<Certificate<'a>>, candidates: Vec<Certificate<'a>> },
    FoundValidCertificateChain { chain: Vec<Certificate<'a>> },
    CouldNotValidateLeafCertificate { reasons: Vec<PolicyFailureReason> },
    IssuerIsAlreadyInTheChain { issuer: Certificate<'a> },
    LoadingTrustRootsFailed { reason: String },
}