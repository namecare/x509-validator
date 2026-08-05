use crate::validated_chain::ValidatedCertificateChain;
use x509_parser::certificate::X509Certificate;

/// Outcome of `Verifier::validate`. Generic over `R`, the failure-reason
/// type a concrete `Verifier` implementation chooses to report — core has
/// no opinion on what a validation failure looks like.
pub enum ChainValidationResult<'a, R> {
    ValidCertificate(ValidatedCertificateChain<'a>),
    CouldNotValidate(R),
}

/// Builds and validates a certificate chain from a leaf certificate up to a
/// trusted root drawn from `root_certificates`. Implementations decide how
/// chain building, signature verification, and any additional acceptance
/// criteria work — core only fixes the shape of construction and the
/// validation entry point.
pub trait Verifier<R> {
    fn new(root_certificates: &[X509Certificate]) -> Self;
    fn with_raw_certificates(root_certificates: &[u8]) -> Self;

    fn validate_raw<'a>(
        &mut self,
        leaf: &[u8],
        intermediates: &[Vec<u8>],
    ) -> ChainValidationResult<'a, R>;

    fn validate<'a>(
        &mut self,
        leaf: &X509Certificate<'a>,
        intermediates: &[X509Certificate<'a>],
    ) -> ChainValidationResult<'a, R>;
}