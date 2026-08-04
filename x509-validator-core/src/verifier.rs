use crate::validated_chain::ValidatedCertificateChain;
use crate::view::CertificateView;

/// Outcome of `Verifier::validate`. Generic over `R`, the failure-reason
/// type a concrete `Verifier` implementation chooses to report — core has
/// no opinion on what a validation failure looks like.
pub enum ChainValidationResult<C: CertificateView, R> {
    ValidCertificate(ValidatedCertificateChain<C>),
    CouldNotValidate(R),
}

/// Builds and validates a certificate chain from a leaf certificate up to a
/// trusted root drawn from `root_certificates`. Implementations decide how
/// chain building, signature verification, and any additional acceptance
/// criteria work — core only fixes the shape of construction and the
/// validation entry point.
pub trait Verifier<C: CertificateView, R> {
    fn new(root_certificates_der: &[Vec<u8>]) -> Self;

    fn validate(
        &mut self,
        leaf: &C,
        intermediates: &[Vec<u8>],
    ) -> ChainValidationResult<C, R>;
}