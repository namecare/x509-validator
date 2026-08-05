use crate::validated_chain::ValidatedCertificateChain;
use x509_parser::certificate::X509Certificate;
use crate::error::PolicyFailure;

/// Outcome of `Verifier::validate`. Generic over `R`, the failure-reason
/// type a concrete `Verifier` implementation chooses to report — core has
/// no opinion on what a validation failure looks like.
pub enum ChainValidationResult<'a> {
    ValidCertificate(ValidatedCertificateChain<'a>),
    CouldNotValidate(PolicyFailure<'a>),
}

/// Builds and validates a certificate chain from a leaf certificate up to a
/// trusted root drawn from `root_certificates`. Implementations decide how
/// chain building, signature verification, and any additional acceptance
/// criteria work — core only fixes the shape of construction and the
/// validation entry point.
///
/// Generic over `'a`: root certificates are borrowed for `'a` and held for
/// the lifetime of the `Verifier`, so a matched trust anchor can be returned
/// as part of a validated chain rather than only referenced by identity.
pub trait Verifier<'a> {
    fn new(root_certificates: &'a [X509Certificate<'a>]) -> Self;
    fn with_raw_certificates(root_certificates: &'a [u8]) -> Self;

    fn validate_raw(&self, leaf: &'a [u8], intermediates: &'a [&'a [u8]]) -> ChainValidationResult<'a>;

    fn validate(&self, leaf: X509Certificate<'a>, intermediates: Vec<X509Certificate<'a>>) -> ChainValidationResult<'a>;
}