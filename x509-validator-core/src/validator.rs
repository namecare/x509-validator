use crate::validated_chain::ValidatedCertificateChain;
use crate::Certificate;
use crate::error::PolicyFailure;

/// Outcome of `Validator::validate`.
pub enum ChainValidationResult<'a> {
    ValidCertificate(ValidatedCertificateChain<'a>),
    CouldNotValidate(PolicyFailure<'a>),
}

/// Builds and validates a certificate chain. Implementations decide how
/// chain building, signature verification, and any additional acceptance
/// criteria work.
pub trait Validator<'a> {
    fn new(root_certificates: &'a [Certificate<'a>]) -> Self;
    fn with_raw_certificates(root_certificates: &'a [u8]) -> Self;

    fn validate_raw(&self, leaf: &'a [u8], intermediates: &'a [&'a [u8]]) -> ChainValidationResult<'a>;
    fn validate(&self, leaf: Certificate<'a>, intermediates: Vec<Certificate<'a>>) -> ChainValidationResult<'a>;
}