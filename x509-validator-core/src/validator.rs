use crate::validated_chain::ValidatedCertificateChain;
use crate::Certificate;
use crate::error::PolicyFailure;

/// The result of validating a certificate chain.
pub enum ChainValidationResult<'a> {
    /// The certificate chain is valid and trusted.
    ValidCertificate(ValidatedCertificateChain<'a>),
    /// No chain could be accepted. Carries every chain that was built and
    /// rejected, each with the reason it was rejected, in the order the
    /// implementation considered them.
    CouldNotValidate(Vec<PolicyFailure<'a>>),
}

/// Builds and validates a certificate chain.
///
/// Implementations decide how chain building, signature verification,
/// and any additional acceptance criteria work, and how they are configured;
/// construction is left to the implementing type.
pub trait Validator<'a> {
    /// Validates a leaf certificate by building chains through `intermediates`
    /// to the implementation's trusted roots.
    fn validate(&self, leaf: Certificate<'a>, intermediates: Vec<Certificate<'a>>) -> ChainValidationResult<'a>;

    /// Validates DER-encoded input, parsing it and delegating to [`Validator::validate`].
    fn validate_raw(&self, leaf: &'a [u8], intermediates: &'a [&'a [u8]]) -> ChainValidationResult<'a>;
}
