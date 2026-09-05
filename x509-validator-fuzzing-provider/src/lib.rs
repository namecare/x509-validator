use x509_validator::{AlgorithmIdentifier, CryptoError, SignatureVerifier, SubjectPublicKeyInfo};

/// This is a `SignatureVerifier` that provides NO SECURITY and is for fuzzing only.
pub static PROVIDER: Provider = Provider;

#[derive(Debug)]
pub struct Provider;

impl SignatureVerifier for Provider {
    fn verify_signature(
        &self,
        _algorithm: &AlgorithmIdentifier<'_>,
        _public_key: &SubjectPublicKeyInfo<'_>,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }
}
