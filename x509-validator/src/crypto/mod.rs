#[cfg(feature = "aws_lc")]
pub mod aws_lc;

use std::fmt::Debug;
use x509_validator_core::SignatureAlgorithmId;

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("invalid key encoding: {0}")]
    InvalidKey(String),
    #[error("signature verification failed")]
    VerificationFailed,
}

pub trait PublicKey: Send + Sync + Debug {
    fn is_valid(&self, signature: &[u8], message: &[u8]) -> Result<(), CryptoError>;
}

pub trait KeyProvider: Send + Sync + Debug {
    fn public_key(
        &self,
        algorithm: SignatureAlgorithmId,
        public_key_der: &[u8],
    ) -> Result<Box<dyn PublicKey>, CryptoError>;
}

pub struct CryptoProvider {
    pub key_provider: &'static dyn KeyProvider,
    pub sha256: &'static dyn Digest,
}

pub trait Digest: Send + Sync + Debug {
    fn hash(&self, data: &[u8]) -> Vec<u8>;
}



/// A `KeyProvider`/`Digest` pair that always fails, used to populate
/// `CryptoProvider::default_backend` until a real crypto backend is wired
/// in. Every call reports that no backend has been configured.
#[derive(Debug)]
struct UnconfiguredCryptoBackend;

impl KeyProvider for UnconfiguredCryptoBackend {
    fn public_key(
        &self,
        _algorithm: SignatureAlgorithmId,
        _public_key_der: &[u8],
    ) -> Result<Box<dyn PublicKey>, CryptoError> {
        Err(CryptoError::InvalidKey("no crypto backend configured".into()))
    }
}

impl Digest for UnconfiguredCryptoBackend {
    fn hash(&self, _data: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

static UNCONFIGURED_CRYPTO_BACKEND: UnconfiguredCryptoBackend = UnconfiguredCryptoBackend;

impl CryptoProvider {
    /// A `CryptoProvider` whose key provider always fails with
    /// `CryptoError::InvalidKey`. Used as the default backend for
    /// `Verifier::new`, which has no way to accept a caller-supplied
    /// backend; callers who need real signature verification should use
    /// `Verifier::with_policy_and_backend` with an actual `CryptoProvider`
    /// instead.
    pub fn default_backend() -> &'static CryptoProvider {
        static DEFAULT: CryptoProvider = CryptoProvider {
            key_provider: &UNCONFIGURED_CRYPTO_BACKEND,
            sha256: &UNCONFIGURED_CRYPTO_BACKEND,
        };
        &DEFAULT
    }

    /// Looks up the public key for `algorithm` and checks `signature` over
    /// `message`. This is the one crypto call site the chain-building core
    /// uses to check a candidate issuer's signature over a certificate.
    pub fn verify_signature(
        &self,
        algorithm: SignatureAlgorithmId,
        public_key_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if algorithm == SignatureAlgorithmId::Unknown {
            return Err(CryptoError::InvalidKey("unknown signature algorithm".into()));
        }
        let key = self.key_provider.public_key(algorithm, public_key_der)?;
        key.is_valid(signature, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tagged KeyProvider that returns a distinct error message from
    /// `public_key` to identify which algorithm it was dispatched for.
    #[derive(Debug)]
    struct TaggedKeyProvider;

    impl KeyProvider for TaggedKeyProvider {
        fn public_key(
            &self,
            algorithm: SignatureAlgorithmId,
            _public_key_der: &[u8],
        ) -> Result<Box<dyn PublicKey>, CryptoError> {
            Err(CryptoError::InvalidKey(format!("{algorithm:?}-was-called")))
        }
    }

    /// Fake KeyProvider whose keys always fail verification with
    /// `VerificationFailed`.
    #[derive(Debug)]
    struct FailurePublicKey;

    impl PublicKey for FailurePublicKey {
        fn is_valid(&self, _signature: &[u8], _message: &[u8]) -> Result<(), CryptoError> {
            Err(CryptoError::VerificationFailed)
        }
    }

    #[derive(Debug)]
    struct FailureKeyProvider;

    impl KeyProvider for FailureKeyProvider {
        fn public_key(
            &self,
            _algorithm: SignatureAlgorithmId,
            _public_key_der: &[u8],
        ) -> Result<Box<dyn PublicKey>, CryptoError> {
            Ok(Box::new(FailurePublicKey))
        }
    }

    /// Fake Digest that returns a fixed output
    #[derive(Debug)]
    struct FakeDigest;

    impl Digest for FakeDigest {
        fn hash(&self, _data: &[u8]) -> Vec<u8> {
            vec![0x42; 32]
        }
    }

    static TAGGED_KEY_PROVIDER: TaggedKeyProvider = TaggedKeyProvider;
    static FAILURE_KEY_PROVIDER: FailureKeyProvider = FailureKeyProvider;
    static FAKE_DIGEST: FakeDigest = FakeDigest;

    fn tagged_provider() -> CryptoProvider {
        CryptoProvider {
            key_provider: &TAGGED_KEY_PROVIDER,
            sha256: &FAKE_DIGEST,
        }
    }

    #[test]
    fn test_verify_signature_ecdsa_p256() {
        let provider = tagged_provider();

        let result = provider.verify_signature(
            SignatureAlgorithmId::EcdsaP256Sha256,
            b"public_key",
            b"message",
            b"signature",
        );

        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "EcdsaP256Sha256-was-called", "Expected p256 algorithm to be dispatched to");
            }
            _ => panic!("Expected InvalidKey error from key provider"),
        }
    }

    #[test]
    fn test_verify_signature_ecdsa_p384() {
        let provider = tagged_provider();

        let result = provider.verify_signature(
            SignatureAlgorithmId::EcdsaP384Sha384,
            b"public_key",
            b"message",
            b"signature",
        );

        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "EcdsaP384Sha384-was-called", "Expected p384 algorithm to be dispatched to");
            }
            _ => panic!("Expected InvalidKey error from key provider"),
        }
    }

    #[test]
    fn test_verify_signature_ecdsa_p521() {
        let provider = tagged_provider();

        let result = provider.verify_signature(
            SignatureAlgorithmId::EcdsaP521Sha512,
            b"public_key",
            b"message",
            b"signature",
        );

        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "EcdsaP521Sha512-was-called", "Expected p521 algorithm to be dispatched to");
            }
            _ => panic!("Expected InvalidKey error from key provider"),
        }
    }

    #[test]
    fn test_verify_signature_ed25519() {
        let provider = tagged_provider();

        let result = provider.verify_signature(SignatureAlgorithmId::Ed25519, b"public_key", b"message", b"signature");

        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "Ed25519-was-called", "Expected ed25519 algorithm to be dispatched to");
            }
            _ => panic!("Expected InvalidKey error from key provider"),
        }
    }

    #[test]
    fn test_verify_signature_rsa_pkcs1() {
        let provider = tagged_provider();

        let result = provider.verify_signature(
            SignatureAlgorithmId::RsaPkcs1Sha256,
            b"public_key",
            b"message",
            b"signature",
        );

        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "RsaPkcs1Sha256-was-called", "Expected rsa algorithm to be dispatched to");
            }
            _ => panic!("Expected InvalidKey error from key provider"),
        }
    }

    #[test]
    fn test_verify_signature_rsa_pss() {
        let provider = tagged_provider();

        let result = provider.verify_signature(
            SignatureAlgorithmId::RsaPssSha256,
            b"public_key",
            b"message",
            b"signature",
        );

        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "RsaPssSha256-was-called", "Expected rsa algorithm to be dispatched to");
            }
            _ => panic!("Expected InvalidKey error from key provider"),
        }
    }

    #[test]
    fn test_verify_signature_unknown() {
        let provider = tagged_provider();

        let result = provider.verify_signature(SignatureAlgorithmId::Unknown, b"public_key", b"message", b"signature");

        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "unknown signature algorithm");
            }
            _ => panic!("Expected InvalidKey error"),
        }
    }

    #[test]
    fn test_verify_signature_verifier_fails() {
        let provider = CryptoProvider {
            key_provider: &FAILURE_KEY_PROVIDER,
            sha256: &FAKE_DIGEST,
        };

        let result = provider.verify_signature(
            SignatureAlgorithmId::EcdsaP256Sha256,
            b"public_key",
            b"message",
            b"signature",
        );

        assert!(result.is_err());
        match result {
            Err(CryptoError::VerificationFailed) => {}
            _ => panic!("Expected VerificationFailed error"),
        }
    }
}