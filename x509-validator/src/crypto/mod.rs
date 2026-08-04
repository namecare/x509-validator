use std::fmt::Debug;
use x509_validator_core::SignatureAlgorithmId;

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("invalid key encoding: {0}")]
    InvalidKey(String),
    #[error("signature verification failed")]
    VerificationFailed,
}

pub trait SignatureVerifier: Send + Sync + Debug {
    fn verify(&self, public_key_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

pub trait Digest: Send + Sync + Debug {
    fn hash(&self, data: &[u8]) -> Vec<u8>;
}

pub struct CryptoProvider {
    pub p256: &'static dyn SignatureVerifier,
    pub p384: &'static dyn SignatureVerifier,
    pub p521: &'static dyn SignatureVerifier,
    pub rsa: &'static dyn SignatureVerifier,
    pub ed25519: &'static dyn SignatureVerifier,
    pub sha256: &'static dyn Digest,
}

/// A `SignatureVerifier`/`Digest` pair that always fails, used to populate
/// `CryptoProvider::default_backend` until a real crypto backend is wired
/// in. Every call reports that no backend has been configured.
#[derive(Debug)]
struct UnconfiguredCryptoBackend;

impl SignatureVerifier for UnconfiguredCryptoBackend {
    fn verify(&self, _public_key_der: &[u8], _message: &[u8], _signature: &[u8]) -> Result<(), CryptoError> {
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
    /// A `CryptoProvider` whose signature verifiers all fail with
    /// `CryptoError::InvalidKey`. Used as the default backend for
    /// `Verifier::new`, which has no way to accept a caller-supplied
    /// backend; callers who need real signature verification should use
    /// `Verifier::with_policy_and_backend` with an actual `CryptoProvider`
    /// instead.
    pub fn default_backend() -> &'static CryptoProvider {
        static DEFAULT: CryptoProvider = CryptoProvider {
            p256: &UNCONFIGURED_CRYPTO_BACKEND,
            p384: &UNCONFIGURED_CRYPTO_BACKEND,
            p521: &UNCONFIGURED_CRYPTO_BACKEND,
            rsa: &UNCONFIGURED_CRYPTO_BACKEND,
            ed25519: &UNCONFIGURED_CRYPTO_BACKEND,
            sha256: &UNCONFIGURED_CRYPTO_BACKEND,
        };
        &DEFAULT
    }

    /// Dispatches to the sub-verifier matching `algorithm`. This is the one
    /// crypto call site the chain-building core uses to check a candidate
    /// issuer's signature over a certificate.
    pub fn verify_signature(
        &self,
        algorithm: SignatureAlgorithmId,
        public_key_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let verifier: &dyn SignatureVerifier = match algorithm {
            SignatureAlgorithmId::EcdsaP256Sha256 => self.p256,
            SignatureAlgorithmId::EcdsaP384Sha384 => self.p384,
            SignatureAlgorithmId::EcdsaP521Sha512 => self.p521,
            SignatureAlgorithmId::Ed25519 => self.ed25519,
            SignatureAlgorithmId::RsaPkcs1Sha256 | SignatureAlgorithmId::RsaPssSha256 => self.rsa,
            SignatureAlgorithmId::Unknown => {
                return Err(CryptoError::InvalidKey("unknown signature algorithm".into()));
            }
        };
        verifier.verify(public_key_der, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tagged SignatureVerifier that returns a distinct error message
    /// to identify which field/verifier instance was called.
    #[derive(Debug)]
    struct TaggedVerifier(&'static str);

    impl SignatureVerifier for TaggedVerifier {
        fn verify(&self, _public_key_der: &[u8], _message: &[u8], _signature: &[u8]) -> Result<(), CryptoError> {
            Err(CryptoError::InvalidKey(self.0.to_string()))
        }
    }

    /// Fake SignatureVerifier that always fails with VerificationFailed
    #[derive(Debug)]
    struct FailureVerifier;

    impl SignatureVerifier for FailureVerifier {
        fn verify(&self, _public_key_der: &[u8], _message: &[u8], _signature: &[u8]) -> Result<(), CryptoError> {
            Err(CryptoError::VerificationFailed)
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

    // Static instances with distinct tags for each algorithm field
    static P256_VERIFIER: TaggedVerifier = TaggedVerifier("p256-was-called");
    static P384_VERIFIER: TaggedVerifier = TaggedVerifier("p384-was-called");
    static P521_VERIFIER: TaggedVerifier = TaggedVerifier("p521-was-called");
    static RSA_VERIFIER: TaggedVerifier = TaggedVerifier("rsa-was-called");
    static ED25519_VERIFIER: TaggedVerifier = TaggedVerifier("ed25519-was-called");
    static FAILURE_VERIFIER: FailureVerifier = FailureVerifier;
    static FAKE_DIGEST: FakeDigest = FakeDigest;

    #[test]
    fn test_verify_signature_ecdsa_p256() {
        let provider = CryptoProvider {
            p256: &P256_VERIFIER,
            p384: &P384_VERIFIER,
            p521: &P521_VERIFIER,
            rsa: &RSA_VERIFIER,
            ed25519: &ED25519_VERIFIER,
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
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "p256-was-called", "Expected p256 field to be dispatched to");
            }
            _ => panic!("Expected InvalidKey error from p256 verifier"),
        }
    }

    #[test]
    fn test_verify_signature_ecdsa_p384() {
        let provider = CryptoProvider {
            p256: &P256_VERIFIER,
            p384: &P384_VERIFIER,
            p521: &P521_VERIFIER,
            rsa: &RSA_VERIFIER,
            ed25519: &ED25519_VERIFIER,
            sha256: &FAKE_DIGEST,
        };

        let result = provider.verify_signature(
            SignatureAlgorithmId::EcdsaP384Sha384,
            b"public_key",
            b"message",
            b"signature",
        );

        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "p384-was-called", "Expected p384 field to be dispatched to");
            }
            _ => panic!("Expected InvalidKey error from p384 verifier"),
        }
    }

    #[test]
    fn test_verify_signature_ecdsa_p521() {
        let provider = CryptoProvider {
            p256: &P256_VERIFIER,
            p384: &P384_VERIFIER,
            p521: &P521_VERIFIER,
            rsa: &RSA_VERIFIER,
            ed25519: &ED25519_VERIFIER,
            sha256: &FAKE_DIGEST,
        };

        let result = provider.verify_signature(
            SignatureAlgorithmId::EcdsaP521Sha512,
            b"public_key",
            b"message",
            b"signature",
        );

        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "p521-was-called", "Expected p521 field to be dispatched to");
            }
            _ => panic!("Expected InvalidKey error from p521 verifier"),
        }
    }

    #[test]
    fn test_verify_signature_ed25519() {
        let provider = CryptoProvider {
            p256: &P256_VERIFIER,
            p384: &P384_VERIFIER,
            p521: &P521_VERIFIER,
            rsa: &RSA_VERIFIER,
            ed25519: &ED25519_VERIFIER,
            sha256: &FAKE_DIGEST,
        };

        let result = provider.verify_signature(
            SignatureAlgorithmId::Ed25519,
            b"public_key",
            b"message",
            b"signature",
        );

        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "ed25519-was-called", "Expected ed25519 field to be dispatched to");
            }
            _ => panic!("Expected InvalidKey error from ed25519 verifier"),
        }
    }

    #[test]
    fn test_verify_signature_rsa_pkcs1() {
        let provider = CryptoProvider {
            p256: &P256_VERIFIER,
            p384: &P384_VERIFIER,
            p521: &P521_VERIFIER,
            rsa: &RSA_VERIFIER,
            ed25519: &ED25519_VERIFIER,
            sha256: &FAKE_DIGEST,
        };

        let result = provider.verify_signature(
            SignatureAlgorithmId::RsaPkcs1Sha256,
            b"public_key",
            b"message",
            b"signature",
        );

        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "rsa-was-called", "Expected rsa field to be dispatched to");
            }
            _ => panic!("Expected InvalidKey error from rsa verifier"),
        }
    }

    #[test]
    fn test_verify_signature_rsa_pss() {
        let provider = CryptoProvider {
            p256: &P256_VERIFIER,
            p384: &P384_VERIFIER,
            p521: &P521_VERIFIER,
            rsa: &RSA_VERIFIER,
            ed25519: &ED25519_VERIFIER,
            sha256: &FAKE_DIGEST,
        };

        let result = provider.verify_signature(
            SignatureAlgorithmId::RsaPssSha256,
            b"public_key",
            b"message",
            b"signature",
        );

        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "rsa-was-called", "Expected rsa field to be dispatched to");
            }
            _ => panic!("Expected InvalidKey error from rsa verifier"),
        }
    }

    #[test]
    fn test_verify_signature_unknown() {
        let provider = CryptoProvider {
            p256: &P256_VERIFIER,
            p384: &P384_VERIFIER,
            p521: &P521_VERIFIER,
            rsa: &RSA_VERIFIER,
            ed25519: &ED25519_VERIFIER,
            sha256: &FAKE_DIGEST,
        };

        let result = provider.verify_signature(
            SignatureAlgorithmId::Unknown,
            b"public_key",
            b"message",
            b"signature",
        );

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
            p256: &FAILURE_VERIFIER,
            p384: &FAILURE_VERIFIER,
            p521: &FAILURE_VERIFIER,
            rsa: &FAILURE_VERIFIER,
            ed25519: &FAILURE_VERIFIER,
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
