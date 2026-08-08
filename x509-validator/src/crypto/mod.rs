#[macro_use]
mod backend;

#[cfg(feature = "aws_lc")]
pub mod aws_lc;
#[cfg(feature = "ring")]
pub mod ring;
#[cfg(feature = "rust_crypto")]
pub mod rust_crypto;

use std::fmt::Debug;
use x509_validator_core::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

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

/// Provides public keys usable for signature verification, given the
/// signer's SPKI and the algorithm the signature to verify was made with.
pub trait KeyProvider: Send + Sync + Debug {
    fn public_key(&self, algorithm: &AlgorithmIdentifier, public_key: &SubjectPublicKeyInfo) -> Result<Box<dyn PublicKey>, CryptoError>;
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
    fn public_key(&self, _algorithm: &AlgorithmIdentifier, _public_key: &SubjectPublicKeyInfo) -> Result<Box<dyn PublicKey>, CryptoError> {
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
    /// `CryptoError::InvalidKey`.
    pub fn default_backend() -> &'static CryptoProvider {
        static DEFAULT: CryptoProvider = CryptoProvider {
            key_provider: &UNCONFIGURED_CRYPTO_BACKEND,
            sha256: &UNCONFIGURED_CRYPTO_BACKEND,
        };
        &DEFAULT
    }

    /// Looks up the public key for `algorithm`/`public_key` and checks
    /// `signature` over `message`. This is the one crypto call site the
    /// chain-building core uses to check a candidate issuer's signature
    /// over a certificate.
    pub fn verify_signature(
        &self,
        algorithm: &AlgorithmIdentifier,
        public_key: &SubjectPublicKeyInfo,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let key = self.key_provider.public_key(algorithm, public_key)?;
        key.is_valid(signature, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_validator_testkit::rcgen::{CertificateParams, KeyPair};
    use x509_validator_core::FromDer;
    use x509_validator_core::Certificate;

    /// A real self-signed certificate's `AlgorithmIdentifier` and
    /// `SubjectPublicKeyInfo`, for tests that only need *some* valid values
    /// of these types rather than to exercise a specific algorithm.
    fn algorithm_and_spki() -> (AlgorithmIdentifier<'static>, SubjectPublicKeyInfo<'static>) {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der = CertificateParams::default().self_signed(&key_pair).expect("self-sign").der().to_vec();
        let der: &'static [u8] = Box::leak(der.into_boxed_slice());
        let cert = Certificate::from_der(der).unwrap().1;
        (cert.signature_algorithm, cert.tbs_certificate.subject_pki)
    }

    /// Tagged KeyProvider that returns a distinct error message from
    /// `public_key` to identify which algorithm it was dispatched for.
    #[derive(Debug)]
    struct TaggedKeyProvider;

    impl KeyProvider for TaggedKeyProvider {
        fn public_key(&self, algorithm: &AlgorithmIdentifier, _public_key: &SubjectPublicKeyInfo) -> Result<Box<dyn PublicKey>, CryptoError> {
            Err(CryptoError::InvalidKey(format!("{}-was-called", algorithm.algorithm)))
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
        fn public_key(&self, _algorithm: &AlgorithmIdentifier, _public_key: &SubjectPublicKeyInfo) -> Result<Box<dyn PublicKey>, CryptoError> {
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
    fn verify_signature_dispatches_by_algorithm_oid() {
        let provider = tagged_provider();
        let (algorithm, spki) = algorithm_and_spki();

        let result = provider.verify_signature(&algorithm, &spki, b"message", b"signature");

        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, format!("{}-was-called", algorithm.algorithm));
            }
            _ => panic!("Expected InvalidKey error from key provider"),
        }
    }

    #[test]
    fn verify_signature_verifier_fails() {
        let provider = CryptoProvider {
            key_provider: &FAILURE_KEY_PROVIDER,
            sha256: &FAKE_DIGEST,
        };
        let (algorithm, spki) = algorithm_and_spki();

        let result = provider.verify_signature(&algorithm, &spki, b"message", b"signature");

        assert!(result.is_err());
        match result {
            Err(CryptoError::VerificationFailed) => {}
            _ => panic!("Expected VerificationFailed error"),
        }
    }
}