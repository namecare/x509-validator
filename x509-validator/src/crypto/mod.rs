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

/// A `KeyProvider`/`Digest` pair whose every operation panics, reporting that
/// no single backend could be determined from the crate's features.
///
/// A provider that instead failed each signature check quietly would report
/// perfectly good chains as unvalidatable — indistinguishable from a genuine
/// policy failure. This is a build misconfiguration, so it surfaces as one the
/// first time crypto is actually used.
#[derive(Debug)]
struct UndeterminedCryptoBackend;

const NO_BACKEND_ERROR: &str = "
Could not automatically determine the crypto backend from x509-validator crate features.
Make sure exactly one of the 'aws_lc', 'ring' and 'rust_crypto' features is enabled, or pass a
provider explicitly to Validator::with_policy_and_backend instead of Validator::with_policy.
";

impl KeyProvider for UndeterminedCryptoBackend {
    fn public_key(&self, _algorithm: &AlgorithmIdentifier, _public_key: &SubjectPublicKeyInfo) -> Result<Box<dyn PublicKey>, CryptoError> {
        panic!("{NO_BACKEND_ERROR}")
    }
}

impl Digest for UndeterminedCryptoBackend {
    fn hash(&self, _data: &[u8]) -> Vec<u8> {
        panic!("{NO_BACKEND_ERROR}")
    }
}

/// The crypto backend determined by this crate's feature flags.
///
/// This is what [`crate::Validator::with_policy`] uses, so that callers name a
/// backend once in `Cargo.toml` rather than at every construction site. Pass a
/// provider to [`crate::Validator::with_policy_and_backend`] to override it for
/// an individual validator.
///
/// A backend is determined only when *exactly one* backend feature is enabled.
/// Enabling several is allowed — the comparison benchmarks verify one chain
/// under each in a single process — but leaves no single default to name, so
/// that configuration, like enabling none, yields a provider whose every
/// operation panics with [`NO_BACKEND_ERROR`]. Backends stay individually
/// reachable as `crypto::<backend>::DEFAULT_PROVIDER` regardless.
pub fn default_provider() -> &'static CryptoProvider {
    #[cfg(all(feature = "aws_lc", not(feature = "ring"), not(feature = "rust_crypto")))]
    {
        return &aws_lc::DEFAULT_PROVIDER;
    }

    #[cfg(all(feature = "ring", not(feature = "aws_lc"), not(feature = "rust_crypto")))]
    {
        return &ring::DEFAULT_PROVIDER;
    }

    #[cfg(all(feature = "rust_crypto", not(feature = "aws_lc"), not(feature = "ring")))]
    {
        return &rust_crypto::DEFAULT_PROVIDER;
    }

    // Reached when zero backends are enabled, or when several are and none can
    // be preferred over the others.
    #[allow(unreachable_code)]
    {
        static UNDETERMINED_BACKEND: UndeterminedCryptoBackend = UndeterminedCryptoBackend;
        static INSTANCE: CryptoProvider = CryptoProvider {
            key_provider: &UNDETERMINED_BACKEND,
            sha256: &UNDETERMINED_BACKEND,
        };

        &INSTANCE
    }
}

impl CryptoProvider {
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
    use x509_validator_core::CertificateExt;
    use x509_validator_core::Certificate;

    /// A real self-signed certificate's `AlgorithmIdentifier` and
    /// `SubjectPublicKeyInfo`, for tests that only need *some* valid values
    /// of these types rather than to exercise a specific algorithm.
    fn algorithm_and_spki() -> (AlgorithmIdentifier<'static>, SubjectPublicKeyInfo<'static>) {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der = CertificateParams::default().self_signed(&key_pair).expect("self-sign").der().to_vec();
        let der: &'static [u8] = Box::leak(der.into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");
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