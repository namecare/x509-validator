#[cfg(any(feature = "aws_lc", feature = "ring", feature = "rust_crypto"))]
#[macro_use]
mod backend;

#[cfg(feature = "aws_lc")]
pub mod aws_lc;
#[cfg(feature = "ring")]
pub mod ring;
#[cfg(feature = "rust_crypto")]
pub mod rust_crypto;

use core::fmt::Debug;

use crate::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use crate::{Any, RsaSsaPssParams, oid_registry};

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("invalid key encoding: {0}")]
    InvalidKey(String),
    #[error("signature verification failed")]
    VerificationFailed,
}

/// Checks one signature over one message, given the signer's SPKI and the
/// algorithm the signature was made with.
///
/// This is the whole contract between the chain-building core and a crypto
/// library: implement it and any backend drops in, whether or not its keys can
/// be usefully prepared ahead of the message. Backends that do have a
/// reusable key type build one inside `verify_signature`; those that carry
/// per-algorithm state (an OpenSSL digest, a PSS flag) simply keep it in local
/// variables rather than in a struct that outlives the call.
pub trait SignatureVerifier: Send + Sync + Debug {
    fn verify_signature(
        &self,
        algorithm: &AlgorithmIdentifier<'_>,
        public_key: &SubjectPublicKeyInfo<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;
}

/// A `SignatureVerifier` whose every operation panics, reporting that
/// no single backend could be determined from the crate's features.
#[derive(Debug)]
struct UndeterminedCryptoBackend;

const NO_BACKEND_ERROR: &str = "
Could not automatically determine the crypto backend from x509-validator crate features.
Make sure exactly one of the 'aws_lc', 'ring' and 'rust_crypto' features is enabled, or pass a
provider explicitly to Validator::with_policy_and_backend instead of Validator::with_policy.
";

impl SignatureVerifier for UndeterminedCryptoBackend {
    fn verify_signature(
        &self,
        _algorithm: &AlgorithmIdentifier<'_>,
        _public_key: &SubjectPublicKeyInfo<'_>,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        panic!("{NO_BACKEND_ERROR}")
    }
}

/// The crypto backend determined by this crate's feature flags.
pub fn default_provider() -> &'static dyn SignatureVerifier {
    #[cfg(all(
        feature = "aws_lc",
        not(feature = "ring"),
        not(feature = "rust_crypto")
    ))]
    {
        return &aws_lc::DEFAULT_PROVIDER;
    }

    #[cfg(all(
        feature = "ring",
        not(feature = "aws_lc"),
        not(feature = "rust_crypto")
    ))]
    {
        return &ring::DEFAULT_PROVIDER;
    }

    #[cfg(all(
        feature = "rust_crypto",
        not(feature = "aws_lc"),
        not(feature = "ring")
    ))]
    {
        return &rust_crypto::DEFAULT_PROVIDER;
    }

    // Reached when zero backends are enabled
    #[allow(unreachable_code)]
    {
        static UNDETERMINED_BACKEND: UndeterminedCryptoBackend = UndeterminedCryptoBackend;

        &UNDETERMINED_BACKEND
    }
}

pub fn rsa_pss_digest_bits(params: Option<&Any<'_>>) -> Option<usize> {
    let params = params?;
    let params = RsaSsaPssParams::try_from(params).ok()?;
    let hash_algorithm = params.hash_algorithm_oid();

    if *hash_algorithm == oid_registry::OID_NIST_HASH_SHA256 {
        Some(256)
    } else if *hash_algorithm == oid_registry::OID_NIST_HASH_SHA384 {
        Some(384)
    } else if *hash_algorithm == oid_registry::OID_NIST_HASH_SHA512 {
        Some(512)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use x509_validator_testkit::rcgen::{CertificateParams, KeyPair};

    use super::*;
    use crate::{Certificate, CertificateExt, FromDer};

    /// The DER of a real self-signed certificate, for tests that only need
    /// *some* valid `AlgorithmIdentifier` and `SubjectPublicKeyInfo` rather
    /// than to exercise a specific algorithm.
    ///
    /// Those two values borrow the certificate they came from, which in turn
    /// borrows this DER, so the caller owns the bytes for as long as it uses
    /// them; see [`algorithm_and_spki`].
    fn self_signed_der() -> Vec<u8> {
        let key_pair = KeyPair::generate().expect("generate key pair");
        CertificateParams::default()
            .self_signed(&key_pair)
            .expect("self-sign")
            .der()
            .to_vec()
    }

    /// A real self-signed certificate's `AlgorithmIdentifier` and
    /// `SubjectPublicKeyInfo`, borrowed from DER the caller owns.
    fn algorithm_and_spki(der: &[u8]) -> (AlgorithmIdentifier<'_>, SubjectPublicKeyInfo<'_>) {
        let cert = Certificate::parse(der).expect("parse certificate");
        (cert.signature_algorithm, cert.tbs_certificate.subject_pki)
    }

    /// Tagged verifier reporting, through the error it returns, which
    /// algorithm it was handed.
    #[derive(Debug)]
    struct TaggedVerifier;

    impl SignatureVerifier for TaggedVerifier {
        fn verify_signature(
            &self,
            algorithm: &AlgorithmIdentifier<'_>,
            _public_key: &SubjectPublicKeyInfo<'_>,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Err(CryptoError::InvalidKey(format!(
                "{}-was-called",
                algorithm.algorithm
            )))
        }
    }

    /// Fake verifier that always reports the signature as bad.
    #[derive(Debug)]
    struct FailureVerifier;

    impl SignatureVerifier for FailureVerifier {
        fn verify_signature(
            &self,
            _algorithm: &AlgorithmIdentifier<'_>,
            _public_key: &SubjectPublicKeyInfo<'_>,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Err(CryptoError::VerificationFailed)
        }
    }

    #[test]
    fn verify_signature_receives_the_signature_algorithm() {
        let der = self_signed_der();
        let (algorithm, spki) = algorithm_and_spki(&der);

        let result = TaggedVerifier.verify_signature(&algorithm, &spki, b"message", b"signature");

        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, format!("{}-was-called", algorithm.algorithm));
            }
            _ => panic!("Expected InvalidKey error naming the algorithm, got {result:?}"),
        }
    }

    #[test]
    fn verify_signature_propagates_verification_failure() {
        let der = self_signed_der();
        let (algorithm, spki) = algorithm_and_spki(&der);

        let result = FailureVerifier.verify_signature(&algorithm, &spki, b"message", b"signature");

        assert!(matches!(result, Err(CryptoError::VerificationFailed)));
    }

    #[test]
    fn absent_parameters_yield_no_digest() {
        assert_eq!(rsa_pss_digest_bits(None), None);
    }

    #[test]
    fn undecodable_parameters_yield_no_digest() {
        // A NULL where `RSASSA-PSS-params` (a SEQUENCE) is expected.
        let params = Any::from_der(&[0x05, 0x00])
            .expect("parse NULL")
            .1;

        assert_eq!(rsa_pss_digest_bits(Some(&params)), None);
    }

    /// DER for `RSASSA-PSS-params` carrying only a `hashAlgorithm` of `oid`.
    fn pss_params_der(oid_der: &[u8]) -> Vec<u8> {
        // AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER }
        let mut algorithm_identifier = vec![0x30, oid_der.len() as u8];
        algorithm_identifier.extend_from_slice(oid_der);

        // hashAlgorithm is context tag [0], explicit.
        let mut tagged = vec![0xa0, algorithm_identifier.len() as u8];
        tagged.extend_from_slice(&algorithm_identifier);

        // RSASSA-PSS-params ::= SEQUENCE { [0] hashAlgorithm ... }
        let mut params = vec![0x30, tagged.len() as u8];
        params.extend_from_slice(&tagged);
        params
    }

    #[test]
    fn sha2_hash_algorithms_yield_their_digest_size() {
        // OIDs 2.16.840.1.101.3.4.2.{1,2,3} = SHA-256 / SHA-384 / SHA-512.
        for (last_octet, expected) in [(0x01, 256), (0x02, 384), (0x03, 512)] {
            let oid_der = [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last_octet,
            ];
            let der = pss_params_der(&oid_der);
            let params = Any::from_der(&der)
                .expect("parse PSS params")
                .1;

            assert_eq!(rsa_pss_digest_bits(Some(&params)), Some(expected));
        }
    }

    #[test]
    fn non_sha2_hash_algorithm_yields_no_digest() {
        // OID 1.3.14.3.2.26 = SHA-1, which no backend supports for RSA-PSS.
        let oid_der = [0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];
        let der = pss_params_der(&oid_der);
        let params = Any::from_der(&der)
            .expect("parse PSS params")
            .1;

        assert_eq!(rsa_pss_digest_bits(Some(&params)), None);
    }
}
