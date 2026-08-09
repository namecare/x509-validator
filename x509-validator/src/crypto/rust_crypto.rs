//! RustCrypto backed crypto backend.
//!
//! Unlike the aws-lc-rs and ring backends, this one is not built from the
//! [`backend!`] macro: RustCrypto ships no single `UnparsedPublicKey` type
//! pairing an algorithm constant with key bytes. Verification lives in
//! per-algorithm crates (`rsa`, `p256`, `p384`, `ed25519-dalek`), each with
//! its own key and signature types, so the algorithm choice is carried by a
//! plain enum and dispatched to a method that builds its own verifier.
//!
//! Coverage matches ring: RSA PKCS#1 v1.5 (SHA-1 for legacy use, SHA-256/384/512),
//! RSA-PSS (SHA-256/384/512), ECDSA P-256/P-384 with SHA-256/384, and Ed25519.
//! ECDSA-with-SHA512 is reported as unsupported rather than verified under a
//! different digest.

use signature::Verifier;

use x509_validator_core::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use crate::crypto::backend::{VerificationAlgorithm, verification_algorithm};
use crate::crypto::{CryptoError, SignatureVerifier};

/// The RSA modulus sizes, in bytes, this backend will verify against.
///
/// The other backends inherit these bounds from the named algorithms they dispatch to
/// (`RSA_PKCS1_2048_8192_*`), while the RSA crate imposes no limit of its own. Applying the same
/// bounds here keeps a chain's fate from depending on which backend happens to be compiled in: a
/// factorable modulus must not verify merely because this backend was selected, and an absurdly
/// large one must not turn verification into a denial of service.
const MIN_RSA_MODULUS_BYTES: usize = 2048 / 8;
const MAX_RSA_MODULUS_BYTES: usize = 8192 / 8;

/// Marker type implementing every capability this backend provides.
#[derive(Debug)]
pub struct RustCrypto;

impl SignatureVerifier for RustCrypto {
    fn verify_signature(
        &self,
        algorithm: &AlgorithmIdentifier,
        public_key: &SubjectPublicKeyInfo,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let unsupported =
            || CryptoError::InvalidKey(format!("unsupported algorithm: {}", algorithm.algorithm));
        let verification_algorithm =
            verification_algorithm(algorithm, public_key).ok_or_else(unsupported)?;

        // Which form of the key an arm needs is its own decision: RSA and
        // Ed25519 parse the full SPKI, while ECDSA takes the `subjectPublicKey`
        // BIT STRING as a SEC1 curve point. Both are borrowed from the caller,
        // and a key that fails to parse is an `InvalidKey`.
        let spki_der = &public_key.raw;
        let key_bytes = public_key.subject_public_key.as_ref();

        // ECDSA-with-SHA512 has no arm on either curve: like ring, this
        // backend does not ship it, so it is reported as unsupported rather
        // than verified under a different digest.
        match verification_algorithm {
            VerificationAlgorithm::RsaPkcs1Sha1 => Self::verify_rsa_pkcs1::<sha1::Sha1>(spki_der, signature, message),
            VerificationAlgorithm::RsaPkcs1Sha256 => Self::verify_rsa_pkcs1::<sha2::Sha256>(spki_der, signature, message),
            VerificationAlgorithm::RsaPkcs1Sha384 => Self::verify_rsa_pkcs1::<sha2::Sha384>(spki_der, signature, message),
            VerificationAlgorithm::RsaPkcs1Sha512 => Self::verify_rsa_pkcs1::<sha2::Sha512>(spki_der, signature, message),
            VerificationAlgorithm::RsaPssSha256 => Self::verify_rsa_pss::<sha2::Sha256>(spki_der, signature, message),
            VerificationAlgorithm::RsaPssSha384 => Self::verify_rsa_pss::<sha2::Sha384>(spki_der, signature, message),
            VerificationAlgorithm::RsaPssSha512 => Self::verify_rsa_pss::<sha2::Sha512>(spki_der, signature, message),
            VerificationAlgorithm::EcdsaP256Sha256 => Self::verify_ecdsa_p256_sha256(key_bytes, signature, message),
            VerificationAlgorithm::EcdsaP256Sha384 => Self::verify_ecdsa_p256_sha384(key_bytes, signature, message),
            VerificationAlgorithm::EcdsaP384Sha256 => Self::verify_ecdsa_p384_sha256(key_bytes, signature, message),
            VerificationAlgorithm::EcdsaP384Sha384 => Self::verify_ecdsa_p384_sha384(key_bytes, signature, message),
            VerificationAlgorithm::Ed25519 => Self::verify_ed25519(key_bytes, signature, message),
            VerificationAlgorithm::EcdsaP256Sha512 | VerificationAlgorithm::EcdsaP384Sha512 => {
                Err(unsupported())
            }
        }
    }
}

impl RustCrypto {
    /// Loads the signer's RSA key from its `SubjectPublicKeyInfo` DER,
    /// refusing a modulus outside the supported range.
    fn rsa_public_key(spki_der: &[u8]) -> Result<rsa::RsaPublicKey, CryptoError> {
        use rsa::pkcs8::DecodePublicKey;
        use rsa::traits::PublicKeyParts;

        let key = rsa::RsaPublicKey::from_public_key_der(spki_der)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let modulus_bytes = key.size();
        if !(MIN_RSA_MODULUS_BYTES..=MAX_RSA_MODULUS_BYTES).contains(&modulus_bytes) {
            return Err(CryptoError::InvalidKey(format!(
                "RSA modulus of {} bits is outside the supported range of {}-{} bits",
                modulus_bytes * 8,
                MIN_RSA_MODULUS_BYTES * 8,
                MAX_RSA_MODULUS_BYTES * 8
            )));
        }

        Ok(key)
    }

    /// `AssociatedOid` is what supplies the DigestInfo prefix PKCS#1 v1.5
    /// verification prepends to the hash.
    fn verify_rsa_pkcs1<D>(spki_der: &[u8], signature: &[u8], message: &[u8]) -> Result<(), CryptoError>
    where
        D: sha2::Digest + rsa::pkcs8::AssociatedOid,
    {
        let verifying_key = rsa::pkcs1v15::VerifyingKey::<D>::new(Self::rsa_public_key(spki_der)?);
        let signature = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    /// PSS reuses one digest instance across the MGF1 rounds, hence
    /// `FixedOutputReset` rather than the PKCS#1 path's OID bound.
    fn verify_rsa_pss<D>(spki_der: &[u8], signature: &[u8], message: &[u8]) -> Result<(), CryptoError>
    where
        D: sha2::Digest + sha2::digest::FixedOutputReset,
    {
        let verifying_key = rsa::pss::VerifyingKey::<D>::new(Self::rsa_public_key(spki_der)?);
        let signature =
            rsa::pss::Signature::try_from(signature).map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_ecdsa_p256_sha256(key_bytes: &[u8], signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let signature = p256::ecdsa::DerSignature::try_from(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    /// P-256 with SHA-384 has no dedicated verifier in `p256`, whose
    /// `VerifyingKey: Verifier` impl is fixed to the curve's own digest, so
    /// the message is hashed here and verified against the prehash.
    fn verify_ecdsa_p256_sha384(key_bytes: &[u8], signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
        use sha2::Digest as _;
        use signature::hazmat::PrehashVerifier;

        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let signature = p256::ecdsa::Signature::from_der(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify_prehash(&sha2::Sha384::digest(message), &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    /// P-384's `Verifier` impl is likewise fixed to SHA-384, so SHA-256 goes
    /// through the prehash path.
    fn verify_ecdsa_p384_sha256(key_bytes: &[u8], signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
        use sha2::Digest as _;
        use signature::hazmat::PrehashVerifier;

        let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let signature = p384::ecdsa::Signature::from_der(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify_prehash(&sha2::Sha256::digest(message), &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_ecdsa_p384_sha384(key_bytes: &[u8], signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
        let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let signature = p384::ecdsa::DerSignature::try_from(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_ed25519(key_bytes: &[u8], signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
        let verifying_key = ed25519_dalek::VerifyingKey::try_from(key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

/// The backend itself. Callers name it as the `crypto` argument to
/// [`crate::Validator::with_policy_and_backend`].
pub static DEFAULT_PROVIDER: RustCrypto = RustCrypto;

#[cfg(test)]
mod tests {
    use super::*;
    use x509_validator_core::oid_registry;
    use x509_validator_core::Certificate;
    use x509_validator_core::CertificateExt;
    use x509_validator_testkit::rcgen::{self, CertificateParams, KeyPair};

    /// Builds a real self-signed certificate for `key_pair` and parses it
    /// back, giving tests a genuine `AlgorithmIdentifier`/`SubjectPublicKeyInfo`
    /// pair straight from a real DER encoding rather than hand-assembled
    /// ASN.1 structs.
    fn self_signed(key_pair: &KeyPair) -> Vec<u8> {
        let params = CertificateParams::default();
        params.self_signed(key_pair).expect("self-sign").der().to_vec()
    }

    #[test]
    fn ecdsa_p256_round_trip_verifies() {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

                let result = RustCrypto.verify_signature(
            &cert.signature_algorithm,
            cert.public_key(),
            cert.tbs_certificate.as_ref(),
            cert.signature_value.as_ref(),
        );
        assert!(result.is_ok(), "expected valid signature to verify, got {result:?}");
    }

    #[test]
    fn ecdsa_p256_tampered_message_fails() {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

                let result = RustCrypto.verify_signature(
            &cert.signature_algorithm,
            cert.public_key(),
            b"tampered message",
            cert.signature_value.as_ref(),
        );
        assert!(matches!(result, Err(CryptoError::VerificationFailed)));
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let algorithm = AlgorithmIdentifier {
            algorithm: oid_registry::OID_SIG_ED448,
            parameters: None,
        };
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

        let result = RustCrypto.verify_signature(&algorithm, cert.public_key(), b"message", b"signature");
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    /// Like ring, and unlike the aws_lc backend, this backend has no
    /// ECDSA-with-SHA512 pairing, so it is reported as unsupported rather
    /// than silently verified with a different digest.
    #[test]
    fn ecdsa_sha512_is_unsupported() {
        let algorithm = AlgorithmIdentifier {
            algorithm: oid_registry::OID_SIG_ECDSA_WITH_SHA512,
            parameters: None,
        };
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

        let result = RustCrypto.verify_signature(&algorithm, cert.public_key(), b"message", b"signature");
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    /// Self-signs under `algorithm` and checks the resulting signature
    /// verifies, exercising one arm of `is_valid` end to end against a
    /// signature this backend did not produce.
    fn assert_round_trip(algorithm: &'static rcgen::SignatureAlgorithm) {
        let key_pair = KeyPair::generate_for(algorithm).expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

                let result = RustCrypto.verify_signature(
            &cert.signature_algorithm,
            cert.public_key(),
            cert.tbs_certificate.as_ref(),
            cert.signature_value.as_ref(),
        );
        assert!(result.is_ok(), "expected valid signature to verify, got {result:?}");
    }

    /// rcgen cannot generate RSA keys unless built against aws-lc-rs, which
    /// the testkit is not, so one is generated with the `rsa` crate and handed
    /// to rcgen as PKCS#8 to sign with. Generating a 2048-bit key is slow
    /// enough that the three digest variants share a single key.
    fn rsa_key_pair(algorithm: &'static rcgen::SignatureAlgorithm) -> KeyPair {
        use rsa::pkcs8::EncodePrivateKey;

        static PKCS8_DER: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

        let der = PKCS8_DER.get_or_init(|| {
            let mut rng = rand::thread_rng();
            let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
            private_key.to_pkcs8_der().expect("encode PKCS#8").as_bytes().to_vec()
        });

        KeyPair::from_pkcs8_der_and_sign_algo(&der.as_slice().into(), algorithm)
            .expect("build RSA key pair")
    }

    /// The RSA counterpart of `assert_round_trip`, differing only in where
    /// the key comes from.
    fn assert_rsa_round_trip(algorithm: &'static rcgen::SignatureAlgorithm) {
        let key_pair = rsa_key_pair(algorithm);
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

                let result = RustCrypto.verify_signature(
            &cert.signature_algorithm,
            cert.public_key(),
            cert.tbs_certificate.as_ref(),
            cert.signature_value.as_ref(),
        );
        assert!(result.is_ok(), "expected valid signature to verify, got {result:?}");
    }

    #[test]
    fn rsa_pkcs1_sha256_round_trip_verifies() {
        assert_rsa_round_trip(&rcgen::PKCS_RSA_SHA256);
    }

    #[test]
    fn rsa_pkcs1_sha384_round_trip_verifies() {
        assert_rsa_round_trip(&rcgen::PKCS_RSA_SHA384);
    }

    #[test]
    fn rsa_pkcs1_sha512_round_trip_verifies() {
        assert_rsa_round_trip(&rcgen::PKCS_RSA_SHA512);
    }

    /// The SPKI DER of a freshly generated RSA key of the given size.
    ///
    /// rcgen will not sign with an undersized key — its own signer rejects one outright — so an
    /// undersized case cannot be reached through a self-signed certificate. Verification loads the
    /// key from the SPKI on every call, so driving that path directly exercises the same bound.
    fn rsa_spki_of_size(bits: usize) -> Vec<u8> {
        use rsa::pkcs8::EncodePublicKey;

        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, bits).expect("generate RSA key");
        private_key
            .to_public_key()
            .to_public_key_der()
            .expect("encode SPKI")
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn rsa_keys_outside_the_supported_size_range_are_refused() {
        // An undersized modulus is refused before any signature is considered, so this backend
        // cannot trust a chain that ring and aws-lc reject on key size alone.
        for bits in [512, 1024] {
            let result = RustCrypto::rsa_public_key(&rsa_spki_of_size(bits));
            assert!(
                matches!(result, Err(CryptoError::InvalidKey(_))),
                "expected {bits}-bit key to be refused, got {result:?}"
            );
        }

        // Guard against a vacuous test: the smallest supported size must still load, so the
        // rejections above are the bound talking and not a broken SPKI encoding.
        assert!(RustCrypto::rsa_public_key(&rsa_spki_of_size(2048)).is_ok());
    }

    // RSA-PSS has no round-trip test because rcgen exposes no public PSS
    // signing algorithm to generate one with. Selection of the PSS algorithm
    // from the signature parameters is backend-independent and covered in
    // `crate::crypto::backend`.

    #[test]
    fn ecdsa_p384_sha384_round_trip_verifies() {
        assert_round_trip(&rcgen::PKCS_ECDSA_P384_SHA384);
    }

    #[test]
    fn ed25519_round_trip_verifies() {
        assert_round_trip(&rcgen::PKCS_ED25519);
    }
}