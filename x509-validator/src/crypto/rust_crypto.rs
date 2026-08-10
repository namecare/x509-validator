//! RustCrypto backed crypto backend.

use signature::Verifier;

use crate::crypto::backend::{VerificationAlgorithm, verification_algorithm};
use crate::crypto::{CryptoError, SignatureVerifier};
use crate::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

/// The RSA modulus sizes, in bytes, this backend will verify against.
const MIN_RSA_MODULUS_BYTES: usize = 2048 / 8;
const MAX_RSA_MODULUS_BYTES: usize = 8192 / 8;

#[derive(Debug)]
pub struct RustCrypto;

impl SignatureVerifier for RustCrypto {
    fn verify_signature(
        &self,
        algorithm: &AlgorithmIdentifier<'_>,
        public_key: &SubjectPublicKeyInfo<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let unsupported =
            || CryptoError::InvalidKey(format!("unsupported algorithm: {}", algorithm.algorithm));
        let verification_algorithm =
            verification_algorithm(algorithm, public_key).ok_or_else(unsupported)?;

        let spki_der = &public_key.raw;
        let key_bytes = public_key.subject_public_key.as_ref();

        match verification_algorithm {
            VerificationAlgorithm::RsaPkcs1Sha1 => {
                Self::verify_rsa_pkcs1::<sha1::Sha1>(spki_der, signature, message)
            }
            VerificationAlgorithm::RsaPkcs1Sha256 => {
                Self::verify_rsa_pkcs1::<sha2::Sha256>(spki_der, signature, message)
            }
            VerificationAlgorithm::RsaPkcs1Sha384 => {
                Self::verify_rsa_pkcs1::<sha2::Sha384>(spki_der, signature, message)
            }
            VerificationAlgorithm::RsaPkcs1Sha512 => {
                Self::verify_rsa_pkcs1::<sha2::Sha512>(spki_der, signature, message)
            }
            VerificationAlgorithm::RsaPssSha256 => {
                Self::verify_rsa_pss::<sha2::Sha256>(spki_der, signature, message)
            }
            VerificationAlgorithm::RsaPssSha384 => {
                Self::verify_rsa_pss::<sha2::Sha384>(spki_der, signature, message)
            }
            VerificationAlgorithm::RsaPssSha512 => {
                Self::verify_rsa_pss::<sha2::Sha512>(spki_der, signature, message)
            }
            VerificationAlgorithm::EcdsaP256Sha256 => {
                Self::verify_ecdsa_p256_sha256(key_bytes, signature, message)
            }
            VerificationAlgorithm::EcdsaP256Sha384 => {
                Self::verify_ecdsa_p256_sha384(key_bytes, signature, message)
            }
            VerificationAlgorithm::EcdsaP384Sha256 => {
                Self::verify_ecdsa_p384_sha256(key_bytes, signature, message)
            }
            VerificationAlgorithm::EcdsaP384Sha384 => {
                Self::verify_ecdsa_p384_sha384(key_bytes, signature, message)
            }
            VerificationAlgorithm::Ed25519 => Self::verify_ed25519(key_bytes, signature, message),
            VerificationAlgorithm::EcdsaP256Sha512 | VerificationAlgorithm::EcdsaP384Sha512 => {
                Err(unsupported())
            }
        }
    }
}

impl RustCrypto {
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

    fn verify_rsa_pkcs1<D>(
        spki_der: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), CryptoError>
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

    fn verify_rsa_pss<D>(
        spki_der: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), CryptoError>
    where
        D: sha2::Digest + sha2::digest::FixedOutputReset,
    {
        let verifying_key = rsa::pss::VerifyingKey::<D>::new(Self::rsa_public_key(spki_der)?);
        let signature = rsa::pss::Signature::try_from(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_ecdsa_p256_sha256(
        key_bytes: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), CryptoError> {
        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let signature = p256::ecdsa::Signature::from_der(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_ecdsa_p256_sha384(
        key_bytes: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), CryptoError> {
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

    fn verify_ecdsa_p384_sha256(
        key_bytes: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), CryptoError> {
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

    fn verify_ecdsa_p384_sha384(
        key_bytes: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), CryptoError> {
        let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let signature = p384::ecdsa::Signature::from_der(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_ed25519(
        key_bytes: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), CryptoError> {
        let verifying_key = ed25519_dalek::VerifyingKey::try_from(key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

pub static DEFAULT_PROVIDER: RustCrypto = RustCrypto;

#[cfg(test)]
mod tests {
    use x509_validator_testkit::rcgen::{self, KeyPair};
    use x509_validator_testkit::self_signed;

    use super::*;
    use crate::{Certificate, CertificateExt, oid_registry};

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
        assert!(
            result.is_ok(),
            "expected valid signature to verify, got {result:?}"
        );
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

        let result =
            RustCrypto.verify_signature(&algorithm, cert.public_key(), b"message", b"signature");
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn ecdsa_sha512_is_unsupported() {
        let algorithm = AlgorithmIdentifier {
            algorithm: oid_registry::OID_SIG_ECDSA_WITH_SHA512,
            parameters: None,
        };
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

        let result =
            RustCrypto.verify_signature(&algorithm, cert.public_key(), b"message", b"signature");
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

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
        assert!(
            result.is_ok(),
            "expected valid signature to verify, got {result:?}"
        );
    }

    fn rsa_key_pair(algorithm: &'static rcgen::SignatureAlgorithm) -> KeyPair {
        use rsa::pkcs8::EncodePrivateKey;

        static PKCS8_DER: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

        let der = PKCS8_DER.get_or_init(|| {
            let mut rng = rand::rng();
            let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
            private_key
                .to_pkcs8_der()
                .expect("encode PKCS#8")
                .as_bytes()
                .to_vec()
        });

        KeyPair::from_pkcs8_der_and_sign_algo(&der.as_slice().into(), algorithm)
            .expect("build RSA key pair")
    }

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
        assert!(
            result.is_ok(),
            "expected valid signature to verify, got {result:?}"
        );
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

    fn rsa_spki_of_size(bits: usize) -> Vec<u8> {
        use rsa::pkcs8::EncodePublicKey;

        let mut rng = rand::rng();
        // `new` refuses to generate below 1024 bits, but the undersized keys are exactly what the
        // size bound needs to be handed, so bypass the generator's own guard here.
        let private_key =
            rsa::RsaPrivateKey::new_unchecked(&mut rng, bits).expect("generate RSA key");
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

    #[test]
    fn ecdsa_p384_sha384_round_trip_verifies() {
        assert_round_trip(&rcgen::PKCS_ECDSA_P384_SHA384);
    }

    #[test]
    fn ed25519_round_trip_verifies() {
        assert_round_trip(&rcgen::PKCS_ED25519);
    }
}
