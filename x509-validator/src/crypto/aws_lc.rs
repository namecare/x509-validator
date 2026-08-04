//! aws-lc-rs backed crypto backend.

use aws_lc_rs::signature::{
    UnparsedPublicKey, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1,
    ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA256,
};

use crate::crypto::{CryptoError, CryptoProvider, Digest, KeyProvider, PublicKey};
use x509_validator_core::SignatureAlgorithmId;

/// Marker type implementing every capability this backend provides.
#[derive(Debug)]
struct AwsLc;

impl Digest for AwsLc {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
            .as_ref()
            .to_vec()
    }
}

#[derive(Debug)]
struct AwsLcPublicKey {
    algorithm: &'static dyn VerificationAlgorithm,
    spki_der: Vec<u8>,
}

impl PublicKey for AwsLcPublicKey {
    fn is_valid(&self, signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
        UnparsedPublicKey::new(self.algorithm, &self.spki_der)
            .verify(message, signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

impl KeyProvider for AwsLc {
    fn public_key(
        &self,
        algorithm: SignatureAlgorithmId,
        public_key_der: &[u8],
    ) -> Result<Box<dyn PublicKey>, CryptoError> {
        let algorithm: &'static dyn VerificationAlgorithm = match algorithm {
            SignatureAlgorithmId::EcdsaP256Sha256 => &ECDSA_P256_SHA256_ASN1,
            SignatureAlgorithmId::EcdsaP384Sha384 => &ECDSA_P384_SHA384_ASN1,
            SignatureAlgorithmId::EcdsaP521Sha512 => {
                return Err(CryptoError::InvalidKey(
                    "unsupported algorithm: EcdsaP521Sha512".into(),
                ));
            }
            SignatureAlgorithmId::Ed25519 => &ED25519,
            SignatureAlgorithmId::RsaPkcs1Sha256 => &RSA_PKCS1_2048_8192_SHA256,
            SignatureAlgorithmId::RsaPssSha256 => &RSA_PSS_2048_8192_SHA256,
            SignatureAlgorithmId::Unknown => {
                return Err(CryptoError::InvalidKey("unknown signature algorithm".into()));
            }
        };

        Ok(Box::new(AwsLcPublicKey {
            algorithm,
            spki_der: public_key_der.to_vec(),
        }))
    }
}

pub const DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
    key_provider: &AwsLc,
    sha256: &AwsLc,
};

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING,
    };

    #[test]
    fn ecdsa_p256_round_trip_verifies() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("generate pkcs8");
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
            .expect("load key pair");

        let message = b"tbs certificate bytes";
        let signature = key_pair.sign(&rng, message).expect("sign");
        let spki_der = key_pair.public_key().as_ref().to_vec();

        let public_key = AwsLc
            .public_key(SignatureAlgorithmId::EcdsaP256Sha256, &spki_der)
            .expect("build public key");

        let result = public_key.is_valid(signature.as_ref(), message);
        assert!(result.is_ok(), "expected valid signature to verify, got {result:?}");
    }

    #[test]
    fn ecdsa_p256_tampered_message_fails() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("generate pkcs8");
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
            .expect("load key pair");

        let signature = key_pair.sign(&rng, b"original message").expect("sign");
        let spki_der = key_pair.public_key().as_ref().to_vec();

        let public_key = AwsLc
            .public_key(SignatureAlgorithmId::EcdsaP256Sha256, &spki_der)
            .expect("build public key");

        let result = public_key.is_valid(signature.as_ref(), b"tampered message");
        assert!(matches!(result, Err(CryptoError::VerificationFailed)));
    }

    #[test]
    fn ed25519_round_trip_verifies() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate pkcs8");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load key pair");

        let message = b"tbs certificate bytes";
        let sig = key_pair.sign(message);
        let spki_der = key_pair.public_key().as_ref().to_vec();

        let public_key = AwsLc
            .public_key(SignatureAlgorithmId::Ed25519, &spki_der)
            .expect("build public key");

        let result = public_key.is_valid(sig.as_ref(), message);
        assert!(result.is_ok(), "expected valid signature to verify, got {result:?}");
    }

    #[test]
    fn p521_is_unsupported() {
        let result = AwsLc.public_key(SignatureAlgorithmId::EcdsaP521Sha512, b"irrelevant");
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert_eq!(msg, "unsupported algorithm: EcdsaP521Sha512");
            }
            other => panic!("expected InvalidKey error, got {other:?}"),
        }
    }

    #[test]
    fn unknown_algorithm_is_rejected() {
        let result = AwsLc.public_key(SignatureAlgorithmId::Unknown, b"irrelevant");
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn digest_returns_32_bytes() {
        let hash = AwsLc.hash(b"some data");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn default_provider_dispatches_through_verify_signature() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("generate pkcs8");
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
            .expect("load key pair");

        let message = b"tbs certificate bytes";
        let signature = key_pair.sign(&rng, message).expect("sign");
        let spki_der = key_pair.public_key().as_ref().to_vec();

        let result = DEFAULT_PROVIDER.verify_signature(
            SignatureAlgorithmId::EcdsaP256Sha256,
            &spki_der,
            message,
            signature.as_ref(),
        );
        assert!(result.is_ok(), "expected valid signature to verify, got {result:?}");
    }
}