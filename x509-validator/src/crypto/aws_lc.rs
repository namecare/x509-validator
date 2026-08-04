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