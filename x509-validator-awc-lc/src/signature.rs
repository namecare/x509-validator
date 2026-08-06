use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use x509_validator_core::oid_registry;
use x509_validator_core::asn1_rs::Any;
use x509_validator_core::crypto::rsa_pss_digest_bits;
use x509_validator_core::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

/// Maps an X.509 `signatureAlgorithm` OID (plus, for ECDSA, the signer's
/// public-key curve OID) to the matching aws-lc-rs verification algorithm.
/// Returns `None` for algorithms this crate does not support.
pub fn verification_algorithm(
    signature_algorithm: &AlgorithmIdentifier,
    public_key: &SubjectPublicKeyInfo,
) -> Option<&'static dyn VerificationAlgorithm> {
    let oid = &signature_algorithm.algorithm;

    if *oid == oid_registry::OID_PKCS1_SHA1WITHRSA || *oid == oid_registry::OID_SHA1_WITH_RSA {
        Some(&signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY)
    } else if *oid == oid_registry::OID_PKCS1_SHA256WITHRSA {
        Some(&signature::RSA_PKCS1_2048_8192_SHA256)
    } else if *oid == oid_registry::OID_PKCS1_SHA384WITHRSA {
        Some(&signature::RSA_PKCS1_2048_8192_SHA384)
    } else if *oid == oid_registry::OID_PKCS1_SHA512WITHRSA {
        Some(&signature::RSA_PKCS1_2048_8192_SHA512)
    } else if *oid == oid_registry::OID_PKCS1_RSASSAPSS {
        rsa_pss_algorithm(signature_algorithm.parameters.as_ref())
    } else if *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA256 {
        ecdsa_algorithm(&public_key.algorithm, 256)
    } else if *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA384 {
        ecdsa_algorithm(&public_key.algorithm, 384)
    } else if *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA512 {
        ecdsa_algorithm(&public_key.algorithm, 512)
    } else if *oid == oid_registry::OID_SIG_ED25519 {
        Some(&signature::ED25519)
    } else {
        None
    }
}

fn ecdsa_algorithm(
    public_key_algorithm: &AlgorithmIdentifier,
    sha_len: usize,
) -> Option<&'static dyn VerificationAlgorithm> {
    let curve_oid = public_key_algorithm.parameters.as_ref()?.as_oid().ok()?;

    if curve_oid == oid_registry::OID_EC_P256 {
        match sha_len {
            256 => Some(&signature::ECDSA_P256_SHA256_ASN1),
            384 => Some(&signature::ECDSA_P256_SHA384_ASN1),
            512 => Some(&signature::ECDSA_P256_SHA512_ASN1),
            _ => None,
        }
    } else if curve_oid == oid_registry::OID_NIST_EC_P384 {
        match sha_len {
            256 => Some(&signature::ECDSA_P384_SHA256_ASN1),
            384 => Some(&signature::ECDSA_P384_SHA384_ASN1),
            512 => Some(&signature::ECDSA_P384_SHA512_ASN1),
            _ => None,
        }
    } else {
        None
    }
}

fn rsa_pss_algorithm(params: Option<&Any>) -> Option<&'static dyn VerificationAlgorithm> {
    match rsa_pss_digest_bits(params)? {
        256 => Some(&signature::RSA_PSS_2048_8192_SHA256),
        384 => Some(&signature::RSA_PSS_2048_8192_SHA384),
        512 => Some(&signature::RSA_PSS_2048_8192_SHA512),
        _ => None,
    }
}

/// Verifies `signature_value` over `signed_data` using `signer_public_key`,
/// selecting the aws-lc-rs algorithm from `signature_algorithm`.
pub fn verify(
    signer_public_key: &SubjectPublicKeyInfo,
    signature_algorithm: &AlgorithmIdentifier,
    signature_value: &[u8],
    signed_data: &[u8],
) -> Result<(), SignatureVerificationError> {
    let algorithm = verification_algorithm(signature_algorithm, signer_public_key)
        .ok_or(SignatureVerificationError::UnsupportedAlgorithm)?;

    let key = UnparsedPublicKey::new(algorithm, signer_public_key.subject_public_key.as_ref());
    key.verify(signed_data, signature_value)
        .map_err(|_| SignatureVerificationError::InvalidSignature)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureVerificationError {
    UnsupportedAlgorithm,
    InvalidSignature,
}