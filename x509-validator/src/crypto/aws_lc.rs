//! aws-lc-rs backed crypto backend.

use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use x509_validator_core::oid_registry;
use x509_validator_core::asn1_rs::Any;
use x509_validator_core::crypto::rsa_pss_digest_bits;
use x509_validator_core::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use crate::crypto::{CryptoError, CryptoProvider, Digest, KeyProvider, PublicKey};

/// Maps an X.509 `signatureAlgorithm` OID (plus, for ECDSA, the signer's
/// public-key curve OID) to the matching aws-lc-rs verification algorithm.
fn verification_algorithm(
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

fn ecdsa_algorithm(public_key_algorithm: &AlgorithmIdentifier, sha_len: usize) -> Option<&'static dyn VerificationAlgorithm> {
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

/// Marker type implementing every capability this backend provides.
#[derive(Debug)]
struct AwsLc;

impl Digest for AwsLc {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data).as_ref().to_vec()
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
    fn public_key(&self, algorithm: &AlgorithmIdentifier, public_key: &SubjectPublicKeyInfo) -> Result<Box<dyn PublicKey>, CryptoError> {
        let algorithm = verification_algorithm(algorithm, public_key)
            .ok_or_else(|| CryptoError::InvalidKey(format!("unsupported algorithm: {}", algorithm.algorithm)))?;

        Ok(Box::new(AwsLcPublicKey {
            algorithm,
            spki_der: public_key.subject_public_key.as_ref().to_vec(),
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
    use x509_validator_testkit::rcgen::{CertificateParams, KeyPair};
    use x509_validator_core::FromDer;
    use x509_validator_core::Certificate;

    /// Builds a real self-signed certificate for `key_pair` and parses it
    /// back, giving tests a genuine `AlgorithmIdentifier`/`SubjectPublicKeyInfo`
    /// pair straight from a real DER encoding rather than hand-assembled
    /// ASN.1 structs.
    fn self_signed(key_pair: &KeyPair) -> Vec<u8> {
        let params = CertificateParams::default();
        params.self_signed(key_pair).expect("self-sign").der().to_vec()
    }

    fn parse(der: &'static [u8]) -> Certificate<'static> {
        Certificate::from_der(der).unwrap().1
    }

    #[test]
    fn ecdsa_p256_round_trip_verifies() {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = parse(der);

        let public_key = AwsLc
            .public_key(&cert.signature_algorithm, cert.public_key())
            .expect("build public key");

        let result = public_key.is_valid(cert.signature_value.as_ref(), cert.tbs_certificate.as_ref());
        assert!(result.is_ok(), "expected valid signature to verify, got {result:?}");
    }

    #[test]
    fn ecdsa_p256_tampered_message_fails() {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = parse(der);

        let public_key = AwsLc
            .public_key(&cert.signature_algorithm, cert.public_key())
            .expect("build public key");

        let result = public_key.is_valid(cert.signature_value.as_ref(), b"tampered message");
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
        let cert = parse(der);

        let result = AwsLc.public_key(&algorithm, cert.public_key());
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn digest_returns_32_bytes() {
        let hash = AwsLc.hash(b"some data");
        assert_eq!(hash.len(), 32);
    }
}