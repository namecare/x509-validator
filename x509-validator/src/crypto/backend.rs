//! Backend-independent algorithm selection

use crate::asn1_rs::Any;
use crate::oid_registry;
use crate::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use crate::crypto::rsa_pss_digest_bits;

/// A signature algorithm named by a certificate, in backend-independent form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationAlgorithm {
    RsaPkcs1Sha1,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    EcdsaP256Sha256,
    EcdsaP256Sha384,
    EcdsaP256Sha512,
    EcdsaP384Sha256,
    EcdsaP384Sha384,
    EcdsaP384Sha512,
    Ed25519,
}

/// Maps an X.509 `signatureAlgorithm` OID (plus, for ECDSA, the signer's
/// public-key curve OID) to the verification algorithm it names.
pub fn verification_algorithm(
    signature_algorithm: &AlgorithmIdentifier,
    public_key: &SubjectPublicKeyInfo,
) -> Option<VerificationAlgorithm> {
    let oid = &signature_algorithm.algorithm;

    if *oid == oid_registry::OID_PKCS1_SHA1WITHRSA || *oid == oid_registry::OID_SHA1_WITH_RSA {
        Some(VerificationAlgorithm::RsaPkcs1Sha1)
    } else if *oid == oid_registry::OID_PKCS1_SHA256WITHRSA {
        Some(VerificationAlgorithm::RsaPkcs1Sha256)
    } else if *oid == oid_registry::OID_PKCS1_SHA384WITHRSA {
        Some(VerificationAlgorithm::RsaPkcs1Sha384)
    } else if *oid == oid_registry::OID_PKCS1_SHA512WITHRSA {
        Some(VerificationAlgorithm::RsaPkcs1Sha512)
    } else if *oid == oid_registry::OID_PKCS1_RSASSAPSS {
        rsa_pss_algorithm(signature_algorithm.parameters.as_ref())
    } else if *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA256 {
        ecdsa_algorithm(&public_key.algorithm, 256)
    } else if *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA384 {
        ecdsa_algorithm(&public_key.algorithm, 384)
    } else if *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA512 {
        ecdsa_algorithm(&public_key.algorithm, 512)
    } else if *oid == oid_registry::OID_SIG_ED25519 {
        Some(VerificationAlgorithm::Ed25519)
    } else {
        None
    }
}

/// Pairs an ECDSA digest size with the curve named by the signer's public-key
/// parameters. A curve no backend supports, or parameters naming no curve at
/// all, yields `None`.
pub fn ecdsa_algorithm(
    public_key_algorithm: &AlgorithmIdentifier,
    sha_len: usize,
) -> Option<VerificationAlgorithm> {
    let curve_oid = public_key_algorithm.parameters.as_ref()?.as_oid().ok()?;

    if curve_oid == oid_registry::OID_EC_P256 {
        match sha_len {
            256 => Some(VerificationAlgorithm::EcdsaP256Sha256),
            384 => Some(VerificationAlgorithm::EcdsaP256Sha384),
            512 => Some(VerificationAlgorithm::EcdsaP256Sha512),
            _ => None,
        }
    } else if curve_oid == oid_registry::OID_NIST_EC_P384 {
        match sha_len {
            256 => Some(VerificationAlgorithm::EcdsaP384Sha256),
            384 => Some(VerificationAlgorithm::EcdsaP384Sha384),
            512 => Some(VerificationAlgorithm::EcdsaP384Sha512),
            _ => None,
        }
    } else {
        None
    }
}

/// Reads the digest named by `RSASSA-PSS-params`, which is where PSS carries
/// it rather than in the signature algorithm OID itself.
pub fn rsa_pss_algorithm(params: Option<&Any>) -> Option<VerificationAlgorithm> {
    match rsa_pss_digest_bits(params)? {
        256 => Some(VerificationAlgorithm::RsaPssSha256),
        384 => Some(VerificationAlgorithm::RsaPssSha384),
        512 => Some(VerificationAlgorithm::RsaPssSha512),
        _ => None,
    }
}

/// Defines a crypto backend over `$krate`, a crate exposing aws-lc-rs' and
/// ring's shared API shape.
macro_rules! backend {
    (
        krate: $krate:tt,
        backend: $backend:ident,
        ecdsa_p256: { $($p256_sha:literal => $p256_alg:ident),* $(,)? },
        ecdsa_p384: { $($p384_sha:literal => $p384_alg:ident),* $(,)? },
    ) => {
        use $krate::signature::{self, UnparsedPublicKey};
        use crate::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};
        use crate::crypto::backend::{VerificationAlgorithm, verification_algorithm};
        use crate::crypto::{CryptoError, SignatureVerifier};
        
        fn backend_algorithm(
            algorithm: VerificationAlgorithm,
        ) -> Option<&'static dyn $krate::signature::VerificationAlgorithm> {
            // The ECDSA arms are written as guarded catch-alls so that a curve
            // whose group names no digest at all still compiles: matching the
            // variants directly would leave an empty match with no arms.
            match algorithm {
                VerificationAlgorithm::RsaPkcs1Sha1 => {
                    Some(&signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY)
                }
                VerificationAlgorithm::RsaPkcs1Sha256 => Some(&signature::RSA_PKCS1_2048_8192_SHA256),
                VerificationAlgorithm::RsaPkcs1Sha384 => Some(&signature::RSA_PKCS1_2048_8192_SHA384),
                VerificationAlgorithm::RsaPkcs1Sha512 => Some(&signature::RSA_PKCS1_2048_8192_SHA512),
                VerificationAlgorithm::RsaPssSha256 => Some(&signature::RSA_PSS_2048_8192_SHA256),
                VerificationAlgorithm::RsaPssSha384 => Some(&signature::RSA_PSS_2048_8192_SHA384),
                VerificationAlgorithm::RsaPssSha512 => Some(&signature::RSA_PSS_2048_8192_SHA512),
                VerificationAlgorithm::Ed25519 => Some(&signature::ED25519),
                $(_ if algorithm == ecdsa_p256($p256_sha) => Some(&signature::$p256_alg),)*
                $(_ if algorithm == ecdsa_p384($p384_sha) => Some(&signature::$p384_alg),)*
                _ => None,
            }
        }

        /// Names the P-256 variant for a digest size, so the `ecdsa_p256`
        /// group above can be written as digest literals rather than variant
        /// paths.
        const fn ecdsa_p256(sha_len: usize) -> VerificationAlgorithm {
            match sha_len {
                256 => VerificationAlgorithm::EcdsaP256Sha256,
                384 => VerificationAlgorithm::EcdsaP256Sha384,
                512 => VerificationAlgorithm::EcdsaP256Sha512,
                _ => panic!("unsupported ECDSA P-256 digest size"),
            }
        }

        /// The P-384 counterpart of [`ecdsa_p256`].
        const fn ecdsa_p384(sha_len: usize) -> VerificationAlgorithm {
            match sha_len {
                256 => VerificationAlgorithm::EcdsaP384Sha256,
                384 => VerificationAlgorithm::EcdsaP384Sha384,
                512 => VerificationAlgorithm::EcdsaP384Sha512,
                _ => panic!("unsupported ECDSA P-384 digest size"),
            }
        }

        /// Marker type implementing every capability this backend provides.
        #[derive(Debug)]
        pub struct $backend;

        impl SignatureVerifier for $backend {
            fn verify_signature(
                &self,
                algorithm: &AlgorithmIdentifier,
                public_key: &SubjectPublicKeyInfo,
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), CryptoError> {
                let verification_algorithm = verification_algorithm(algorithm, public_key)
                    .and_then(backend_algorithm)
                    .ok_or_else(|| {
                        CryptoError::InvalidKey(format!(
                            "unsupported algorithm: {}",
                            algorithm.algorithm
                        ))
                    })?;

                // `UnparsedPublicKey` borrows the key bytes straight out of
                // the SPKI: with the whole verification happening in one call,
                // nothing outlives them and there is nothing to copy.
                UnparsedPublicKey::new(
                    verification_algorithm,
                    public_key.subject_public_key.as_ref(),
                )
                .verify(message, signature)
                .map_err(|_| CryptoError::VerificationFailed)
            }
        }

        /// The backend itself. Callers name it as the `crypto` argument to
        /// [`crate::Validator::with_policy_and_backend`].
        pub static DEFAULT_PROVIDER: $backend = $backend;
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FromDer;

    /// The digest RSA-PSS is parameterised by lives in the signature
    /// parameters rather than the algorithm OID, so selection reads it from
    /// there.
    #[test]
    fn rsa_pss_parameters_select_the_matching_digest() {
        // RSASSA-PSS-params ::= SEQUENCE { [0] hashAlgorithm AlgorithmIdentifier },
        // where the algorithm OID is 2.16.840.1.101.3.4.2.{1,2,3} for
        // SHA-256/384/512. Assembled rather than hardcoded so the nested
        // lengths stay consistent.
        fn pss_params(last_octet: u8) -> Vec<u8> {
            let oid = [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last_octet,
            ];
            let algorithm_identifier = [&[0x30, oid.len() as u8][..], &oid].concat();
            let tagged = [
                &[0xa0, algorithm_identifier.len() as u8][..],
                &algorithm_identifier,
            ]
            .concat();
            [&[0x30, tagged.len() as u8][..], &tagged].concat()
        }

        for (last_octet, expected) in [
            (0x01, VerificationAlgorithm::RsaPssSha256),
            (0x02, VerificationAlgorithm::RsaPssSha384),
            (0x03, VerificationAlgorithm::RsaPssSha512),
        ] {
            let der = pss_params(last_octet);
            let params = Any::from_der(&der).expect("parse PSS params").1;

            assert_eq!(rsa_pss_algorithm(Some(&params)), Some(expected));
        }

        assert_eq!(rsa_pss_algorithm(None), None);
    }
}
