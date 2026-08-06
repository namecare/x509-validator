//! The body shared by every crypto backend.
//!
//! aws-lc-rs and ring expose the same shape — a `signature` module of
//! `&'static dyn VerificationAlgorithm` constants, an `UnparsedPublicKey` that
//! pairs one with key bytes, and a `digest` module — so mapping X.509
//! algorithm identifiers onto them is the same code twice over, differing only
//! in which crate the names resolve to and in which algorithms the crate
//! actually ships.
//!
//! [`backend`] holds that code once. Each backend module invokes it with its
//! own crate path and marker type, plus the ECDSA arms it supports: aws-lc-rs
//! offers ECDSA-with-SHA512 for both curves, ring does not, and a backend
//! naming no arm for a pairing reports it as unsupported.

/// Defines a crypto backend over `$krate`, a crate exposing aws-lc-rs' and
/// ring's shared API shape.
///
/// `$krate` is matched as a `:tt` rather than `:ident` or `:path`: both of
/// those capture into a single opaque fragment that cannot then be extended
/// with `::` inside a `use`, while a bare token tree stays transparent to the
/// parser. `$backend` names the marker type carrying the backend's trait
/// impls, and the trailing `ecdsa` groups list the `(curve, digest) =>
/// algorithm` pairings the crate provides.
macro_rules! backend {
    (
        krate: $krate:tt,
        backend: $backend:ident,
        ecdsa_p256: { $($p256_sha:literal => $p256_alg:ident),* $(,)? },
        ecdsa_p384: { $($p384_sha:literal => $p384_alg:ident),* $(,)? },
    ) => {
        use $krate::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
        use x509_validator_core::oid_registry;
        use x509_validator_core::asn1_rs::Any;
        use x509_validator_core::crypto::rsa_pss_digest_bits;
        use x509_validator_core::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

        use crate::crypto::{CryptoError, CryptoProvider, Digest, KeyProvider, PublicKey};

        /// Maps an X.509 `signatureAlgorithm` OID (plus, for ECDSA, the
        /// signer's public-key curve OID) to this backend's matching
        /// verification algorithm.
        fn verification_algorithm(
            signature_algorithm: &AlgorithmIdentifier,
            public_key: &SubjectPublicKeyInfo,
        ) -> Option<&'static dyn VerificationAlgorithm> {
            let oid = &signature_algorithm.algorithm;

            if *oid == oid_registry::OID_PKCS1_SHA1WITHRSA
                || *oid == oid_registry::OID_SHA1_WITH_RSA
            {
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

        /// Pairs an ECDSA digest size with the curve named by the signer's
        /// public-key parameters. Digest/curve pairings this backend does not
        /// ship fall through to `None` and surface as
        /// `CryptoError::InvalidKey`, rather than being verified under a
        /// different digest.
        fn ecdsa_algorithm(
            public_key_algorithm: &AlgorithmIdentifier,
            sha_len: usize,
        ) -> Option<&'static dyn VerificationAlgorithm> {
            let curve_oid = public_key_algorithm.parameters.as_ref()?.as_oid().ok()?;

            if curve_oid == oid_registry::OID_EC_P256 {
                match sha_len {
                    $($p256_sha => Some(&signature::$p256_alg),)*
                    _ => None,
                }
            } else if curve_oid == oid_registry::OID_NIST_EC_P384 {
                match sha_len {
                    $($p384_sha => Some(&signature::$p384_alg),)*
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
        struct $backend;

        impl Digest for $backend {
            fn hash(&self, data: &[u8]) -> Vec<u8> {
                $krate::digest::digest(&$krate::digest::SHA256, data)
                    .as_ref()
                    .to_vec()
            }
        }

        /// `UnparsedPublicKey` already pairs an algorithm with key bytes and
        /// verifies against them, so it serves as the `PublicKey` itself
        /// rather than being wrapped in one.
        impl PublicKey for UnparsedPublicKey<Vec<u8>> {
            fn is_valid(&self, signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
                self.verify(message, signature)
                    .map_err(|_| CryptoError::VerificationFailed)
            }
        }

        impl KeyProvider for $backend {
            fn public_key(
                &self,
                algorithm: &AlgorithmIdentifier,
                public_key: &SubjectPublicKeyInfo,
            ) -> Result<Box<dyn PublicKey>, CryptoError> {
                let verification_algorithm = verification_algorithm(algorithm, public_key)
                    .ok_or_else(|| {
                        CryptoError::InvalidKey(format!(
                            "unsupported algorithm: {}",
                            algorithm.algorithm
                        ))
                    })?;

                Ok(Box::new(UnparsedPublicKey::new(
                    verification_algorithm,
                    public_key.subject_public_key.as_ref().to_vec(),
                )))
            }
        }

        pub const DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
            key_provider: &$backend,
            sha256: &$backend,
        };
    };
}
