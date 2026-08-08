//! RustCrypto backed crypto backend.
//!
//! Unlike the aws-lc-rs and ring backends, this one is not built from the
//! [`backend!`] macro: RustCrypto ships no single `UnparsedPublicKey` type
//! pairing an algorithm constant with key bytes. Verification lives in
//! per-algorithm crates (`rsa`, `p256`, `p384`, `ed25519-dalek`), each with
//! its own key and signature types, so the algorithm choice is carried by a
//! plain enum and each arm builds its own verifier.
//!
//! Coverage matches ring: RSA PKCS#1 v1.5 (SHA-1 for legacy use, SHA-256/384/512),
//! RSA-PSS (SHA-256/384/512), ECDSA P-256/P-384 with SHA-256/384, and Ed25519.
//! ECDSA-with-SHA512 is reported as unsupported rather than verified under a
//! different digest.

use signature::Verifier;

use x509_validator_core::asn1_rs::Any;
use x509_validator_core::crypto::rsa_pss_digest_bits;
use x509_validator_core::oid_registry;
use x509_validator_core::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use crate::crypto::{CryptoError, CryptoProvider, Digest, KeyProvider, PublicKey};

/// The verification algorithms this backend provides.
///
/// This stands in for the `&'static dyn VerificationAlgorithm` constants the
/// macro-built backends select: it names the algorithm without yet binding it
/// to key bytes, keeping OID dispatch separate from key parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    RsaPkcs1Sha1,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    EcdsaP256Sha256,
    EcdsaP256Sha384,
    EcdsaP384Sha256,
    EcdsaP384Sha384,
    Ed25519,
}

/// Maps an X.509 `signatureAlgorithm` OID (plus, for ECDSA, the signer's
/// public-key curve OID) to this backend's matching verification algorithm.
fn verification_algorithm(
    signature_algorithm: &AlgorithmIdentifier,
    public_key: &SubjectPublicKeyInfo,
) -> Option<Algorithm> {
    let oid = &signature_algorithm.algorithm;

    if *oid == oid_registry::OID_PKCS1_SHA1WITHRSA || *oid == oid_registry::OID_SHA1_WITH_RSA {
        Some(Algorithm::RsaPkcs1Sha1)
    } else if *oid == oid_registry::OID_PKCS1_SHA256WITHRSA {
        Some(Algorithm::RsaPkcs1Sha256)
    } else if *oid == oid_registry::OID_PKCS1_SHA384WITHRSA {
        Some(Algorithm::RsaPkcs1Sha384)
    } else if *oid == oid_registry::OID_PKCS1_SHA512WITHRSA {
        Some(Algorithm::RsaPkcs1Sha512)
    } else if *oid == oid_registry::OID_PKCS1_RSASSAPSS {
        rsa_pss_algorithm(signature_algorithm.parameters.as_ref())
    } else if *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA256 {
        ecdsa_algorithm(&public_key.algorithm, 256)
    } else if *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA384 {
        ecdsa_algorithm(&public_key.algorithm, 384)
    } else if *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA512 {
        ecdsa_algorithm(&public_key.algorithm, 512)
    } else if *oid == oid_registry::OID_SIG_ED25519 {
        Some(Algorithm::Ed25519)
    } else {
        None
    }
}

/// Pairs an ECDSA digest size with the curve named by the signer's public-key
/// parameters. Digest/curve pairings this backend does not ship — SHA-512 on
/// either curve — fall through to `None` and surface as
/// `CryptoError::InvalidKey`, rather than being verified under a different
/// digest.
fn ecdsa_algorithm(public_key_algorithm: &AlgorithmIdentifier, sha_len: usize) -> Option<Algorithm> {
    let curve_oid = public_key_algorithm.parameters.as_ref()?.as_oid().ok()?;

    if curve_oid == oid_registry::OID_EC_P256 {
        match sha_len {
            256 => Some(Algorithm::EcdsaP256Sha256),
            384 => Some(Algorithm::EcdsaP256Sha384),
            _ => None,
        }
    } else if curve_oid == oid_registry::OID_NIST_EC_P384 {
        match sha_len {
            256 => Some(Algorithm::EcdsaP384Sha256),
            384 => Some(Algorithm::EcdsaP384Sha384),
            _ => None,
        }
    } else {
        None
    }
}

fn rsa_pss_algorithm(params: Option<&Any>) -> Option<Algorithm> {
    match rsa_pss_digest_bits(params)? {
        256 => Some(Algorithm::RsaPssSha256),
        384 => Some(Algorithm::RsaPssSha384),
        512 => Some(Algorithm::RsaPssSha512),
        _ => None,
    }
}

/// An algorithm paired with the signer's key bytes, mirroring the role
/// `UnparsedPublicKey` plays in the macro-built backends.
///
/// The key is held in its DER form and parsed on each verification rather than
/// eagerly: which form to parse (full SPKI for RSA and Ed25519, the SEC1 point
/// for ECDSA) is decided by the algorithm arm, and a key that fails to parse is
/// an `InvalidKey` at verification time.
#[derive(Debug)]
struct RustCryptoPublicKey {
    algorithm: Algorithm,
    /// The full `SubjectPublicKeyInfo` DER, as RSA and Ed25519 keys are
    /// parsed from it.
    spki_der: Vec<u8>,
    /// The `subjectPublicKey` BIT STRING contents, which for ECDSA is the
    /// SEC1-encoded curve point.
    key_bytes: Vec<u8>,
}

impl PublicKey for RustCryptoPublicKey {
    fn is_valid(&self, signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
        match self.algorithm {
            Algorithm::RsaPkcs1Sha1 => self.verify_rsa_pkcs1::<sha1::Sha1>(signature, message),
            Algorithm::RsaPkcs1Sha256 => self.verify_rsa_pkcs1::<sha2::Sha256>(signature, message),
            Algorithm::RsaPkcs1Sha384 => self.verify_rsa_pkcs1::<sha2::Sha384>(signature, message),
            Algorithm::RsaPkcs1Sha512 => self.verify_rsa_pkcs1::<sha2::Sha512>(signature, message),
            Algorithm::RsaPssSha256 => self.verify_rsa_pss::<sha2::Sha256>(signature, message),
            Algorithm::RsaPssSha384 => self.verify_rsa_pss::<sha2::Sha384>(signature, message),
            Algorithm::RsaPssSha512 => self.verify_rsa_pss::<sha2::Sha512>(signature, message),
            Algorithm::EcdsaP256Sha256 => self.verify_ecdsa_p256_sha256(signature, message),
            Algorithm::EcdsaP256Sha384 => self.verify_ecdsa_p256_sha384(signature, message),
            Algorithm::EcdsaP384Sha256 => self.verify_ecdsa_p384_sha256(signature, message),
            Algorithm::EcdsaP384Sha384 => self.verify_ecdsa_p384_sha384(signature, message),
            Algorithm::Ed25519 => self.verify_ed25519(signature, message),
        }
    }
}

/// The RSA modulus sizes, in bytes, this backend will verify against.
///
/// The other backends inherit these bounds from the named algorithms they dispatch to
/// (`RSA_PKCS1_2048_8192_*`), while the RSA crate imposes no limit of its own. Applying the same
/// bounds here keeps a chain's fate from depending on which backend happens to be compiled in: a
/// factorable modulus must not verify merely because this backend was selected, and an absurdly
/// large one must not turn verification into a denial of service.
const MIN_RSA_MODULUS_BYTES: usize = 2048 / 8;
const MAX_RSA_MODULUS_BYTES: usize = 8192 / 8;

impl RustCryptoPublicKey {
    fn rsa_public_key(&self) -> Result<rsa::RsaPublicKey, CryptoError> {
        use rsa::pkcs8::DecodePublicKey;
        use rsa::traits::PublicKeyParts;

        let key = rsa::RsaPublicKey::from_public_key_der(&self.spki_der)
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
    fn verify_rsa_pkcs1<D>(&self, signature: &[u8], message: &[u8]) -> Result<(), CryptoError>
    where
        D: sha2::Digest + rsa::pkcs8::AssociatedOid,
    {
        let verifying_key = rsa::pkcs1v15::VerifyingKey::<D>::new(self.rsa_public_key()?);
        let signature = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    /// PSS reuses one digest instance across the MGF1 rounds, hence
    /// `FixedOutputReset` rather than the PKCS#1 path's OID bound.
    fn verify_rsa_pss<D>(&self, signature: &[u8], message: &[u8]) -> Result<(), CryptoError>
    where
        D: sha2::Digest + sha2::digest::FixedOutputReset,
    {
        let verifying_key = rsa::pss::VerifyingKey::<D>::new(self.rsa_public_key()?);
        let signature =
            rsa::pss::Signature::try_from(signature).map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_ecdsa_p256_sha256(&self, signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.key_bytes)
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
    fn verify_ecdsa_p256_sha384(&self, signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
        use sha2::Digest as _;
        use signature::hazmat::PrehashVerifier;

        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let signature = p256::ecdsa::Signature::from_der(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify_prehash(&sha2::Sha384::digest(message), &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    /// P-384's `Verifier` impl is likewise fixed to SHA-384, so SHA-256 goes
    /// through the prehash path.
    fn verify_ecdsa_p384_sha256(&self, signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
        use sha2::Digest as _;
        use signature::hazmat::PrehashVerifier;

        let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&self.key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let signature = p384::ecdsa::Signature::from_der(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify_prehash(&sha2::Sha256::digest(message), &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_ecdsa_p384_sha384(&self, signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
        let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&self.key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let signature = p384::ecdsa::DerSignature::try_from(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verify_ed25519(&self, signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
        let verifying_key = ed25519_dalek::VerifyingKey::try_from(self.key_bytes.as_slice())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| CryptoError::VerificationFailed)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

/// Marker type implementing every capability this backend provides.
#[derive(Debug)]
struct RustCrypto;

impl Digest for RustCrypto {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;

        sha2::Sha256::digest(data).to_vec()
    }
}

impl KeyProvider for RustCrypto {
    fn public_key(
        &self,
        algorithm: &AlgorithmIdentifier,
        public_key: &SubjectPublicKeyInfo,
    ) -> Result<Box<dyn PublicKey>, CryptoError> {
        let algorithm = verification_algorithm(algorithm, public_key).ok_or_else(|| {
            CryptoError::InvalidKey(format!("unsupported algorithm: {}", algorithm.algorithm))
        })?;

        Ok(Box::new(RustCryptoPublicKey {
            algorithm,
            spki_der: public_key.raw.to_vec(),
            key_bytes: public_key.subject_public_key.as_ref().to_vec(),
        }))
    }
}

pub const DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
    key_provider: &RustCrypto,
    sha256: &RustCrypto,
};

#[cfg(test)]
mod tests {
    use super::*;
    use x509_validator_core::Certificate;
    use x509_validator_core::FromDer;
    use x509_validator_testkit::rcgen::{self, CertificateParams, KeyPair};

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

        let public_key = RustCrypto
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

        let public_key = RustCrypto
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

        let result = RustCrypto.public_key(&algorithm, cert.public_key());
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
        let cert = parse(der);

        let result = RustCrypto.public_key(&algorithm, cert.public_key());
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn digest_returns_32_bytes() {
        let hash = RustCrypto.hash(b"some data");
        assert_eq!(hash.len(), 32);
    }

    /// Self-signs under `algorithm` and checks the resulting signature
    /// verifies, exercising one arm of `is_valid` end to end against a
    /// signature this backend did not produce.
    fn assert_round_trip(algorithm: &'static rcgen::SignatureAlgorithm) {
        let key_pair = KeyPair::generate_for(algorithm).expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = parse(der);

        let public_key = RustCrypto
            .public_key(&cert.signature_algorithm, cert.public_key())
            .expect("build public key");

        let result = public_key.is_valid(cert.signature_value.as_ref(), cert.tbs_certificate.as_ref());
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
        let cert = parse(der);

        let public_key = RustCrypto
            .public_key(&cert.signature_algorithm, cert.public_key())
            .expect("build public key");

        let result = public_key.is_valid(cert.signature_value.as_ref(), cert.tbs_certificate.as_ref());
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

    /// A `RustCryptoPublicKey` wrapping a freshly generated RSA key of the given size.
    ///
    /// rcgen will not sign with an undersized key — its own signer rejects one outright — so an
    /// undersized case cannot be reached through a self-signed certificate. Verification loads the
    /// key from the SPKI on every call, so driving that path directly exercises the same bound.
    fn rsa_key_of_size(bits: usize) -> RustCryptoPublicKey {
        use rsa::pkcs8::EncodePublicKey;

        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, bits).expect("generate RSA key");
        let spki_der = private_key
            .to_public_key()
            .to_public_key_der()
            .expect("encode SPKI")
            .as_bytes()
            .to_vec();

        RustCryptoPublicKey {
            algorithm: Algorithm::RsaPkcs1Sha256,
            spki_der,
            key_bytes: Vec::new(),
        }
    }

    #[test]
    fn rsa_keys_outside_the_supported_size_range_are_refused() {
        // An undersized modulus is refused before any signature is considered, so this backend
        // cannot trust a chain that ring and aws-lc reject on key size alone.
        for bits in [512, 1024] {
            let result = rsa_key_of_size(bits).rsa_public_key();
            assert!(
                matches!(result, Err(CryptoError::InvalidKey(_))),
                "expected {bits}-bit key to be refused, got {result:?}"
            );
        }

        // Guard against a vacuous test: the smallest supported size must still load, so the
        // rejections above are the bound talking and not a broken SPKI encoding.
        assert!(rsa_key_of_size(2048).rsa_public_key().is_ok());
    }

    /// RSA-PSS has no round-trip test because rcgen exposes no public
    /// PSS signing algorithm to generate one with. Dispatch to the PSS arms
    /// is covered here instead, via the digest named in the signature
    /// algorithm parameters.
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
            (0x01, Algorithm::RsaPssSha256),
            (0x02, Algorithm::RsaPssSha384),
            (0x03, Algorithm::RsaPssSha512),
        ] {
            let der = pss_params(last_octet);
            let params = Any::from_der(&der).expect("parse PSS params").1;

            assert_eq!(rsa_pss_algorithm(Some(&params)), Some(expected));
        }

        assert_eq!(rsa_pss_algorithm(None), None);
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