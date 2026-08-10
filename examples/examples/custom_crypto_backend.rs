//! Verifying signatures with a crypto library this crate knows nothing about.
//!
//!     cargo run -p x509-validator-examples --example custom_crypto_backend
//!
//! Custom signature verifier using OpenSSL


use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier as OpenSslVerifier;
use x509_validator::crypto::{CryptoError, SignatureVerifier};
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::{rsa_pss_digest_bits, Validator};
use x509_validator::oid_registry;
use x509_validator::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use x509_validator_examples::{demo_chain_with, validation_time};
use x509_validator_testkit::rcgen;

#[derive(Debug)]
struct OpenSsl;

impl SignatureVerifier for OpenSsl {
    fn verify_signature(
        &self,
        algorithm: &AlgorithmIdentifier,
        public_key: &SubjectPublicKeyInfo,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let (digest, pss) = signature_scheme(algorithm)?;

        let key = PKey::public_key_from_der(&public_key.raw).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let mut verifier = match digest {
            Some(digest) => OpenSslVerifier::new(digest, &key),
            None => OpenSslVerifier::new_without_digest(&key),
        }
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        if pss {
            verifier
                .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
                .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
            verifier
                .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)
                .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        }

        match verifier.verify_oneshot(signature, message) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(CryptoError::VerificationFailed),
        }
    }
}

/// Maps a signature `AlgorithmIdentifier` onto a digest and whether PSS
/// padding applies.
fn signature_scheme(algorithm: &AlgorithmIdentifier) -> Result<(Option<MessageDigest>, bool), CryptoError> {
    let oid = &algorithm.algorithm;

    let digest = if *oid == oid_registry::OID_PKCS1_SHA256WITHRSA || *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA256 {
        MessageDigest::sha256()
    } else if *oid == oid_registry::OID_PKCS1_SHA384WITHRSA || *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA384 {
        MessageDigest::sha384()
    } else if *oid == oid_registry::OID_PKCS1_SHA512WITHRSA || *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA512 {
        MessageDigest::sha512()
    } else if *oid == oid_registry::OID_SIG_ED25519 {
        return Ok((None, false));
    } else if *oid == oid_registry::OID_PKCS1_RSASSAPSS {
        // The digest for PSS lives in the algorithm parameters, not the OID.
        let bits = rsa_pss_digest_bits(algorithm.parameters.as_ref())
            .ok_or_else(|| CryptoError::InvalidKey("unsupported RSA-PSS digest".to_string()))?;
        let digest = match bits {
            256 => MessageDigest::sha256(),
            384 => MessageDigest::sha384(),
            512 => MessageDigest::sha512(),
            _ => return Err(CryptoError::InvalidKey(format!("unsupported RSA-PSS digest: {bits}"))),
        };
        return Ok((Some(digest), true));
    } else {
        // SHA-1 is deliberately absent: an algorithm this backend will not
        // verify must be refused here, never silently verified as something
        // else.
        return Err(CryptoError::InvalidKey(format!("unsupported algorithm: {oid}")));
    };

    Ok((Some(digest), false))
}

/// The assembled backend
static OPENSSL_PROVIDER: OpenSsl = OpenSsl;

fn main() {
    // One chain per algorithm the backend claims to map, so every arm of
    // `signature_scheme` is actually exercised against real signatures.
    let algorithms: [(&str, &'static rcgen::SignatureAlgorithm); 4] = [
        ("ECDSA P-256 / SHA-256", &rcgen::PKCS_ECDSA_P256_SHA256),
        ("ECDSA P-384 / SHA-384", &rcgen::PKCS_ECDSA_P384_SHA384),
        ("RSA / SHA-256", &rcgen::PKCS_RSA_SHA256),
        ("Ed25519", &rcgen::PKCS_ED25519),
    ];

    for (name, algorithm) in algorithms {
        let chain = demo_chain_with(&["example.com"], algorithm);

        let roots = CertificateStore::from_iter([chain.root.clone()]);
        let intermediates = CertificateStore::from_iter([chain.intermediate.clone()]);

        // Only the backend argument differs from the `validate_chain` example.
        let validator = Validator::with_policy_and_backend(roots, RFC5280Policy::new(validation_time()), &OPENSSL_PROVIDER);

        let verdict = match validator.validate_with_diagnostics(&chain.leaf, &intermediates, &mut |_| {}) {
            Ok(valid) => {
                format!("valid — chain of {}", valid.iter().count())
            }
            Err(reasons) if reasons.is_empty() => {
                "rejected — no chain to a trusted root could be built".to_string()
            }
            Err(reasons) => {
                let listed = reasons.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ");
                format!("rejected — {listed}")
            }
        };

        println!("{name:<24} {verdict}");
    }

    // A backend is also where an algorithm policy belongs. This one refuses
    // SHA-1, so a chain signed with it fails to verify no matter what the
    // certificates themselves claim.
    let sha1 = AlgorithmIdentifier::new(oid_registry::OID_PKCS1_SHA1WITHRSA, None);
    match signature_scheme(&sha1) {
        Ok(_) => println!("\nsha1WithRSA: accepted"),
        Err(e) => println!("\nsha1WithRSA: refused by the backend — {e}"),
    }
}