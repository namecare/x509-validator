//! Verifying signatures with a crypto library the crate knows nothing about.
//!
//! The bundled backends are a convenience, not a requirement. A caller who
//! already links a crypto library — here OpenSSL — can implement
//! `SignatureVerifier` over it and pass it to the validator instead.
//!
//! The backend is also where an algorithm policy belongs: an algorithm it
//! declines to map, SHA-1 below, cannot be used to sign a chain no matter
//! what the certificates say.
//!
//!     cargo run -p x509-validator-examples --example custom_crypto_backend

use std::time::{SystemTime, UNIX_EPOCH};

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SignatureAlgorithm,
};
use x509_validator::crypto::{CryptoError, SignatureVerifier};
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use x509_validator::{oid_registry, rsa_pss_digest_bits, Certificate, CertificateExt, Validator};

#[derive(Debug)]
struct OpenSsl;

impl SignatureVerifier for OpenSsl {
    fn verify_signature(
        &self,
        algorithm: &AlgorithmIdentifier<'_>,
        public_key: &SubjectPublicKeyInfo<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let (digest, pss) = signature_scheme(algorithm)?;

        let key = PKey::public_key_from_der(public_key.raw)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let mut verifier = match digest {
            Some(digest) => Verifier::new(digest, &key),
            None => Verifier::new_without_digest(&key),
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

/// The digest an `AlgorithmIdentifier` calls for, and whether PSS padding
/// applies. An unmapped algorithm is refused rather than guessed at.
fn signature_scheme(
    algorithm: &AlgorithmIdentifier<'_>,
) -> Result<(Option<MessageDigest>, bool), CryptoError> {
    let oid = &algorithm.algorithm;

    let digest = if *oid == oid_registry::OID_PKCS1_SHA256WITHRSA
        || *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA256
    {
        MessageDigest::sha256()
    } else if *oid == oid_registry::OID_PKCS1_SHA384WITHRSA
        || *oid == oid_registry::OID_SIG_ECDSA_WITH_SHA384
    {
        MessageDigest::sha384()
    } else if *oid == oid_registry::OID_SIG_ED25519 {
        return Ok((None, false));
    } else if *oid == oid_registry::OID_PKCS1_RSASSAPSS {
        // The digest for PSS lives in the parameters, not the OID.
        let bits = rsa_pss_digest_bits(algorithm.parameters.as_ref())
            .ok_or_else(|| CryptoError::InvalidKey("unsupported RSA-PSS digest".to_string()))?;
        let digest = match bits {
            256 => MessageDigest::sha256(),
            384 => MessageDigest::sha384(),
            512 => MessageDigest::sha512(),
            _ => return Err(CryptoError::InvalidKey(format!("RSA-PSS with SHA-{bits}"))),
        };
        return Ok((Some(digest), true));
    } else {
        return Err(CryptoError::InvalidKey(format!("unsupported: {oid}")));
    };

    Ok((Some(digest), false))
}

static OPENSSL: OpenSsl = OpenSsl;

fn parse(der: &[u8]) -> Certificate<'_> {
    Certificate::parse(der).expect("certificate parses")
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_secs() as i64
}

/// A root and a leaf it issued, both signed with `algorithm`.
fn chain_signed_with(algorithm: &'static SignatureAlgorithm) -> (Vec<u8>, Vec<u8>) {
    let mut ca_params = CertificateParams::new(vec![]).expect("CA parameters");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Example Root CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = date_time_ymd(2020, 1, 1);
    ca_params.not_after = date_time_ymd(2100, 1, 1);

    let ca_key = KeyPair::generate_for(algorithm).expect("CA key");
    let ca_der = ca_params
        .self_signed(&ca_key)
        .expect("self-signed CA")
        .der()
        .to_vec();

    let mut leaf_params =
        CertificateParams::new(vec!["service.example".to_string()]).expect("leaf parameters");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "service.example");
    leaf_params.not_before = date_time_ymd(2020, 1, 1);
    leaf_params.not_after = date_time_ymd(2100, 1, 1);

    let leaf_key = KeyPair::generate_for(algorithm).expect("leaf key");
    let leaf_der = leaf_params
        .signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))
        .expect("issued leaf")
        .der()
        .to_vec();

    (ca_der, leaf_der)
}

fn main() {
    let algorithms: [(&str, &'static SignatureAlgorithm); 3] = [
        ("ECDSA P-256 / SHA-256", &rcgen::PKCS_ECDSA_P256_SHA256),
        ("ECDSA P-384 / SHA-384", &rcgen::PKCS_ECDSA_P384_SHA384),
        ("Ed25519", &rcgen::PKCS_ED25519),
    ];

    for (name, algorithm) in algorithms {
        let (ca_der, leaf_der) = chain_signed_with(algorithm);
        let leaf = parse(&leaf_der);
        let roots = CertificateStore::from_iter([parse(&ca_der)]);

        // Only the backend argument differs from the other examples.
        let validator =
            Validator::with_policy_and_backend(roots, RFC5280Policy::new(now()), &OPENSSL);

        let verdict = match validator.validate(&leaf, &CertificateStore::new()) {
            Ok(_) => "verified by OpenSSL".to_string(),
            Err(failures) if failures.is_empty() => "no chain to a trusted root".to_string(),
            Err(failures) => format!("rejected — {}", failures[0]),
        };

        println!("{name:<24} {verdict}");
    }

    let sha1 = AlgorithmIdentifier::new(oid_registry::OID_PKCS1_SHA1WITHRSA, None);
    match signature_scheme(&sha1) {
        Ok(_) => println!("\nsha1WithRSA           accepted"),
        Err(e) => println!("\nsha1WithRSA           refused by the backend — {e}"),
    }
}
