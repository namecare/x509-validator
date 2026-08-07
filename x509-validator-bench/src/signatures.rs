//! Pre-signed material for the atomic crypto benchmarks.
//!
//! Each entry pairs a signature with the algorithm and public key needed to
//! check it, so the benchmark measures verification alone — key generation
//! and signing happen once, here.

use std::sync::OnceLock;
use x509_validator_core::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use x509_validator_core::{Certificate, FromDer};
use x509_validator_testkit::parse::leak;
use x509_validator_testkit::rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384, PKCS_ED25519};

/// One verifiable signature, with everything needed to check it.
pub struct SignedSample {
    pub label: &'static str,
    pub algorithm: AlgorithmIdentifier<'static>,
    pub spki: SubjectPublicKeyInfo<'static>,
    pub message: &'static [u8],
    pub signature: &'static [u8],
}

static CORPUS: OnceLock<Vec<SignedSample>> = OnceLock::new();

pub fn corpus() -> &'static [SignedSample] {
    CORPUS.get_or_init(build)
}

/// Builds a sample from a self-signed certificate: the certificate's own
/// signature over its own TBS bytes is a real signature by the key its SPKI
/// carries, which is exactly the shape the chain builder verifies.
///
/// `AlgorithmIdentifier` and `SubjectPublicKeyInfo` are `Clone`, but cloning
/// them out of a `Certificate` parsed from a local (non-leaked) binding still
/// leaves `message`/`signature` — plain byte-slice fields borrowed straight
/// from the certificate, not owned copies — tied to that binding's lifetime.
/// The certificate itself is leaked instead: it already only borrows from
/// the leaked DER, so leaking it gives every field, cloned or borrowed, a
/// `'static` lifetime.
fn sample_from_self_signed(label: &'static str, key_pair: KeyPair) -> SignedSample {
    let der = CertificateParams::default()
        .self_signed(&key_pair)
        .expect("self-sign")
        .der()
        .to_vec();
    let der: &'static [u8] = leak(der);
    let certificate: &'static Certificate<'static> = Box::leak(Box::new(Certificate::from_der(der).expect("parse").1));

    SignedSample {
        label,
        algorithm: certificate.signature_algorithm.clone(),
        spki: certificate.tbs_certificate.subject_pki.clone(),
        message: certificate.tbs_certificate.as_ref(),
        signature: certificate.signature_value.as_ref(),
    }
}

fn build() -> Vec<SignedSample> {
    let mut corpus = vec![
        sample_from_self_signed("ecdsa_p256_sha256", KeyPair::generate().expect("p256 key")),
        sample_from_self_signed(
            "ecdsa_p384_sha384",
            KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("p384 key"),
        ),
        sample_from_self_signed("ed25519", KeyPair::generate_for(&PKCS_ED25519).expect("ed25519 key")),
    ];

    // rcgen cannot generate RSA keys, so these are generated with `rsa` and
    // handed to rcgen as a PKCS#8 private key.
    for (label, bits) in [("rsa_2048_sha256", 2048usize), ("rsa_4096_sha256", 4096usize)] {
        corpus.push(sample_from_self_signed(label, rsa_key_pair(bits)));
    }

    corpus
}

/// An RSA key pair of `bits`, routed through PKCS#8 DER so rcgen can sign
/// with it. `KeyPair::try_from(&[u8])` auto-detects the key kind from the
/// PKCS#8 DER and, for RSA, selects `PKCS_RSA_SHA256` — exactly the
/// algorithm these samples are labeled with.
fn rsa_key_pair(bits: usize) -> KeyPair {
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::RsaPrivateKey;

    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("generate RSA key");
    let pkcs8 = private_key.to_pkcs8_der().expect("encode PKCS#8");
    KeyPair::try_from(pkcs8.as_bytes()).expect("rcgen accepts RSA PKCS#8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BACKENDS;

    #[test]
    fn every_sample_verifies_on_at_least_one_backend() {
        for sample in corpus() {
            let verified = BACKENDS.iter().any(|backend| {
                backend
                    .provider
                    .verify_signature(&sample.algorithm, &sample.spki, sample.message, sample.signature)
                    .is_ok()
            });
            assert!(verified, "no backend verified sample {}", sample.label);
        }
    }
}
