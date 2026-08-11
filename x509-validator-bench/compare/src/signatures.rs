//! Pre-signed material for the atomic crypto benchmarks.
use std::sync::OnceLock;

use x509_validator::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use x509_validator::{Certificate, FromDer};
use x509_validator_testkit::parse::leak;
use x509_validator_testkit::rcgen::{
    CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
};

/// One verifiable signature, with everything needed to check it.
pub struct SignedSample {
    pub label: &'static str,
    pub algorithm: AlgorithmIdentifier<'static>,
    pub spki: SubjectPublicKeyInfo<'static>,
    pub message: &'static [u8],
    pub signature: &'static [u8],
}

/// divan labels an `args` row with its `Debug` output, so this prints just
/// the algorithm name — which is what the row should read as.
impl core::fmt::Debug for SignedSample {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label)
    }
}

static CORPUS: OnceLock<Vec<SignedSample>> = OnceLock::new();

pub fn corpus() -> &'static [SignedSample] {
    CORPUS.get_or_init(build)
}

/// Builds a sample from a self-signed certificate
fn sample_from_self_signed(label: &'static str, key_pair: KeyPair) -> SignedSample {
    let der = CertificateParams::default()
        .self_signed(&key_pair)
        .expect("self-sign")
        .der()
        .to_vec();
    let der: &'static [u8] = leak(der);
    let certificate: &'static Certificate<'static> = Box::leak(Box::new(
        Certificate::from_der(der)
            .expect("parse")
            .1,
    ));

    SignedSample {
        label,
        algorithm: certificate.signature_algorithm.clone(),
        spki: certificate
            .tbs_certificate
            .subject_pki
            .clone(),
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
        sample_from_self_signed(
            "ed25519",
            KeyPair::generate_for(&PKCS_ED25519).expect("ed25519 key"),
        ),
    ];

    // rcgen cannot generate RSA keys, so these are generated with `rsa` and
    // handed to rcgen as a PKCS#8 private key.
    for (label, bits) in [
        ("rsa_2048_sha256", 2048usize),
        ("rsa_4096_sha256", 4096usize),
    ] {
        corpus.push(sample_from_self_signed(label, rsa_key_pair(bits)));
    }

    corpus
}

/// Re-encodes an `AlgorithmIdentifier` to DER.
///
/// Unlike `SubjectPublicKeyInfo`, x509-parser's `AlgorithmIdentifier` keeps
/// no `.raw` field, so there is no unparsed DER to hand to x509-verify
/// directly. Its `algorithm` OID and optional `parameters` are each
/// DER-encodable on their own, so the SEQUENCE is rebuilt from those parts.
#[cfg(feature = "verify_peer")]
pub fn algorithm_der(algorithm: &AlgorithmIdentifier<'_>) -> Option<Vec<u8>> {
    use x509_validator::asn1_rs::{Sequence, ToDer};

    let mut content = algorithm.algorithm.to_der_vec().ok()?;
    if let Some(parameters) = &algorithm.parameters {
        content.extend_from_slice(&parameters.to_der_vec().ok()?);
    }
    Sequence::new(content.into())
        .to_der_vec()
        .ok()
}

/// An RSA key pair of `bits`
fn rsa_key_pair(bits: usize) -> KeyPair {
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::RsaPrivateKey;

    let mut rng = rand::rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("generate RSA key");
    let pkcs8 = private_key
        .to_pkcs8_der()
        .expect("encode PKCS#8");
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
                    .verify_signature(
                        &sample.algorithm,
                        &sample.spki,
                        sample.message,
                        sample.signature,
                    )
                    .is_ok()
            });
            assert!(verified, "no backend verified sample {}", sample.label);
        }
    }
}
