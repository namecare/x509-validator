//! Pre-signed material for the atomic crypto benchmarks.
use core::ops::Range;
use std::sync::OnceLock;

use x509_validator::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use x509_validator::{Certificate, FromDer};
use x509_validator_testkit::rcgen::{
    CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
};

/// One verifiable signature, with everything needed to check it.
///
/// Owns the DER it was built from. The algorithm and key are views into that
/// DER, so they are parsed on access rather than stored: a struct holding
/// both the bytes and borrows of them would be self-referential. The message
/// and signature are recorded as ranges of the DER for the same reason.
pub struct SignedSample {
    pub label: &'static str,
    der: Vec<u8>,
    /// The range of `der` holding the signed `TbsCertificate`.
    message: Range<usize>,
    /// The range of `der` holding the signature over `message`.
    signature: Range<usize>,
}

impl SignedSample {
    /// Builds a sample from the DER of a self-signed certificate.
    fn new(label: &'static str, der: Vec<u8>) -> Self {
        let (message, signature) = {
            let certificate = Certificate::from_der(&der)
                .expect("parse")
                .1;
            (
                range_within(&der, certificate.tbs_certificate.as_ref()),
                range_within(&der, certificate.signature_value.as_ref()),
            )
        };

        Self {
            label,
            der,
            message,
            signature,
        }
    }

    /// The certificate the sample's algorithm and key come from.
    fn certificate(&self) -> Certificate<'_> {
        Certificate::from_der(&self.der)
            .expect("parse")
            .1
    }

    /// The algorithm the signature was produced with.
    pub fn algorithm(&self) -> AlgorithmIdentifier<'_> {
        self.certificate().signature_algorithm
    }

    /// The public key the signature verifies against.
    pub fn spki(&self) -> SubjectPublicKeyInfo<'_> {
        self.certificate()
            .tbs_certificate
            .subject_pki
    }

    /// The bytes that were signed.
    pub fn message(&self) -> &[u8] {
        &self.der[self.message.clone()]
    }

    /// The signature over [`Self::message`].
    pub fn signature(&self) -> &[u8] {
        &self.der[self.signature.clone()]
    }
}

/// The range of `whole` that `part` occupies.
///
/// `part` is a subslice of `whole` produced by the parser, so recording it as
/// a range lets the sample keep referring to those bytes after the parsed
/// certificate they came from is dropped.
fn range_within(whole: &[u8], part: &[u8]) -> Range<usize> {
    let start = part.as_ptr() as usize - whole.as_ptr() as usize;
    debug_assert!(
        start + part.len() <= whole.len(),
        "part must lie within whole"
    );
    start..start + part.len()
}

/// divan labels an `args` row with its `Debug` output, so this prints just
/// the algorithm name — which is what the row should read as.
impl core::fmt::Debug for SignedSample {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label)
    }
}

/// The corpus, built once on first call.
///
/// Generating keys is expensive and must never land inside a timed region,
/// so the corpus is built once and reused across every benchmark. `divan`
/// takes its `args` as `&'static [T]`, which is what this lifetime is for.
static CORPUS: OnceLock<Vec<SignedSample>> = OnceLock::new();

pub fn corpus() -> &'static [SignedSample] {
    CORPUS.get_or_init(build)
}

/// The DER of a self-signed certificate for `key_pair`.
fn self_signed_der(key_pair: KeyPair) -> Vec<u8> {
    CertificateParams::default()
        .self_signed(&key_pair)
        .expect("self-sign")
        .der()
        .to_vec()
}

fn build() -> Vec<SignedSample> {
    let mut corpus = vec![
        SignedSample::new(
            "ecdsa_p256_sha256",
            self_signed_der(KeyPair::generate().expect("p256 key")),
        ),
        SignedSample::new(
            "ecdsa_p384_sha384",
            self_signed_der(KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("p384 key")),
        ),
        SignedSample::new(
            "ed25519",
            self_signed_der(KeyPair::generate_for(&PKCS_ED25519).expect("ed25519 key")),
        ),
    ];

    // rcgen cannot generate RSA keys, so these are generated with `rsa` and
    // handed to rcgen as a PKCS#8 private key.
    for (label, bits) in [
        ("rsa_2048_sha256", 2048usize),
        ("rsa_4096_sha256", 4096usize),
    ] {
        corpus.push(SignedSample::new(
            label,
            self_signed_der(rsa_key_pair(bits)),
        ));
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
                        &sample.algorithm(),
                        &sample.spki(),
                        sample.message(),
                        sample.signature(),
                    )
                    .is_ok()
            });
            assert!(verified, "no backend verified sample {}", sample.label);
        }
    }
}
