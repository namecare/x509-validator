//! Confirms x509-verify agrees with our own backends on the signature corpus.
//!
//! `benches/internals/crypto_atomic.rs` uses `harness = false`, so a `#[test]`
//! placed inside it never runs. This is where the check executes.
#![cfg(feature = "verify_peer")]

use x509_validator_bench_compare::signatures;
use x509_verify::der::Decode;
use x509_verify::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoRef};
use x509_verify::{Message, Signature, VerifyInfo, VerifyingKey};

#[test]
fn x509_verify_accepts_every_corpus_sample() {
    let mut supported = 0;

    for sample in signatures::corpus() {
        // Algorithms x509-verify does not support are skipped, not failed: an
        // absent row means "unsupported", matching how the benchmark treats an
        // unsupported backend pairing.
        let Ok(spki) = SubjectPublicKeyInfoRef::from_der(sample.spki.raw) else {
            continue;
        };
        let Ok(key) = VerifyingKey::try_from(spki) else {
            continue;
        };
        let Some(algorithm_der) = signatures::algorithm_der(&sample.algorithm) else {
            continue;
        };
        let Ok(algorithm) = AlgorithmIdentifierOwned::from_der(&algorithm_der) else {
            continue;
        };

        let info = VerifyInfo::new(
            Message::new(sample.message),
            Signature::new(&algorithm, sample.signature),
        );
        assert!(
            key.verify(info).is_ok(),
            "x509-verify must accept the {} sample our backends accept",
            sample.label,
        );
        supported += 1;
    }

    // Every corpus algorithm is expected to be supported by x509-verify's
    // default features. Asserting the exact count (rather than just "> 0")
    // means a future x509-verify release dropping support, or a regression
    // in `algorithm_der`, shows up as a hard failure instead of silently
    // shrinking the bench's row count.
    assert_eq!(
        supported,
        signatures::corpus().len(),
        "x509-verify should support every corpus algorithm",
    );
}
