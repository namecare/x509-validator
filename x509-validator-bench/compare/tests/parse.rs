//! Confirms the vendored Mozilla CA bundle roots are correctly embedded as
//! DER for `benches/parsers.rs`.
//!
//! The parsing benchmark uses `harness = false`, so a plain `#[test]` placed
//! inside it never runs under `cargo test` — divan's own `main` drives that
//! binary. This integration test is where the completeness and parseability
//! checks actually execute.
//!
//! The corpus itself lives in `src/roots.rs` so this test and the benchmark
//! read the same list. They were once separate copies, which meant this test
//! could pass while the benchmark measured a different set of certificates.

use x509_validator_bench_compare::roots::ROOTS;
use x509_validator::{Certificate, FromDer};

#[test]
fn every_root_parses_and_corpus_is_complete() {
    assert_eq!(ROOTS.len(), 137, "corpus should hold every vendored root");
    for der in ROOTS {
        let (_, certificate) = Certificate::from_der(der).expect("every vendored root parses");
        assert!(!certificate.tbs_certificate.subject.as_raw().is_empty());
    }
}

/// Both parsers in `benches/parsers.rs` must actually succeed on the whole
/// corpus. A benchmark whose rival silently fails on some inputs would be
/// timing an error path and reporting it as a parse.
#[test]
fn x509_cert_parses_every_root_too() {
    use der::Decode;

    for der in ROOTS {
        x509_cert::Certificate::from_der(der).expect("x509-cert parses every vendored root");
    }
}
