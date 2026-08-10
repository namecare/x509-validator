//! DER parsing, our parser against another.
//!
//! We parse via `x509_validator::Certificate`, which is a re-export of
//! x509-parser's `X509Certificate` — so this row is x509-parser's number,
//! with no wrapper overhead of ours in it. The rival is RustCrypto's
//! `x509-cert`.
//!
//! The two do not do equal work, and the ratio should not be read as a
//! straight verdict: x509-parser returns a view borrowing the input buffer,
//! while x509-cert returns an owned, heap-allocated tree that outlives its
//! input and can be cloned. Both benches touch the extension list so neither
//! side is credited for work it merely deferred.

use x509_validator_bench_compare::{fixtures, roots::ROOTS};

fn main() {
    divan::main();
}

/// The whole corpus of vendored roots, per parser.
mod webpki_roots {
    use super::*;

    #[divan::bench]
    fn x509_parser(bencher: divan::Bencher) {
        use x509_validator::{Certificate, FromDer};

        bencher.bench(|| {
            for der in ROOTS {
                let (_, certificate) = Certificate::from_der(divan::black_box(der)).expect("parse root");
                divan::black_box(certificate.tbs_certificate.extensions().len());
            }
        });
    }

    #[divan::bench]
    fn x509_cert(bencher: divan::Bencher) {
        use der::Decode;
        use x509_cert::Certificate;

        bencher.bench(|| {
            for der in ROOTS {
                let certificate = Certificate::from_der(divan::black_box(der)).expect("parse root");
                divan::black_box(certificate.tbs_certificate().extensions().map_or(0, |e| e.len()));
            }
        });
    }
}

/// A single root, so the per-certificate cost is readable without dividing
/// by the corpus size.
mod single_root {
    use super::*;

    #[divan::bench]
    fn x509_parser(bencher: divan::Bencher) {
        use x509_validator::{Certificate, FromDer};

        let der = ROOTS[0];
        bencher.bench(|| {
            let (_, certificate) = Certificate::from_der(divan::black_box(der)).expect("parse root");
            divan::black_box(certificate.tbs_certificate.extensions().len())
        });
    }

    #[divan::bench]
    fn x509_cert(bencher: divan::Bencher) {
        use der::Decode;
        use x509_cert::Certificate;

        let der = ROOTS[0];
        bencher.bench(|| {
            let certificate = Certificate::from_der(divan::black_box(der)).expect("parse root");
            divan::black_box(certificate.tbs_certificate().extensions().map_or(0, |e| e.len()))
        });
    }
}

/// A real, publicly-issued leaf, which carries policy OIDs and CRL/OCSP
/// pointers the vendored roots and generated fixtures do not.
mod apple_leaf {
    use super::*;

    #[divan::bench]
    fn x509_parser(bencher: divan::Bencher) {
        use x509_validator::{Certificate, FromDer};

        let der = fixtures::apple::LEAF_DER;
        bencher.bench(|| {
            let (_, certificate) = Certificate::from_der(divan::black_box(der)).expect("parse leaf");
            divan::black_box(certificate.tbs_certificate.extensions().len())
        });
    }

    #[divan::bench]
    fn x509_cert(bencher: divan::Bencher) {
        use der::Decode;
        use x509_cert::Certificate;

        let der = fixtures::apple::LEAF_DER;
        bencher.bench(|| {
            let certificate = Certificate::from_der(divan::black_box(der)).expect("parse leaf");
            divan::black_box(certificate.tbs_certificate().extensions().map_or(0, |e| e.len()))
        });
    }
}
