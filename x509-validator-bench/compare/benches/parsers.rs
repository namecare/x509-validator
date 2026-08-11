//! DER parsing, our parser against the others.

use x509_validator_bench_compare::{apple, ROOTS};

fn main() {
    divan::main();
}

/// One named corpus of DER-encoded certificates.
#[derive(Clone, Copy)]
struct Corpus {
    name: &'static str,
    ders: &'static [&'static [u8]],
}

impl core::fmt::Debug for Corpus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name)
    }
}

const CORPORA: &[Corpus] = &[
    Corpus {
        name: "webpki_roots",
        ders: ROOTS,
    },
    Corpus {
        name: "single_root",
        ders: &[ROOTS[0]],
    },
    Corpus {
        name: "apple_leaf",
        ders: &[apple::LEAF_DER],
    },
];

/// Case A: parse and enumerate every extension.
mod full_parse {
    use divan::{black_box, Bencher};

    use super::{Corpus, CORPORA};

    #[divan::bench(args = CORPORA)]
    fn x509_parser(bencher: Bencher<'_, '_>, corpus: Corpus) {
        use x509_validator::{Certificate, FromDer};

        bencher.bench(|| {
            for der in corpus.ders {
                let (_, certificate) =
                    Certificate::from_der(black_box(der)).expect("parse certificate");
                black_box(
                    certificate
                        .tbs_certificate
                        .extensions()
                        .len(),
                );
            }
        });
    }

    #[divan::bench(args = CORPORA)]
    fn x509_cert(bencher: Bencher<'_, '_>, corpus: Corpus) {
        use der::Decode;
        use x509_cert::Certificate;

        bencher.bench(|| {
            for der in corpus.ders {
                let certificate = Certificate::from_der(black_box(der)).expect("parse certificate");
                black_box(
                    certificate
                        .tbs_certificate()
                        .extensions()
                        .map_or(0, |extensions| extensions.len()),
                );
            }
        });
    }
}

/// Case B: parse, then walk to the subject alternative name extension and
/// count its entries. openssl joins here because this is the largest job its
/// API can do without an extension-list accessor.
mod read_san {
    use divan::{black_box, Bencher};

    use super::{Corpus, CORPORA};

    #[divan::bench(args = CORPORA)]
    fn x509_parser(bencher: Bencher<'_, '_>, corpus: Corpus) {
        use x509_validator::{Certificate, FromDer};

        bencher.bench(|| {
            for der in corpus.ders {
                let (_, certificate) =
                    Certificate::from_der(black_box(der)).expect("parse certificate");
                black_box(
                    certificate
                        .tbs_certificate
                        .subject_alternative_name()
                        .ok()
                        .flatten()
                        .map_or(0, |san| san.value.general_names.len()),
                );
            }
        });
    }

    #[divan::bench(args = CORPORA)]
    fn x509_cert(bencher: Bencher<'_, '_>, corpus: Corpus) {
        use const_oid::AssociatedOid;
        use der::Decode;
        use x509_cert::ext::pkix::name::GeneralNames;
        use x509_cert::ext::pkix::SubjectAltName;
        use x509_cert::Certificate;

        bencher.bench(|| {
            for der in corpus.ders {
                let certificate = Certificate::from_der(black_box(der)).expect("parse certificate");
                // Find the SAN extension, decode just that one, and count its
                // entries — mirroring the smaller job the other two rows do,
                // rather than enumerating every extension.
                black_box(
                    certificate
                        .tbs_certificate()
                        .extensions()
                        .and_then(|extensions| {
                            extensions
                                .iter()
                                .find(|extension| extension.extn_id == SubjectAltName::OID)
                        })
                        .and_then(|extension| {
                            SubjectAltName::from_der(extension.extn_value.as_bytes()).ok()
                        })
                        .map_or(0, |san| GeneralNames::from(san).len()),
                );
            }
        });
    }

    #[divan::bench(args = CORPORA)]
    #[cfg(feature = "openssl")]
    fn openssl(bencher: Bencher<'_, '_>, corpus: Corpus) {
        bencher.bench(|| {
            for der in corpus.ders {
                let certificate =
                    openssl::x509::X509::from_der(black_box(der)).expect("parse certificate");
                black_box(
                    certificate
                        .subject_alt_names()
                        .map_or(0, |names| names.len()),
                );
            }
        });
    }
}
