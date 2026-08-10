//! The same atomic crypto operations, run against every backend.
//!
//! This is the tier where the backends actually differ: everything else in
//! the crate is shared code.

use x509_validator_bench_compare::{signatures, Backend, BACKENDS};

fn main() {
    divan::main();
}

/// Defines one verification benchmark for a named corpus entry, run against
/// every compiled-in backend.
///
/// One function per algorithm rather than a loop over the corpus: divan's
/// `args` supplies a single axis (the backend), so the algorithm axis has to
/// come from separate functions for each to appear as its own row.
macro_rules! verify_bench {
    ($name:ident, $label:literal) => {
        #[divan::bench(args = BACKENDS)]
        fn $name(bencher: divan::Bencher<'_, '_>, backend: Backend) {
            let sample = signatures::corpus()
                .iter()
                .find(|s| s.label == $label)
                .expect(concat!("corpus contains ", $label));

            // Backends need not support every algorithm. When this pairing
            // is unsupported, return without registering a bench closure so
            // the row is simply absent from the report rather than timing
            // the rejection path, which would read as suspiciously fast.
            // An absent row means "unsupported", not "crashed".
            if backend
                .provider
                .verify_signature(
                    &sample.algorithm,
                    &sample.spki,
                    sample.message,
                    sample.signature,
                )
                .is_err()
            {
                return;
            }

            bencher.bench(|| {
                divan::black_box(backend.provider.verify_signature(
                    divan::black_box(&sample.algorithm),
                    divan::black_box(&sample.spki),
                    divan::black_box(sample.message),
                    divan::black_box(sample.signature),
                ))
                .ok();
            });
        }
    };
}

verify_bench!(verify_ecdsa_p256_sha256, "ecdsa_p256_sha256");
verify_bench!(verify_ecdsa_p384_sha384, "ecdsa_p384_sha384");
verify_bench!(verify_ed25519, "ed25519");
verify_bench!(verify_rsa_2048_sha256, "rsa_2048_sha256");
verify_bench!(verify_rsa_4096_sha256, "rsa_4096_sha256");
