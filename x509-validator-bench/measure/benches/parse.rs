//! DER parsing cost over a realistic corpus of root certificates.

use core::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use x509_validator::{Certificate, FromDer};
use x509_validator_bench_measure::roots::ROOTS;

fn parse(c: &mut Criterion) {
    // The whole corpus, parsed once per iteration.
    c.bench_function("parse/webpki_roots", |b| {
        b.iter(|| {
            for der in ROOTS {
                let (_, certificate) = Certificate::from_der(black_box(der)).expect("parse root");
                black_box(
                    certificate
                        .tbs_certificate
                        .extensions()
                        .len(),
                );
            }
        })
    });

    // A single root, so the per-certificate cost is readable without
    // dividing by the corpus size. `ROOTS[0]` is the corpus's largest
    // certificate, so this figure is pessimistic relative to a median root.
    c.bench_function("parse/single_root", |b| {
        let der = ROOTS[0];
        b.iter(|| {
            let (_, certificate) = Certificate::from_der(black_box(der)).expect("parse root");
            black_box(
                certificate
                    .tbs_certificate
                    .extensions()
                    .len(),
            )
        })
    });
}

criterion_group!(benches, parse);
criterion_main!(benches);
