//! Our own internals, backend against backend.

fn main() {
    divan::main();
}

/// End-to-end chain validation, per backend.
///
/// `args` is the chain being validated; the backend is the bench function.
mod backend {
    use divan::{black_box, Bencher};
    use x509_validator::crypto::SignatureVerifier;
    use x509_validator::rfc5280::RFC5280Policy;
    use x509_validator::store::CertificateStore;
    use x509_validator::{Certificate, Validator};
    use x509_validator_bench_compare::{apple, p256_chain, REFERENCE_TIME};

    /// One chain to validate: a trust store, an intermediate store, a leaf,
    /// and the time to evaluate validity at.
    struct Chain {
        name: &'static str,
        roots: Vec<Certificate<'static>>,
        intermediates: Vec<Certificate<'static>>,
        leaf: Certificate<'static>,
        at: i64,
    }

    impl core::fmt::Debug for Chain {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str(self.name)
        }
    }

    /// The chains every backend below is measured against.
    ///
    /// Two chains of the same shape — leaf → intermediate → root, two
    /// signature verifications each — differing only in the curve of the
    /// issuer keys doing the verifying. That isolation is the point: a
    /// backend's two rows differ by curve alone, so the pair shows both what
    /// it costs where the curve is well optimized and where it is not.
    ///
    /// Which curve verifies is set by the ISSUER's key, not the subject's. In
    /// the Apple chain the leaf is itself P-256, but it is verified with the
    /// intermediate's P-384 key, so every verification in that chain is P-384.
    fn chains() -> &'static [Chain] {
        static CHAINS: std::sync::OnceLock<Vec<Chain>> = std::sync::OnceLock::new();
        CHAINS.get_or_init(|| {
            let p256 = p256_chain();
            let apple = apple::chain();
            vec![
                // The fast curve. Both verifications use P-256 issuer keys,
                // which every backend has a dedicated implementation for.
                Chain {
                    name: "p256_chain",
                    roots: vec![p256.root.clone()],
                    intermediates: vec![p256.intermediate.clone()],
                    leaf: p256.leaf.clone(),
                    at: REFERENCE_TIME,
                },
                // The real, publicly-issued counterpart: Apple's
                // receipt-signing leaf → WWDR G6 → Apple Root CA - G3,
                // validated at the `signedDate` of a payload these
                // certificates actually signed. Both the intermediate and the
                // root hold P-384 keys, so both verifications are P-384 —
                // the curve where backends diverge most.
                Chain {
                    name: "apple_receipt_p384",
                    roots: vec![apple.root.clone()],
                    intermediates: vec![apple.intermediate.clone()],
                    leaf: apple.leaf.clone(),
                    at: apple::SIGNED_DATE,
                },
            ]
        })
    }

    /// Validates `chain` on `provider`, timing store construction, validator
    /// construction, and validation together.
    fn validate(bencher: Bencher<'_, '_>, chain: &Chain, provider: &'static dyn SignatureVerifier) {
        let validator = || {
            Validator::with_policy_and_backend(
                CertificateStore::from_iter(chain.roots.clone()),
                RFC5280Policy::new(chain.at),
                provider,
            )
        };
        let intermediates = || CertificateStore::from_iter(chain.intermediates.clone());

        // Confirm the chain actually validates before timing anything: if
        // this silently failed, the benchmark below would measure the (much
        // cheaper) error path and every number would be meaningless.
        assert!(
            validator()
                .validate_with_diagnostics(&chain.leaf, &intermediates(), &mut |_| {})
                .is_ok(),
            "the {} chain must validate successfully before being timed",
            chain.name,
        );

        bencher.bench(|| {
            black_box(validator().validate_with_diagnostics(
                black_box(&chain.leaf),
                &intermediates(),
                &mut |_| {},
            ))
        });
    }

    #[cfg(feature = "aws_lc")]
    #[divan::bench(args = chains())]
    fn aws_lc(bencher: Bencher<'_, '_>, chain: &Chain) {
        validate(
            bencher,
            chain,
            &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER,
        );
    }

    #[cfg(feature = "ring")]
    #[divan::bench(args = chains())]
    fn ring(bencher: Bencher<'_, '_>, chain: &Chain) {
        validate(
            bencher,
            chain,
            &x509_validator::crypto::ring::DEFAULT_PROVIDER,
        );
    }

    #[cfg(feature = "rust_crypto")]
    #[divan::bench(args = chains())]
    fn rust_crypto(bencher: Bencher<'_, '_>, chain: &Chain) {
        validate(
            bencher,
            chain,
            &x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER,
        );
    }
}

/// A single signature verification, with nothing around it.
mod crypto_atomics {
    use divan::{black_box, Bencher};
    use x509_validator::crypto::SignatureVerifier;
    use x509_validator_bench_compare::signatures::{corpus, SignedSample};

    /// Verifies `sample` on `provider`.
    fn verify(
        bencher: Bencher<'_, '_>,
        sample: &SignedSample,
        provider: &'static dyn SignatureVerifier,
    ) {
        let verify = || {
            provider.verify_signature(
                &sample.algorithm,
                &sample.spki,
                sample.message,
                sample.signature,
            )
        };
        if verify().is_err() {
            return;
        }

        bencher.bench(|| {
            black_box(provider.verify_signature(
                black_box(&sample.algorithm),
                black_box(&sample.spki),
                black_box(sample.message),
                black_box(sample.signature),
            ))
            .ok()
        });
    }

    #[cfg(feature = "aws_lc")]
    #[divan::bench(args = corpus())]
    fn aws_lc(bencher: Bencher<'_, '_>, sample: &SignedSample) {
        verify(
            bencher,
            sample,
            &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER,
        );
    }

    #[cfg(feature = "ring")]
    #[divan::bench(args = corpus())]
    fn ring(bencher: Bencher<'_, '_>, sample: &SignedSample) {
        verify(
            bencher,
            sample,
            &x509_validator::crypto::ring::DEFAULT_PROVIDER,
        );
    }

    #[cfg(feature = "rust_crypto")]
    #[divan::bench(args = corpus())]
    fn rust_crypto(bencher: Bencher<'_, '_>, sample: &SignedSample) {
        verify(
            bencher,
            sample,
            &x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER,
        );
    }
}

#[cfg(feature = "aws_lc")]
mod validate {
    use core::hint::black_box;

    use x509_validator::store::CertificateStore;
    use x509_validator::{RFC5280Policy, Validator};
    use x509_validator_testkit::real_chain::apple;

    #[divan::bench]
    fn validate(bencher: divan::Bencher<'_, '_>) {
        let chain = apple::chain();
        let roots = vec![chain.root.clone()];
        let intermediates = vec![chain.intermediate.clone()];

        let validate = || {
            let validator = Validator::with_policy_and_backend(
                CertificateStore::from_iter(roots.clone()),
                RFC5280Policy::new(apple::SIGNED_DATE),
                &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER,
            );
            validator.validate(
                &chain.leaf,
                &CertificateStore::from_iter(intermediates.clone()),
            )
        };

        bencher.bench(|| black_box(validate()));
    }

    #[divan::bench]
    fn validate_with_diagnostics(bencher: divan::Bencher<'_, '_>) {
        let chain = apple::chain();
        let roots = vec![chain.root.clone()];
        let intermediates = vec![chain.intermediate.clone()];

        let validate = || {
            let validator = Validator::with_policy_and_backend(
                CertificateStore::from_iter(roots.clone()),
                RFC5280Policy::new(apple::SIGNED_DATE),
                &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER,
            );
            validator.validate_with_diagnostics(
                &chain.leaf,
                &CertificateStore::from_iter(intermediates.clone()),
                &mut |_| {},
            )
        };

        bencher.bench(|| black_box(validate()));
    }
}
