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
    use x509_validator_bench_compare::{apple, parity, REFERENCE_TIME};

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
    fn chains() -> &'static [Chain] {
        static CHAINS: std::sync::OnceLock<Vec<Chain>> = std::sync::OnceLock::new();
        CHAINS.get_or_init(|| {
            let parity = parity();
            let apple = apple::chain();
            vec![
                // leaf → intermediate → root, the common case.
                Chain {
                    name: "three_cert",
                    roots: vec![parity.ca1.clone()],
                    intermediates: vec![parity.intermediate1.clone()],
                    leaf: parity.localhost_leaf.clone(),
                    at: REFERENCE_TIME,
                },
                // The same chain where the intermediate store also holds
                // cross-signed decoys that must be rejected — the cost of
                // issuer search rather than the happy path alone.
                Chain {
                    name: "cross_signed_candidates",
                    roots: vec![parity.ca1.clone(), parity.ca2.clone()],
                    intermediates: vec![
                        parity.intermediate1.clone(),
                        parity.ca1_cross_signed_by_ca2.clone(),
                        parity.ca2_cross_signed_by_ca1.clone(),
                    ],
                    leaf: parity.localhost_leaf.clone(),
                    at: REFERENCE_TIME,
                },
                // A real, publicly-issued chain: Apple's receipt-signing leaf
                // → WWDR G6 → Apple Root CA - G3, validated at the
                // `signedDate` of a payload these certificates actually
                // signed. Both verifications are ECDSA-P384, where the spread
                // between backends is widest, so this is the pessimistic
                // real-world case rather than the average one.
                Chain {
                    name: "apple_receipt",
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
