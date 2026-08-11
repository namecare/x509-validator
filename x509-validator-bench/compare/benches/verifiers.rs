//! Full path validation, verifier against verifier: our own library against
//! rustls-webpki and openssl.

fn main() {
    divan::main();
}

/// leaf → intermediate → root, all three libraries, matched TLS server-auth
/// semantics.
mod tls_fixture {
    use divan::{black_box, Bencher};
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
    use x509_validator::crypto::SignatureVerifier;
    use x509_validator::rfc5280::RFC5280Policy;
    use x509_validator::store::CertificateStore;
    use x509_validator::{AllOfPolicies, ServerIdentityPolicy, Tuple2, Validator};
    use x509_validator_bench_compare::{parity, REFERENCE_TIME};

    const HOST: &str = "localhost";

    /// Our own validator on `provider`, composing RFC5280 with a hostname
    /// check so it does the same work the other two rows do.
    fn ours(bencher: Bencher<'_, '_>, provider: &'static dyn SignatureVerifier) {
        let parity = parity();
        let roots = vec![parity.ca1.clone()];
        let intermediates = vec![parity.intermediate1.clone()];

        let validate = || {
            let validator = Validator::with_policy_and_backend(
                CertificateStore::from_iter(roots.clone()),
                AllOfPolicies::new(Tuple2::new(
                    RFC5280Policy::new(REFERENCE_TIME),
                    ServerIdentityPolicy::new(Some(HOST), None),
                )),
                provider,
            );
            validator.validate_with_diagnostics(
                &parity.localhost_leaf,
                &CertificateStore::from_iter(intermediates.clone()),
                &mut |_| {},
            )
        };

        // Confirm the chain actually validates before timing anything: if
        // this silently failed, the benchmark below would measure the (much
        // cheaper) error path and every number would be meaningless.
        assert!(
            validate().is_ok(),
            "our validator must accept the TLS fixture chain",
        );

        bencher.bench(|| black_box(validate()));
    }

    #[cfg(feature = "aws_lc")]
    #[divan::bench]
    fn ours_aws_lc(bencher: Bencher<'_, '_>) {
        ours(bencher, &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER);
    }

    #[cfg(feature = "ring")]
    #[divan::bench]
    fn ours_ring(bencher: Bencher<'_, '_>) {
        ours(bencher, &x509_validator::crypto::ring::DEFAULT_PROVIDER);
    }

    #[cfg(feature = "rust_crypto")]
    #[divan::bench]
    fn ours_rust_crypto(bencher: Bencher<'_, '_>) {
        ours(
            bencher,
            &x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER,
        );
    }

    #[divan::bench]
    fn rustls_webpki(bencher: Bencher<'_, '_>) {
        let parity = parity();
        let leaf = CertificateDer::from(parity.localhost_leaf.as_raw());
        let inter = CertificateDer::from(parity.intermediate1.as_raw());
        let root = CertificateDer::from(parity.ca1.as_raw());
        let time =
            UnixTime::since_unix_epoch(core::time::Duration::from_secs(REFERENCE_TIME as u64));
        let name = ServerName::try_from(HOST).expect("server name");

        let verify = || {
            let anchor = webpki::anchor_from_trusted_cert(&root).expect("anchor");
            let ee = webpki::EndEntityCert::try_from(&leaf).expect("parse leaf");
            ee.verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                core::slice::from_ref(&anchor),
                core::slice::from_ref(&inter),
                time,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .expect("verify");
            ee.verify_is_valid_for_subject_name(&name)
                .is_ok()
        };
        assert!(
            verify(),
            "rustls-webpki must accept the TLS fixture chain and its localhost SAN",
        );

        bencher.bench(|| black_box(verify()));
    }

    #[divan::bench]
    #[cfg(feature = "openssl")]
    fn openssl(bencher: Bencher<'_, '_>) {
        let parity = parity();
        let verify = || {
            super::openssl_verify(
                parity.localhost_leaf.as_raw(),
                parity.intermediate1.as_raw(),
                parity.ca1.as_raw(),
                REFERENCE_TIME,
                Some(HOST),
            )
        };
        assert!(verify(), "openssl must accept the TLS fixture chain");

        bencher.bench(|| black_box(verify()));
    }
}

/// A real, publicly-issued chain: Apple's receipt-signing leaf → WWDR G6 →
/// Apple Root CA - G3, validated at the `signedDate` of a payload these
/// certificates actually signed.
mod apple_chain {
    use divan::{black_box, Bencher};
    use rustls_pki_types::{CertificateDer, UnixTime};
    use x509_validator::crypto::SignatureVerifier;
    use x509_validator::rfc5280::RFC5280Policy;
    use x509_validator::store::CertificateStore;
    use x509_validator::Validator;
    use x509_validator_bench_compare::apple;

    /// Our own validator on `provider`. No `ServerIdentityPolicy` here: see
    /// this module's doc for why neither row checks a name.
    fn ours(bencher: Bencher<'_, '_>, provider: &'static dyn SignatureVerifier) {
        let chain = apple::chain();
        let roots = vec![chain.root.clone()];
        let intermediates = vec![chain.intermediate.clone()];

        let validate = || {
            let validator = Validator::with_policy_and_backend(
                CertificateStore::from_iter(roots.clone()),
                RFC5280Policy::new(apple::SIGNED_DATE),
                provider,
            );
            validator.validate_with_diagnostics(
                &chain.leaf,
                &CertificateStore::from_iter(intermediates.clone()),
                &mut |_| {},
            )
        };

        assert!(
            validate().is_ok(),
            "our validator must accept the Apple receipt chain",
        );

        bencher.bench(|| black_box(validate()));
    }

    #[cfg(feature = "aws_lc")]
    #[divan::bench]
    fn ours_aws_lc(bencher: Bencher<'_, '_>) {
        ours(bencher, &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER);
    }

    #[cfg(feature = "ring")]
    #[divan::bench]
    fn ours_ring(bencher: Bencher<'_, '_>) {
        ours(bencher, &x509_validator::crypto::ring::DEFAULT_PROVIDER);
    }

    #[cfg(feature = "rust_crypto")]
    #[divan::bench]
    fn ours_rust_crypto(bencher: Bencher<'_, '_>) {
        ours(
            bencher,
            &x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER,
        );
    }

    #[divan::bench]
    fn rustls_webpki(bencher: Bencher<'_, '_>) {
        let chain = apple::chain();
        let leaf = CertificateDer::from(chain.leaf.as_raw());
        let inter = CertificateDer::from(chain.intermediate.as_raw());
        let root = CertificateDer::from(chain.root.as_raw());
        let time =
            UnixTime::since_unix_epoch(core::time::Duration::from_secs(apple::SIGNED_DATE as u64));

        let verify = || {
            let anchor = webpki::anchor_from_trusted_cert(&root).expect("anchor");
            let ee = webpki::EndEntityCert::try_from(&leaf).expect("parse leaf");
            ee.verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                core::slice::from_ref(&anchor),
                core::slice::from_ref(&inter),
                time,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .is_ok()
        };
        assert!(
            verify(),
            "rustls-webpki must accept the Apple receipt chain",
        );

        bencher.bench(|| black_box(verify()));
    }
}

/// openssl's verification path.
///
/// Store and parameter construction happen inside this helper on every call
/// rather than being hoisted out, since openssl's `X509Store` does not
/// implement `Clone`; the alternative would be rebuilding the store per
/// iteration anyway, which is exactly what this does. The other rows in this
/// file also build their stores inside the timed region, so the shapes match.
#[cfg(feature = "openssl")]
fn openssl_verify(leaf: &[u8], inter: &[u8], root: &[u8], at: i64, host: Option<&str>) -> bool {
    use openssl::stack::Stack;
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::verify::X509VerifyParam;
    use openssl::x509::{X509StoreContext, X509};

    let leaf = X509::from_der(leaf).expect("leaf");
    let inter = X509::from_der(inter).expect("inter");
    let root = X509::from_der(root).expect("root");

    let mut builder = X509StoreBuilder::new().expect("builder");
    builder
        .add_cert(root)
        .expect("add root");

    // Pinned to a fixed time, matching the other rows: without this, openssl
    // validates against the wall clock and the fixture's validity window
    // would decide the result.
    let mut param = X509VerifyParam::new().expect("param");
    param.set_time(at);
    if let Some(host) = host {
        param.set_host(host).expect("host");
    }
    builder
        .set_param(&param)
        .expect("set param");
    let store = builder.build();

    let mut chain = Stack::new().expect("stack");
    chain.push(inter).expect("push inter");

    let mut ctx = X509StoreContext::new().expect("ctx");
    ctx.init(&store, &leaf, &chain, |c| c.verify_cert())
        .expect("verify")
}
