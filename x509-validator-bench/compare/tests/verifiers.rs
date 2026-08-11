//! Every verifier in the comparison must reach the same verdict.
//!
//! `benches/verifiers.rs` uses `harness = false`, so a `#[test]` inside it
//! never runs. Without this check, one library could be silently failing —
//! timing its cheap error path and appearing fastest.
#![cfg(feature = "verifiers")]

use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::{AllOfPolicies, ServerIdentityPolicy, Tuple2, Validator};
use x509_validator_bench_compare::{apple, parity, DEFAULT_BACKEND, REFERENCE_TIME};

#[test]
fn all_verifiers_accept_the_tls_chain() {
    let parity = parity();

    // Ours, with TLS server-auth semantics rather than an empty policy.
    // `tests/` and `benches/` are separate compilation targets that cannot
    // share private code, so this setup is inlined rather than reached
    // through a shared helper.
    let roots = CertificateStore::from_iter(vec![parity.ca1.clone()]);
    let intermediates = CertificateStore::from_iter(vec![parity.intermediate1.clone()]);
    let policy = AllOfPolicies::new(Tuple2::new(
        RFC5280Policy::new(REFERENCE_TIME),
        ServerIdentityPolicy::new(Some("localhost"), None),
    ));
    let validator = Validator::with_policy_and_backend(roots, policy, DEFAULT_BACKEND.provider);
    let result =
        validator.validate_with_diagnostics(&parity.localhost_leaf, &intermediates, &mut |_| {});
    assert!(
        result.is_ok(),
        "our validator must accept the TLS fixture chain",
    );

    // rustls-webpki.
    let leaf = CertificateDer::from(parity.localhost_leaf.as_raw());
    let inter = CertificateDer::from(parity.intermediate1.as_raw());
    let root = CertificateDer::from(parity.ca1.as_raw());
    let anchor = webpki::anchor_from_trusted_cert(&root).expect("anchor");
    let ee = webpki::EndEntityCert::try_from(&leaf).expect("parse leaf");
    let time = UnixTime::since_unix_epoch(core::time::Duration::from_secs(REFERENCE_TIME as u64));
    assert!(
        ee.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor],
            &[inter],
            time,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .is_ok(),
        "rustls-webpki must accept the same chain our validator accepts",
    );
    let name = ServerName::try_from("localhost").expect("server name");
    assert!(
        ee.verify_is_valid_for_subject_name(&name)
            .is_ok(),
        "rustls-webpki must accept the localhost SAN",
    );
}

#[test]
fn all_verifiers_accept_the_apple_chain() {
    let chain = apple::chain();

    // Ours. No `ServerIdentityPolicy`: this receipt-signing leaf has no
    // SAN, so a name check would fail every backend and prove nothing —
    // see `benches/verifiers.rs`'s `apple_chain` module doc for the detail.
    let roots = CertificateStore::from_iter(vec![chain.root.clone()]);
    let intermediates = CertificateStore::from_iter(vec![chain.intermediate.clone()]);
    let policy = RFC5280Policy::new(apple::SIGNED_DATE);
    let validator = Validator::with_policy_and_backend(roots, policy, DEFAULT_BACKEND.provider);
    let result = validator.validate_with_diagnostics(&chain.leaf, &intermediates, &mut |_| {});
    assert!(
        result.is_ok(),
        "our validator must accept the Apple receipt chain",
    );

    // rustls-webpki.
    let leaf = CertificateDer::from(chain.leaf.as_raw());
    let inter = CertificateDer::from(chain.intermediate.as_raw());
    let root = CertificateDer::from(chain.root.as_raw());
    let anchor = webpki::anchor_from_trusted_cert(&root).expect("anchor");
    let ee = webpki::EndEntityCert::try_from(&leaf).expect("parse leaf");
    let time =
        UnixTime::since_unix_epoch(core::time::Duration::from_secs(apple::SIGNED_DATE as u64));
    assert!(
        ee.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor],
            &[inter],
            time,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .is_ok(),
        "rustls-webpki must accept the same Apple receipt chain our validator accepts",
    );
}

#[cfg(feature = "openssl")]
#[test]
fn openssl_accepts_the_tls_chain() {
    use openssl::stack::Stack;
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::verify::X509VerifyParam;
    use openssl::x509::{X509StoreContext, X509};

    let parity = parity();
    let leaf = X509::from_der(parity.localhost_leaf.as_raw()).expect("leaf");
    let inter = X509::from_der(parity.intermediate1.as_raw()).expect("inter");
    let root = X509::from_der(parity.ca1.as_raw()).expect("root");

    let mut builder = X509StoreBuilder::new().expect("builder");
    builder
        .add_cert(root)
        .expect("add root");

    let mut param = X509VerifyParam::new().expect("param");
    param.set_time(REFERENCE_TIME);
    param
        .set_host("localhost")
        .expect("host");
    builder
        .set_param(&param)
        .expect("set param");
    let store = builder.build();

    let mut chain = Stack::new().expect("stack");
    chain.push(inter).expect("push inter");

    let mut ctx = X509StoreContext::new().expect("ctx");
    let verified = ctx
        .init(&store, &leaf, &chain, |c| c.verify_cert())
        .expect("verify");
    assert!(
        verified,
        "openssl must accept the same chain our validator accepts",
    );
}
