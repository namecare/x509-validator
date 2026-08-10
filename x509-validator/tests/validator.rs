//! Chain-building conformance for `Validator`, run against a real
//! crypto backend.
//!
//! Every certificate here is genuinely signed by the key of the certificate
//! named as its issuer, and every signature is checked by the compiled-in
//! backend. That makes assertions about *which* candidate issuer the search
//! accepts meaningful: RFC 5280 §6.1.3(a)(1) requires the candidate's public
//! key to actually verify the signature on the certificate below it, and a
//! certificate offered by the wrong key is rejected by real arithmetic
//! rather than by a test double.

#![cfg(any(feature = "aws_lc", feature = "ring", feature = "rust_crypto"))]

use std::sync::{Arc, Mutex};

#[cfg(feature = "aws_lc")]
use x509_validator::crypto::aws_lc::DEFAULT_PROVIDER;
#[cfg(all(feature = "ring", not(feature = "aws_lc")))]
use x509_validator::crypto::ring::DEFAULT_PROVIDER;
#[cfg(all(
    feature = "rust_crypto",
    not(feature = "aws_lc"),
    not(feature = "ring")
))]
use x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER;
use x509_validator::diagnostic::VerificationDiagnostic;
use x509_validator::oid_registry::{
    OID_X509_EXT_BASIC_CONSTRAINTS, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
};
use x509_validator::policy::{PolicyEvaluationResult, PolicyFailureReason, ValidationPolicy};
use x509_validator::store::CertificateStore;
use x509_validator::unverified_chain::UnverifiedCertificateChain;
use x509_validator::validator::ChainValidationResult;
use x509_validator::{Certificate, CertificateExt, Validator};
use x509_validator_testkit::rcgen::KeyPair;
use x509_validator_testkit::{
    Ski, cert, issue_ca, issue_ca_with_key, issue_ca_with_key_and_name, issue_ca_with_key_ids,
    issue_leaf, issue_leaf_with, issue_leaf_with_aki, leak, self_signed_ca_with,
    self_signed_ca_with_key_ids, signing_identity, weird_critical_extension,
};

fn parse(der: &'static [u8]) -> Certificate<'static> {
    Certificate::parse(der).unwrap()
}

/// Asserts that `result` is a valid chain whose certificates are exactly
/// `expected`, in leaf-to-root order. Comparison is on the full DER of
/// each certificate, so this catches a chain containing the right number
/// of certificates in the wrong order just as readily as a wrong one.
fn assert_chain_is(result: ChainValidationResult<'_>, expected: &[&Certificate<'_>]) {
    match result {
        Ok(chain) => {
            let actual: Vec<&[u8]> = chain
                .iter()
                .map(|c| c.as_ref())
                .collect();
            let expected: Vec<&[u8]> = expected
                .iter()
                .map(|c| c.as_ref())
                .collect();
            assert_eq!(
                actual, expected,
                "chain contents or order differ from expectation"
            );
        }
        Err(reasons) => {
            panic!("expected a valid chain, got failures: {reasons:?}")
        }
    }
}

/// A policy that accepts every chain, so that a test's outcome is decided
/// purely by chain building and signature verification.
struct AlwaysMeetsPolicy;
impl ValidationPolicy for AlwaysMeetsPolicy {
    fn verifying_critical_extensions(&self) -> Vec<x509_validator::der_parser::Oid<'static>> {
        // The generator always marks basicConstraints critical, so a policy
        // claiming no extensions at all would reject every generated
        // CA/root as carrying an unhandled critical extension.
        vec![OID_X509_EXT_BASIC_CONSTRAINTS]
    }
    fn chain_meets_policy_requirements(
        &self,
        _chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        Ok(())
    }
}

#[test]
fn trivial_chain_succeeds_leaf_intermediate_root() {
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let intermediate_der = leak(intermediate.der);
    let root_der = leak(root.der);

    let leaf = parse(leaf_der);
    let roots = CertificateStore::from_iter(vec![parse(root_der)]);
    let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    // The chain is exactly leaf, intermediate, root — leaf-to-root order,
    // as RFC 5280 §6.1 orders a certification path from the subject
    // outward to the trust anchor.
    assert_chain_is(result, &[&leaf, &parse(intermediate_der), &parse(root_der)]);
}

/// The API a library consumer is expected to use: name a backend once in
/// `Cargo.toml`, then construct a `Validator` with roots and a
/// policy only. Asserts that the feature-selected default provider really
/// verifies signatures, rather than being a stub that fails every check.
///
/// Gated to a single enabled backend: `with_policy` determines a backend only
/// then. The workspace build enables all three at once for the comparison
/// benchmarks, where no default exists and using one panics by design —
/// `tests/default_backend.rs` covers that case.
#[cfg(any(
    all(
        feature = "aws_lc",
        not(feature = "ring"),
        not(feature = "rust_crypto")
    ),
    all(
        feature = "ring",
        not(feature = "aws_lc"),
        not(feature = "rust_crypto")
    ),
    all(
        feature = "rust_crypto",
        not(feature = "aws_lc"),
        not(feature = "ring")
    ),
))]
#[test]
fn with_policy_uses_the_feature_selected_backend() {
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let intermediate_der = leak(intermediate.der);
    let root_der = leak(root.der);

    let leaf = parse(leaf_der);
    let roots = CertificateStore::from_iter(vec![parse(root_der)]);
    let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
    let validator = Validator::with_policy(roots, AlwaysMeetsPolicy);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert_chain_is(result, &[&leaf, &parse(intermediate_der), &parse(root_der)]);
}

/// `with_policy` and `with_policy_and_backend` given the same backend must
/// agree, so that the convenience constructor cannot quietly select something
/// other than the backend the crate was built with. Gated as above.
#[cfg(any(
    all(
        feature = "aws_lc",
        not(feature = "ring"),
        not(feature = "rust_crypto")
    ),
    all(
        feature = "ring",
        not(feature = "aws_lc"),
        not(feature = "rust_crypto")
    ),
    all(
        feature = "rust_crypto",
        not(feature = "aws_lc"),
        not(feature = "ring")
    ),
))]
#[test]
fn with_policy_matches_explicit_default_provider() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &root));
    let root_der = leak(root.der);
    let leaf = parse(leaf_der);
    let intermediates: CertificateStore<'_> = CertificateStore::new();

    let implicit = Validator::with_policy(
        CertificateStore::from_iter(vec![parse(root_der)]),
        AlwaysMeetsPolicy,
    );
    let explicit = Validator::with_policy_and_backend(
        CertificateStore::from_iter(vec![parse(root_der)]),
        AlwaysMeetsPolicy,
        &DEFAULT_PROVIDER,
    );

    let expected: &[&Certificate<'_>] = &[&leaf, &parse(root_der)];
    assert_chain_is(
        implicit.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {}),
        expected,
    );
    assert_chain_is(
        explicit.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {}),
        expected,
    );
}

#[test]
fn missing_issuer_fails() {
    let orphan = self_signed_ca_with("orphan", |_| {});
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &orphan));
    // Deliberately don't put `orphan` in either store, so the leaf's
    // issuer can never be found.
    let leaf = parse(leaf_der);
    let roots: CertificateStore<'_> = CertificateStore::new();
    let intermediates: CertificateStore<'_> = CertificateStore::new();
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert!(result.is_err());
}

#[test]
fn leaf_directly_in_root_store_is_accepted_immediately() {
    let root = self_signed_ca_with("leaf-is-root", |_| {});
    let root_der = leak(root.der);
    let leaf = parse(root_der);
    let roots = CertificateStore::from_iter(vec![parse(root_der)]);
    let intermediates: CertificateStore<'_> = CertificateStore::new();
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    match result {
        Ok(chain) => {
            assert_eq!(chain.iter().count(), 1);
        }
        Err(reasons) => {
            panic!("expected immediate root acceptance, got failures: {reasons:?}")
        }
    }
}

#[test]
fn candidate_with_non_verifying_signature_is_skipped() {
    // The trust store holds a root that matches the intermediate's issuer
    // name but carries a different key pair, so its signature check over
    // the intermediate genuinely fails. RFC 5280 §6.1.3(a)(1) requires that
    // check to pass, so the candidate is skipped and — the real root being
    // absent — no path exists.
    let root = self_signed_ca_with("root", |_| {});
    let impostor_root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let intermediate_der = leak(intermediate.der);
    let impostor_der = leak(impostor_root.der);

    let leaf = parse(leaf_der);
    let impostor_cert = parse(impostor_der);

    // Guard against a vacuous test: the impostor must be reachable by the
    // intermediate's issuer-name lookup, and must carry a different key.
    assert_eq!(
        impostor_cert.subject_key(),
        parse(intermediate_der).issuer_key(),
        "the impostor root must be found by the intermediate's issuer name"
    );
    assert_ne!(
        impostor_cert.public_key().raw,
        parse(leak(root.der))
            .public_key()
            .raw,
        "the impostor root must carry a different key than the real root"
    );

    let roots = CertificateStore::from_iter(vec![impostor_cert]);
    let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert!(result.is_err());
}

#[test]
fn candidate_with_unhandled_critical_extension_is_skipped() {
    // A root carrying an unrecognized critical extension must be
    // skipped as a candidate issuer, so a leaf whose only path runs
    // through it fails to validate.
    let root = self_signed_ca_with(
        "root",
        |params: &mut x509_validator_testkit::rcgen::CertificateParams| {
            params.custom_extensions.push(
                x509_validator_testkit::rcgen::CustomExtension::from_oid_content(
                    &[1, 2, 3, 4, 5],
                    b"unrecognized".to_vec(),
                ),
            );
            let mut ext = params
                .custom_extensions
                .last()
                .unwrap()
                .clone();
            ext.set_criticality(true);
            *params
                .custom_extensions
                .last_mut()
                .unwrap() = ext;
        },
    );
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &root));
    let root_der = leak(root.der);

    let leaf = parse(leaf_der);
    let roots = CertificateStore::from_iter(vec![parse(root_der)]);
    let intermediates: CertificateStore<'_> = CertificateStore::new();
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert!(result.is_err());
}

#[test]
fn policy_failure_on_first_root_candidate_continues_search() {
    // Two roots share the same subject name "root" and one key pair, so
    // both pass the signature check over the leaf and neither is pruned by
    // crypto. Only the second one (by insertion order, since no AKI/SKI is
    // set to reorder them) satisfies the policy. Confirms policy failures
    // accumulate and the search keeps trying further candidates rather than
    // stopping at the first failure.
    struct RequireRootPolicy {
        right_root_der: Vec<u8>,
    }
    impl ValidationPolicy for RequireRootPolicy {
        fn verifying_critical_extensions(&self) -> Vec<x509_validator::der_parser::Oid<'static>> {
            vec![OID_X509_EXT_BASIC_CONSTRAINTS]
        }
        fn chain_meets_policy_requirements(
            &self,
            chain: &UnverifiedCertificateChain<'_>,
        ) -> PolicyEvaluationResult {
            let root = &chain[chain.len() - 1];
            if root.as_ref() == self.right_root_der.as_slice() {
                Ok(())
            } else {
                Err(PolicyFailureReason::new("wrong root"))
            }
        }
    }

    let shared_key = KeyPair::generate().expect("generate key pair");
    let right_root = self_signed_ca_with_key_ids("root", Some(shared_key), Ski::Absent);
    let wrong_root =
        self_signed_ca_with_key_ids("root", Some(right_root.copy_of_key_pair()), Ski::Absent);
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &right_root));
    let wrong_root_der = leak(wrong_root.der);
    let right_root_der = leak(right_root.der);

    let leaf = parse(leaf_der);
    // Insertion order deliberately puts the policy-rejected root first.
    let roots = CertificateStore::from_iter(vec![parse(wrong_root_der), parse(right_root_der)]);
    let intermediates: CertificateStore<'_> = CertificateStore::new();
    let policy = RequireRootPolicy {
        right_root_der: right_root_der.to_vec(),
    };
    let validator = Validator::with_policy_and_backend(roots, policy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert_chain_is(result, &[&leaf, &parse(right_root_der)]);
}

#[test]
fn candidate_without_subject_key_identifier_is_preferred_over_one_whose_ski_mismatches() {
    // RFC 5280 §4.2.1.1 makes the authorityKeyIdentifier a hint for
    // selecting among issuers sharing a subject name, and RFC 4158 §3.5.3
    // ranks that hint three ways rather than two: a candidate whose
    // subjectKeyIdentifier equals the subject's AKI is the best match; a
    // candidate carrying *no* subjectKeyIdentifier is merely uninformative
    // (§4.2.1.2 leaves the extension optional for certificates that are
    // not CAs, and legacy CAs omit it too); a candidate that *does* carry
    // a subjectKeyIdentifier which differs from the AKI is positive
    // evidence of the wrong issuer, so it must sort last.
    //
    // Both roots below share the subject name "root" and share one key
    // pair, so either can validly sign the leaf and neither is skipped for
    // a bad signature. The mismatching-SKI root is inserted first, so only
    // a three-way ranking puts the no-SKI root ahead of it.
    // The recording buffer is shared rather than owned by the policy: the
    // validator takes the policy by value and does not hand it back, so the
    // test keeps its own handle on the record.
    struct RecordingPolicy {
        root_skis: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
    }
    impl ValidationPolicy for RecordingPolicy {
        fn verifying_critical_extensions(&self) -> Vec<x509_validator::der_parser::Oid<'static>> {
            vec![OID_X509_EXT_BASIC_CONSTRAINTS]
        }
        fn chain_meets_policy_requirements(
            &self,
            chain: &UnverifiedCertificateChain<'_>,
        ) -> PolicyEvaluationResult {
            let root = &chain[chain.len() - 1];
            self.root_skis.lock().unwrap().push(
                root.subject_key_identifier()
                    .map(<[u8]>::to_vec),
            );
            // Never satisfied, so every candidate is visited in order.
            Err(PolicyFailureReason::new("recording only"))
        }
    }

    let shared_key = KeyPair::generate().expect("generate key pair");
    // A key identifier no certificate here actually carries, used as the
    // leaf's AKI so that neither root can match it.
    let unmatched_key_id = vec![0xAA; 20];

    // The signing identity fixes the AKI that the issued leaf will carry.
    let signer = signing_identity("root", shared_key, Some(unmatched_key_id.clone()));
    let leaf_der = leak(issue_leaf_with_aki(
        "leaf",
        &["www.example.com"],
        &signer,
        true,
    ));

    let mismatching_ski_root = self_signed_ca_with_key_ids(
        "root",
        Some(signer.copy_of_key_pair()),
        Ski::Exactly(vec![0xBB; 20]),
    );
    let no_ski_root =
        self_signed_ca_with_key_ids("root", Some(signer.copy_of_key_pair()), Ski::Absent);

    let mismatching_der = leak(mismatching_ski_root.der);
    let no_ski_der = leak(no_ski_root.der);

    let leaf = parse(leaf_der);
    let mismatching_cert = parse(mismatching_der);
    let no_ski_cert = parse(no_ski_der);

    // Guard against a vacuous test: confirm the fixtures really carry the
    // key identifiers the ranking is supposed to react to.
    assert_eq!(
        leaf.authority_key_identifier(),
        Some(unmatched_key_id.as_slice()),
        "leaf must carry an authorityKeyIdentifier matching neither root"
    );
    assert_eq!(
        mismatching_cert.subject_key_identifier(),
        Some([0xBB; 20].as_slice()),
        "first root must carry a non-matching subjectKeyIdentifier"
    );
    assert_eq!(
        no_ski_cert.subject_key_identifier(),
        None,
        "second root must carry no subjectKeyIdentifier at all"
    );
    assert_eq!(
        mismatching_cert.subject_key(),
        no_ski_cert.subject_key(),
        "both roots must share a subject name so both are candidates"
    );

    // Insertion order deliberately puts the mismatching-SKI root first.
    let roots = CertificateStore::from_iter(vec![mismatching_cert, no_ski_cert]);
    let intermediates: CertificateStore<'_> = CertificateStore::new();
    let root_skis = Arc::new(Mutex::new(Vec::new()));
    let policy = RecordingPolicy {
        root_skis: Arc::clone(&root_skis),
    };
    let validator = Validator::with_policy_and_backend(roots, policy, &DEFAULT_PROVIDER);

    let _ = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});

    let visited = root_skis.lock().unwrap().clone();
    assert_eq!(
        visited.len(),
        2,
        "both roots should have been offered to the policy"
    );
    assert_eq!(
        visited[0], None,
        "the root with no subjectKeyIdentifier must be tried first"
    );
    assert_eq!(
        visited[1],
        Some(vec![0xBB; 20]),
        "the root with a mismatching subjectKeyIdentifier must be tried last"
    );
}

#[test]
fn missing_intermediate_fails_to_build() {
    // The root is trusted, but the certificate linking the leaf to it is
    // supplied nowhere, so no certification path exists.
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let root_der = leak(root.der);

    let leaf = parse(leaf_der);
    let roots = CertificateStore::from_iter(vec![parse(root_der)]);
    let intermediates: CertificateStore<'_> = CertificateStore::new();
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    match result {
        Err(reasons) => {
            // Nothing was ever offered to the policy, so there is no
            // policy failure to report — only the absence of a path.
            assert!(
                reasons.is_empty(),
                "expected no policy failures, got: {reasons:?}"
            );
        }
        Ok(_) => panic!("built a chain with no intermediate available"),
    }
}

#[test]
fn missing_root_fails_to_build() {
    // The intermediate is available, so the search can climb one link,
    // but the trust anchor it terminates at is not trusted.
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let intermediate_der = leak(intermediate.der);

    let leaf = parse(leaf_der);
    let roots: CertificateStore<'_> = CertificateStore::new();
    let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    match result {
        Err(reasons) => {
            assert!(
                reasons.is_empty(),
                "expected no policy failures, got: {reasons:?}"
            );
        }
        Ok(_) => panic!("built a chain terminating at an untrusted root"),
    }
}

#[test]
fn extra_roots_are_ignored() {
    // An unrelated trust anchor sharing no subject name with anything in
    // the path must neither be selected nor disturb the search.
    let root = self_signed_ca_with("root", |_| {});
    let unrelated_root = self_signed_ca_with("unrelated-root", |_| {});
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let intermediate_der = leak(intermediate.der);
    let root_der = leak(root.der);
    let unrelated_root_der = leak(unrelated_root.der);

    let leaf = parse(leaf_der);
    let roots = CertificateStore::from_iter(vec![parse(root_der), parse(unrelated_root_der)]);
    let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert_chain_is(result, &[&leaf, &parse(intermediate_der), &parse(root_der)]);
}

#[test]
fn roots_also_present_in_the_intermediate_store_are_not_a_problem() {
    // Callers routinely hand the same bundle to both stores. The roots
    // appearing a second time as intermediate candidates must not produce
    // a duplicated or longer path.
    let root = self_signed_ca_with("root", |_| {});
    let unrelated_root = self_signed_ca_with("unrelated-root", |_| {});
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let intermediate_der = leak(intermediate.der);
    let root_der = leak(root.der);
    let unrelated_root_der = leak(unrelated_root.der);

    let leaf = parse(leaf_der);
    let roots = CertificateStore::from_iter(vec![parse(root_der), parse(unrelated_root_der)]);
    let intermediates = CertificateStore::from_iter(vec![
        parse(intermediate_der),
        parse(root_der),
        parse(unrelated_root_der),
    ]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert_chain_is(result, &[&leaf, &parse(intermediate_der), &parse(root_der)]);
}

#[test]
fn self_signed_certificate_is_rejected_when_not_in_the_trust_store() {
    // A self-signed certificate is its own issuer, but being its own
    // issuer confers no trust: RFC 5280 §6.1 requires the path to
    // terminate at a configured trust anchor.
    let trusted_root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &trusted_root, None, |_| {});
    let isolated = self_signed_ca_with("isolated-self-signed", |_| {});

    let isolated_der = leak(isolated.der);
    let intermediate_der = leak(intermediate.der);
    let trusted_root_der = leak(trusted_root.der);

    let leaf = parse(isolated_der);
    let roots = CertificateStore::from_iter(vec![parse(trusted_root_der)]);
    let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert!(
        result.is_err(),
        "a self-signed certificate outside the trust store must not validate"
    );
}

#[test]
fn self_signed_certificate_is_trusted_when_in_the_trust_store() {
    // The same certificate as above, now configured as a trust anchor:
    // the path is the anchor alone, length one.
    let trusted_root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &trusted_root, None, |_| {});
    let isolated = self_signed_ca_with("isolated-self-signed", |_| {});

    let isolated_der = leak(isolated.der);
    let intermediate_der = leak(intermediate.der);
    let trusted_root_der = leak(trusted_root.der);

    let leaf = parse(isolated_der);
    let roots = CertificateStore::from_iter(vec![parse(trusted_root_der), parse(isolated_der)]);
    let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert_chain_is(result, &[&leaf]);
}

#[test]
fn trust_roots_can_be_non_self_signed_leaves() {
    // Nothing requires a trust anchor to be a CA or to be self-signed.
    // A non-CA leaf placed directly in the trust store validates as a
    // path of length one, without any search.
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let intermediate_der = leak(intermediate.der);

    let leaf = parse(leaf_der);
    let roots = CertificateStore::from_iter(vec![parse(leaf_der)]);
    let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert_chain_is(result, &[&leaf]);
}

#[test]
fn trust_roots_can_be_non_self_signed_intermediates() {
    // Trusting an intermediate directly terminates the path there: the
    // chain stops at the anchor and never reaches the certificate that
    // issued it.
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let intermediate_der = leak(intermediate.der);

    let leaf = parse(leaf_der);
    let roots = CertificateStore::from_iter(vec![parse(intermediate_der)]);
    let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert_chain_is(result, &[&leaf, &parse(intermediate_der)]);
}

#[test]
fn critical_extensions_are_policed_on_leaf_certificates() {
    // RFC 5280 §4.2: a certificate consumer must reject a certificate
    // carrying a critical extension it does not recognize. The policy
    // here declares only basicConstraints, so the leaf's extra critical
    // extension is unhandled and the leaf is rejected outright — even
    // though it is itself in the trust store and would otherwise be
    // accepted as a path of length one.
    let trusted_root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &trusted_root, None, |_| {});
    let weird = self_signed_ca_with(
        "weird-critical-extension",
        |params: &mut x509_validator_testkit::rcgen::CertificateParams| {
            params
                .custom_extensions
                .push(weird_critical_extension());
        },
    );

    let weird_der = leak(weird.der);
    let intermediate_der = leak(intermediate.der);
    let trusted_root_der = leak(trusted_root.der);

    let leaf = parse(weird_der);
    // Guard against a vacuous test: the leaf really must carry a critical
    // extension the policy does not list.
    let handled = AlwaysMeetsPolicy.verifying_critical_extensions();
    assert!(
        leaf.tbs_certificate
            .iter_extensions()
            .any(|ext| ext.critical && !handled.contains(&ext.oid)),
        "leaf must carry a critical extension outside the policy's handled set"
    );

    let roots = CertificateStore::from_iter(vec![parse(trusted_root_der), parse(weird_der)]);
    let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert!(
        result.is_err(),
        "a leaf with an unhandled critical extension must not validate"
    );
}

#[test]
fn roots_with_a_matching_subject_key_identifier_are_preferred() {
    // Two trust anchors share one subject name and one key pair, so
    // either terminates a valid path and neither can be eliminated by a
    // signature check. They differ only in that one carries a
    // subjectKeyIdentifier equal to the intermediate's
    // authorityKeyIdentifier and the other carries none at all.
    //
    // RFC 5280 §4.2.1.1 offers the AKI precisely as the means of
    // selecting among issuers that share a name, and RFC 4158 §3.5.3
    // ranks a matching key identifier above an absent one. The no-SKI
    // anchor is inserted first, so only that ranking — rather than store
    // insertion order — can put the matching anchor in the built chain.
    let root_key = KeyPair::generate().expect("generate key pair");
    let matching_root = self_signed_ca_with_key_ids("root", Some(root_key), Ski::Derived);
    let no_ski_root =
        self_signed_ca_with_key_ids("root", Some(matching_root.copy_of_key_pair()), Ski::Absent);

    let intermediate =
        issue_ca_with_key_ids("intermediate", &matching_root, None, Ski::Derived, true);
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let intermediate_der = leak(intermediate.der);
    let matching_der = leak(matching_root.der);
    let no_ski_der = leak(no_ski_root.der);

    let leaf = parse(leaf_der);
    let matching_cert = parse(matching_der);
    let no_ski_cert = parse(no_ski_der);
    let intermediate_cert = parse(intermediate_der);

    // Guard against a vacuous test: the ranking signal must really exist.
    assert_eq!(
        intermediate_cert.authority_key_identifier(),
        matching_cert.subject_key_identifier(),
        "the intermediate's AKI must equal the matching root's SKI"
    );
    assert_eq!(
        no_ski_cert.subject_key_identifier(),
        None,
        "the other root must carry no SKI"
    );
    assert_eq!(
        matching_cert.subject_key(),
        no_ski_cert.subject_key(),
        "both roots must share a subject name so both are candidates"
    );

    // Insertion order deliberately puts the unranked root first.
    let roots = CertificateStore::from_iter(vec![no_ski_cert, matching_cert]);
    let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert_chain_is(
        result,
        &[&leaf, &parse(intermediate_der), &parse(matching_der)],
    );
}

#[test]
fn intermediates_whose_subject_key_identifier_matches_the_subject_aki_are_preferred() {
    // A single subject name, "intermediate", is served by two
    // certificates in the intermediate store: one carrying a
    // subjectKeyIdentifier equal to the leaf's authorityKeyIdentifier,
    // one carrying none. Both share a key pair and both are validly
    // issued by the same root, so both complete a chain and the search
    // cannot discriminate on signatures — only the RFC 4158 §3.5.3
    // ranking of the RFC 5280 §4.2.1.1 key-identifier hint decides.
    //
    // Two candidates under one subject name is also what makes the
    // ranking observable at all: candidates are pushed onto a LIFO
    // search stack, so the best-ranked candidate must be pushed last to
    // be popped first. With a single candidate per name the push order
    // is unobservable.
    let root = self_signed_ca_with("root", |_| {});

    let intermediate_key = KeyPair::generate().expect("generate key pair");
    let matching_intermediate = issue_ca_with_key(
        "intermediate",
        &root,
        intermediate_key,
        Ski::Derived,
        true,
        |_| {},
    );
    let no_ski_intermediate = issue_ca_with_key(
        "intermediate",
        &root,
        matching_intermediate.copy_of_key_pair(),
        Ski::Absent,
        true,
        |_| {},
    );

    let leaf_der = leak(issue_leaf_with_aki(
        "leaf",
        &["www.example.com"],
        &matching_intermediate,
        true,
    ));
    let matching_der = leak(matching_intermediate.der);
    let no_ski_der = leak(no_ski_intermediate.der);
    let root_der = leak(root.der);

    let leaf = parse(leaf_der);
    let matching_cert = parse(matching_der);
    let no_ski_cert = parse(no_ski_der);

    // Guard against a vacuous test.
    assert_eq!(
        leaf.authority_key_identifier(),
        matching_cert.subject_key_identifier(),
        "the leaf's AKI must equal the preferred intermediate's SKI"
    );
    assert_eq!(
        no_ski_cert.subject_key_identifier(),
        None,
        "the other intermediate must carry no SKI"
    );
    assert_eq!(
        matching_cert.subject_key(),
        no_ski_cert.subject_key(),
        "both intermediates must share a subject name so both are candidates"
    );

    let roots = CertificateStore::from_iter(vec![parse(root_der)]);
    // Insertion order deliberately puts the unranked intermediate first.
    let intermediates = CertificateStore::from_iter(vec![no_ski_cert, matching_cert]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert_chain_is(result, &[&leaf, &parse(matching_der), &parse(root_der)]);
}

#[test]
fn cross_signed_root_is_supported() {
    // Only ca2 is trusted. The path to it runs leaf -> intermediate ->
    // ca1-as-cross-signed-by-ca2 -> ca2: the intermediate names ca1 as
    // its issuer, and the certificate satisfying that name in the
    // intermediate store is the cross-signed one, whose own issuer name
    // is ca2. RFC 4158 §2.4.2 describes exactly this shape.
    let ca1 = self_signed_ca_with("ca1", |_| {});
    let ca2 = self_signed_ca_with("ca2", |_| {});
    let ca1_cross_signed = ca1.cross_signed_by(&ca2);
    let intermediate = issue_ca("intermediate", &ca1, None, |_| {});

    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let intermediate_der = leak(intermediate.der);
    let cross_signed_der = leak(ca1_cross_signed.der);
    let ca2_der = leak(ca2.der);

    let leaf = parse(leaf_der);
    let roots = CertificateStore::from_iter(vec![parse(ca2_der)]);
    let intermediates =
        CertificateStore::from_iter(vec![parse(intermediate_der), parse(cross_signed_der)]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert_chain_is(
        result,
        &[
            &leaf,
            &parse(intermediate_der),
            &parse(cross_signed_der),
            &parse(ca2_der),
        ],
    );
}

#[test]
fn shorter_path_is_built_when_cross_signed_roots_offer_both() {
    // Both ca1 and ca2 are trusted, and both cross-signed certificates
    // are available as intermediates, so two paths terminate at a trust
    // anchor: the three-certificate one through ca1 directly, and the
    // four-certificate one through ca1-cross-signed-by-ca2.
    //
    // RFC 4158 §3.2 prefers the shorter path, and the search reaches it
    // first because trust anchors are considered ahead of intermediates
    // at each step. The extra cross-signed certificates must not divert
    // it.
    let ca1 = self_signed_ca_with("ca1", |_| {});
    let ca2 = self_signed_ca_with("ca2", |_| {});
    let ca1_cross_signed = ca1.cross_signed_by(&ca2);
    let ca2_cross_signed = ca2.cross_signed_by(&ca1);
    let intermediate = issue_ca("intermediate", &ca1, None, |_| {});

    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let intermediate_der = leak(intermediate.der);
    let ca1_cross_der = leak(ca1_cross_signed.der);
    let ca2_cross_der = leak(ca2_cross_signed.der);
    let ca1_der = leak(ca1.der);
    let ca2_der = leak(ca2.der);

    let leaf = parse(leaf_der);
    let roots = CertificateStore::from_iter(vec![parse(ca1_der), parse(ca2_der)]);
    let intermediates = CertificateStore::from_iter(vec![
        parse(intermediate_der),
        parse(ca2_cross_der),
        parse(ca1_cross_der),
    ]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert_chain_is(result, &[&leaf, &parse(intermediate_der), &parse(ca1_der)]);
}

#[test]
fn roots_that_did_not_sign_the_certificate_below_them_are_rejected() {
    // The trust store holds a certificate for ca1's subject name that
    // carries a *different* key than the one that actually signed the
    // intermediate. RFC 5280 §6.1.3(a)(1) requires the signature on each
    // certificate to verify under the public key of the certificate
    // above it, so that anchor must be rejected despite matching by
    // name, and the search must fall through to the longer path that
    // terminates at ca2.
    let ca1 = self_signed_ca_with("ca1", |_| {});
    let ca2 = self_signed_ca_with("ca2", |_| {});
    let ca1_cross_signed = ca1.cross_signed_by(&ca2);
    let ca2_cross_signed = ca2.cross_signed_by(&ca1);
    let intermediate = issue_ca("intermediate", &ca1, None, |_| {});

    // A second certificate for ca1's name and a different key pair,
    // issued by ca1 itself. It never signed the intermediate.
    let ca1_with_other_key = issue_ca_with_key_and_name(
        "ca1",
        &ca1,
        KeyPair::generate().expect("generate key pair"),
        None,
        Ski::Derived,
        false,
        |_| {},
    );

    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let intermediate_der = leak(intermediate.der);
    let ca1_cross_der = leak(ca1_cross_signed.der);
    let ca2_cross_der = leak(ca2_cross_signed.der);
    let ca1_other_der = leak(ca1_with_other_key.der);
    let ca2_der = leak(ca2.der);

    let leaf = parse(leaf_der);
    let ca1_other_cert = parse(ca1_other_der);

    // Guard against a vacuous test: the impostor anchor must match the
    // intermediate's issuer name, and must carry a different key from
    // the one that signed the intermediate.
    assert_eq!(
        ca1_other_cert.subject_key(),
        parse(intermediate_der).issuer_key(),
        "the impostor anchor must be found by the intermediate's issuer name"
    );
    assert_ne!(
        ca1_other_cert.public_key().raw,
        parse(ca1_cross_der).public_key().raw,
        "the impostor anchor must carry a different key than the real ca1"
    );

    // ca1 itself is deliberately absent from the trust store; only the
    // impostor bearing its name and ca2 are trusted.
    let roots = CertificateStore::from_iter(vec![ca1_other_cert, parse(ca2_der)]);
    let intermediates = CertificateStore::from_iter(vec![
        parse(ca1_cross_der),
        parse(ca2_cross_der),
        parse(intermediate_der),
    ]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert_chain_is(
        result,
        &[
            &leaf,
            &parse(intermediate_der),
            &parse(ca1_cross_der),
            &parse(ca2_der),
        ],
    );
}

#[test]
fn policy_failures_let_the_search_find_a_longer_path() {
    // The same PKI as the shorter-path test, but with a policy that
    // rejects any chain containing ca1. The short path is found first
    // and fails the policy; the search must not stop there but continue
    // through the cross-signed certificate to the longer path
    // terminating at ca2, which the policy accepts.
    struct ForbidCertificatePolicy {
        forbidden_der: Vec<u8>,
    }
    impl ValidationPolicy for ForbidCertificatePolicy {
        fn verifying_critical_extensions(&self) -> Vec<x509_validator::der_parser::Oid<'static>> {
            vec![OID_X509_EXT_BASIC_CONSTRAINTS]
        }
        fn chain_meets_policy_requirements(
            &self,
            chain: &UnverifiedCertificateChain<'_>,
        ) -> PolicyEvaluationResult {
            for index in 0..chain.len() {
                if chain[index].as_ref() == self.forbidden_der.as_slice() {
                    return Err(PolicyFailureReason::new(
                        "chain must not contain forbidden certificate",
                    ));
                }
            }
            Ok(())
        }
    }

    let ca1 = self_signed_ca_with("ca1", |_| {});
    let ca2 = self_signed_ca_with("ca2", |_| {});
    let ca1_cross_signed = ca1.cross_signed_by(&ca2);
    let ca2_cross_signed = ca2.cross_signed_by(&ca1);
    let intermediate = issue_ca("intermediate", &ca1, None, |_| {});

    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
    let intermediate_der = leak(intermediate.der);
    let ca1_cross_der = leak(ca1_cross_signed.der);
    let ca2_cross_der = leak(ca2_cross_signed.der);
    let ca1_der = leak(ca1.der);
    let ca2_der = leak(ca2.der);

    let leaf = parse(leaf_der);
    let roots = CertificateStore::from_iter(vec![parse(ca1_der), parse(ca2_der)]);
    let intermediates = CertificateStore::from_iter(vec![
        parse(intermediate_der),
        parse(ca2_cross_der),
        parse(ca1_cross_der),
    ]);
    let policy = ForbidCertificatePolicy {
        forbidden_der: ca1_der.to_vec(),
    };
    let validator = Validator::with_policy_and_backend(roots, policy, &DEFAULT_PROVIDER);

    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
    assert_chain_is(
        result,
        &[
            &leaf,
            &parse(intermediate_der),
            &parse(ca1_cross_der),
            &parse(ca2_der),
        ],
    );
}

#[test]
fn pathological_pki_with_mutually_cross_signed_intermediates_can_still_build() {
    // A deliberately hostile PKI. Two intermediate subject names, "T"
    // and "X", each served by several certificates, cross-sign each
    // other: certificates named T are issued by X and vice versa. RFC
    // 5280 §4.1.2.4 links a certificate to its issuer by name alone, so
    // by name this graph contains a cycle, and a depth-first search that
    // did not recognise a repeated certificate would revisit T and X
    // forever.
    //
    // The only thing that terminates the search is the loop detection
    // that refuses to add a certificate already present in the partial
    // chain. To force the detection to actually fire — rather than a
    // signature check quietly pruning the cycle — the T certificates are
    // arranged to be distinguishable from one another in each of the
    // ways the identity comparison considers, so the search must
    // genuinely re-offer already-visited certificates and reject them:
    //
    //   t1, t2: same subject name "T", same key pair, but t1 carries a
    //           subjectAltName that t2 does not.
    //   t3:     same subject name "T", a different key pair.
    //   x1, x2: same subject name "X", same key pair, distinguished by
    //           x2's subjectAltName.
    //
    // The leaf's AKI matches t3's SKI, and both X certificates carry the
    // same AKI, which fixes the order in which candidates are tried and
    // drives the search into the cycle rather than around it.
    let root = self_signed_ca_with("root", |_| {});

    let t1_t2_key = KeyPair::generate().expect("generate key pair");
    let t3_key = KeyPair::generate().expect("generate key pair");
    let x_key = KeyPair::generate().expect("generate key pair");

    // t3's key identifier, used as the AKI of the leaf and of both X
    // certificates. It is computed before t3 exists, from t3's key.
    let t3_key_id = {
        let probe = self_signed_ca_with_key_ids(
            "probe",
            Some(KeyPair::from_pem(&t3_key.serialize_pem()).unwrap()),
            Ski::Derived,
        );
        probe.key_identifier()
    };

    // Signing identities for the two intermediate names, so certificates
    // can be issued "as" T and "as" X before any certificate for either
    // name exists — the only way to close the cycle.
    let sign_as_t_with_t1_t2_key = signing_identity(
        "T",
        KeyPair::from_pem(&t1_t2_key.serialize_pem()).unwrap(),
        Some(t3_key_id.clone()),
    );
    let sign_as_t_with_t3_key = signing_identity(
        "T",
        KeyPair::from_pem(&t3_key.serialize_pem()).unwrap(),
        Some(t3_key_id),
    );
    let sign_as_x = signing_identity(
        "X",
        KeyPair::from_pem(&x_key.serialize_pem()).unwrap(),
        None,
    );

    // t1 is issued by the root and carries the SKI of the *wrong* key,
    // which RFC 5280 §4.2.1.2 does not forbid and chain building must
    // tolerate. It is the only T that leads out of the cycle.
    let t1 = issue_ca_with_key_and_name(
        "T",
        &root,
        KeyPair::from_pem(&t1_t2_key.serialize_pem()).unwrap(),
        None,
        Ski::Exactly(vec![0xC1; 20]),
        true,
        |params| {
            params.subject_alt_names = vec![x509_validator_testkit::rcgen::SanType::DnsName(
                x509_validator_testkit::rcgen::string::Ia5String::try_from("example.com").unwrap(),
            )];
        },
    );
    // t2 shares t1's key and name but has no SAN and no SKI.
    let t2 = issue_ca_with_key_and_name(
        "T",
        &sign_as_x,
        KeyPair::from_pem(&t1_t2_key.serialize_pem()).unwrap(),
        None,
        Ski::Absent,
        false,
        |_| {},
    );
    // t3 uses a different key and carries the SKI the leaf points at.
    let t3 = issue_ca_with_key_and_name(
        "T",
        &sign_as_x,
        KeyPair::from_pem(&t3_key.serialize_pem()).unwrap(),
        Some(1),
        Ski::Derived,
        false,
        |_| {},
    );
    // x1 and x2 are both issued "as T" with the t1/t2 key, share the X
    // key, and differ only by x2's subjectAltName.
    let x1 = issue_ca_with_key_and_name(
        "X",
        &sign_as_t_with_t1_t2_key,
        KeyPair::from_pem(&x_key.serialize_pem()).unwrap(),
        None,
        Ski::Absent,
        true,
        |_| {},
    );
    let x2 = issue_ca_with_key_and_name(
        "X",
        &sign_as_t_with_t1_t2_key,
        KeyPair::from_pem(&x_key.serialize_pem()).unwrap(),
        None,
        Ski::Absent,
        true,
        |params| {
            params.subject_alt_names = vec![x509_validator_testkit::rcgen::SanType::DnsName(
                x509_validator_testkit::rcgen::string::Ia5String::try_from("foo.example.com")
                    .unwrap(),
            )];
        },
    );
    let insane_leaf_der = issue_leaf_with("insane-leaf", &[], &sign_as_t_with_t3_key, |params| {
        params.use_authority_key_identifier_extension = true;
    });

    let root_der = leak(root.der);
    let t1_der = leak(t1.der);
    let t2_der = leak(t2.der);
    let t3_der = leak(t3.der);
    let x1_der = leak(x1.der);
    let x2_der = leak(x2.der);
    let leaf_der = leak(insane_leaf_der);

    let leaf = parse(leaf_der);

    // Guard against a vacuous test: the graph must really contain a
    // cycle by issuer name, otherwise loop detection is never exercised.
    assert_eq!(
        parse(t2_der).issuer_key(),
        parse(x1_der).subject_key(),
        "T certificates must name X as their issuer"
    );
    assert_eq!(
        parse(x1_der).issuer_key(),
        parse(t2_der).subject_key(),
        "X certificates must name T as their issuer, closing the cycle"
    );
    assert_eq!(
        leaf.authority_key_identifier(),
        parse(t3_der).subject_key_identifier(),
        "the leaf's AKI must select t3 first"
    );

    let roots = CertificateStore::from_iter(vec![parse(root_der)]);
    let intermediates = CertificateStore::from_iter(vec![
        parse(t1_der),
        parse(t2_der),
        parse(t3_der),
        parse(x2_der),
        parse(x1_der),
    ]);
    let validator = Validator::with_policy_and_backend(roots, AlwaysMeetsPolicy, &DEFAULT_PROVIDER);

    // Bound the search explicitly. Without loop detection this PKI has
    // no finite traversal at all, so an unbounded run would hang rather
    // than fail. Counting diagnostic events and panicking past a
    // generous ceiling turns "the search never terminates" into an
    // ordinary, quickly-reported test failure. A correct search emits
    // well under this many events; the ceiling only has to be finite.
    const MAX_SEARCH_EVENTS: usize = 500;
    let mut events = 0usize;
    let result = validator.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {
        events += 1;
        assert!(
            events <= MAX_SEARCH_EVENTS,
            "chain building did not terminate: exceeded {MAX_SEARCH_EVENTS} search events, \
             so a certificate already in the partial chain is being revisited"
        );
    });

    assert_chain_is(
        result,
        &[
            &leaf,
            &parse(t3_der),
            &parse(x2_der),
            &parse(t2_der),
            &parse(x1_der),
            &parse(t1_der),
            &parse(root_der),
        ],
    );
}

#[test]
fn verification_diagnostic_description_does_not_include_new_lines() {
    // Every diagnostic's single-line `Display` form must stay on one
    // line, so that a caller logging diagnostics one-per-line cannot have
    // its output structure broken by certificate content. The multi-line
    // form is available separately for callers that want it.
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));

    let leaf = cert(leaf_der.to_vec());
    let intermediate_cert = cert(intermediate.der);
    let root_cert = cert(root.der);

    let handled = vec![
        OID_X509_EXT_BASIC_CONSTRAINTS,
        OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
    ];

    let diagnostics: Vec<VerificationDiagnostic<'_>> = vec![
        VerificationDiagnostic::leaf_certificate_has_unhandled_critical_extension(
            leaf.clone(),
            handled.clone(),
        ),
        VerificationDiagnostic::leaf_certificate_is_in_the_root_store_but_does_not_meet_policy(
            leaf.clone(),
            PolicyFailureReason::new("policy failure reason"),
        ),
        VerificationDiagnostic::chain_fails_to_meet_policy(
            vec![leaf.clone(), root_cert.clone()],
            PolicyFailureReason::new("policy failure reason"),
        ),
        VerificationDiagnostic::issuer_has_not_signed_certificate(
            intermediate_cert.clone(),
            vec![leaf.clone()],
        ),
        VerificationDiagnostic::issuer_has_unhandled_critical_extension(
            intermediate_cert.clone(),
            vec![leaf.clone()],
            handled.clone(),
        ),
        VerificationDiagnostic::searching_for_issuer_of_partial_chain(vec![
            leaf.clone(),
            intermediate_cert.clone(),
        ]),
        VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_root_store(
            vec![leaf.clone(), intermediate_cert.clone()],
            vec![root_cert.clone()],
        ),
        VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_intermediate_store(
            vec![leaf.clone()],
            vec![intermediate_cert.clone()],
        ),
        VerificationDiagnostic::found_valid_certificate_chain(vec![
            leaf.clone(),
            intermediate_cert.clone(),
            root_cert.clone(),
        ]),
        VerificationDiagnostic::could_not_validate_leaf_certificate(leaf.clone()),
        VerificationDiagnostic::issuer_is_already_in_the_chain(
            vec![leaf.clone(), intermediate_cert.clone()],
            intermediate_cert.clone(),
        ),
    ];

    for diagnostic in &diagnostics {
        let description = diagnostic.to_string();
        assert!(
            !description.contains('\n'),
            "diagnostic description contains a new line: {description}"
        );
    }
}
