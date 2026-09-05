//! Verification progress and failure events emitted while a chain is being
//! built.
//!
//! These tests only ever construct and inspect the public
//! [`VerificationDiagnostic`] type through its constructor functions and its
//! two rendering forms ([`Display`](std::fmt::Display) and
//! [`VerificationDiagnostic::multiline_description`]).

use x509_validator::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS;
use x509_validator::{Certificate, PolicyFailureReason, VerificationDiagnostic};
use x509_validator_testkit::{cert, issue_ca, issue_leaf, self_signed_ca_with};

/// The DER of a root, an intermediate issued by it, and a leaf issued by the
/// intermediate — enough material to populate every variant.
///
/// A `Certificate` borrows the bytes it was parsed from, so the DER is
/// returned for the caller to own; [`sample_chain`] parses it.
struct SampleDers {
    leaf: Vec<u8>,
    intermediate: Vec<u8>,
    root: Vec<u8>,
}

fn sample_ders() -> SampleDers {
    let root = self_signed_ca_with("Diagnostic Root", |_| {});
    let intermediate = issue_ca("Diagnostic Intermediate", &root, None, |_| {});
    let leaf = issue_leaf("diagnostic-leaf", &["www.example.com"], &intermediate);
    SampleDers {
        leaf,
        intermediate: intermediate.der,
        root: root.der,
    }
}

/// The sample chain, borrowing DER the caller owns.
fn sample_chain(ders: &SampleDers) -> (Certificate<'_>, Certificate<'_>, Certificate<'_>) {
    (cert(&ders.leaf), cert(&ders.intermediate), cert(&ders.root))
}

/// A self-signed CA carrying an unrecognized critical extension with OID
/// 1.2.3.4.5, alongside the critical basicConstraints rcgen always adds.
fn unknown_critical_extension_der() -> Vec<u8> {
    let ca = self_signed_ca_with(
        "Unknown Critical Ext",
        |params: &mut x509_validator_testkit::rcgen::CertificateParams| {
            let mut ext = x509_validator_testkit::rcgen::CustomExtension::from_oid_content(
                &[1, 2, 3, 4, 5],
                b"unrecognized".to_vec(),
            );
            ext.set_criticality(true);
            params.custom_extensions.push(ext);
        },
    );
    ca.der
}

/// Every variant, constructed over the same sample material. The
/// invariant tests below iterate this table so a newly added variant is
/// covered by construction.
fn all_variants<'a>(sample: &'a SampleDers, odd_der: &'a [u8]) -> Vec<VerificationDiagnostic<'a>> {
    let (leaf, intermediate, root) = sample_chain(sample);
    let handled = vec![OID_X509_EXT_BASIC_CONSTRAINTS];
    let odd = cert(odd_der);

    vec![
        VerificationDiagnostic::leaf_certificate_has_unhandled_critical_extension(
            odd.clone(),
            handled.clone(),
        ),
        VerificationDiagnostic::leaf_certificate_is_in_the_root_store_but_does_not_meet_policy(
            leaf.clone(),
            PolicyFailureReason::new("leaf is not a valid trust anchor by itself"),
        ),
        VerificationDiagnostic::chain_fails_to_meet_policy(
            vec![leaf.clone(), intermediate.clone(), root.clone()],
            PolicyFailureReason::new("chain does not meet policy"),
        ),
        VerificationDiagnostic::issuer_has_unhandled_critical_extension(
            odd,
            vec![leaf.clone()],
            handled,
        ),
        VerificationDiagnostic::issuer_has_not_signed_certificate(root.clone(), vec![leaf.clone()]),
        VerificationDiagnostic::searching_for_issuer_of_partial_chain(vec![
            leaf.clone(),
            intermediate.clone(),
        ]),
        VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_root_store(
            vec![leaf.clone(), intermediate.clone()],
            vec![root.clone()],
        ),
        VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_intermediate_store(
            vec![leaf.clone()],
            vec![intermediate.clone()],
        ),
        VerificationDiagnostic::found_valid_certificate_chain(vec![
            leaf.clone(),
            intermediate.clone(),
            root.clone(),
        ]),
        VerificationDiagnostic::could_not_validate_leaf_certificate(leaf.clone()),
        VerificationDiagnostic::issuer_is_already_in_the_chain(vec![leaf, intermediate], root),
    ]
}

#[test]
fn table_covers_every_variant() {
    let sample = sample_ders();
    let odd_der = unknown_critical_extension_der();
    assert_eq!(all_variants(&sample, &odd_der).len(), 11);
}

#[test]
fn every_variant_renders_non_empty_single_and_multiline_forms() {
    let sample = sample_ders();
    let odd_der = unknown_critical_extension_der();
    for diagnostic in all_variants(&sample, &odd_der) {
        let single = diagnostic.to_string();
        let multi = diagnostic.multiline_description();
        assert!(!single.is_empty());
        assert!(!multi.is_empty());
        // Both forms must render certificates through the summary
        // formatter rather than dumping DER.
        assert!(!single.contains("X509Certificate"), "{single}");
        assert!(!multi.contains("X509Certificate"), "{multi}");
    }
}

#[test]
fn single_line_description_never_contains_a_newline() {
    let sample = sample_ders();
    let odd_der = unknown_critical_extension_der();
    for diagnostic in all_variants(&sample, &odd_der) {
        let rendered = format!("{diagnostic}");
        assert!(
            !rendered.contains('\n'),
            "single-line description contains a newline: {rendered}"
        );
    }
}

#[test]
fn debug_is_the_quoted_single_line_description() {
    let sample = sample_ders();
    let odd_der = unknown_critical_extension_der();
    for diagnostic in all_variants(&sample, &odd_der) {
        assert_eq!(
            format!("{diagnostic:?}"),
            format!("{:?}", diagnostic.to_string())
        );
    }
}

#[test]
fn multiline_description_contains_newlines_for_list_variants() {
    let sample = sample_ders();
    let odd_der = unknown_critical_extension_der();
    for diagnostic in all_variants(&sample, &odd_der) {
        let rendered = diagnostic.multiline_description();
        assert!(
            rendered.contains('\n'),
            "multiline description has no newline: {rendered}"
        );
    }
}

#[test]
fn chain_variants_put_each_certificate_on_its_own_line() {
    let sample = sample_ders();
    let (leaf, intermediate, root) = sample_chain(&sample);
    let diagnostic =
        VerificationDiagnostic::found_valid_certificate_chain(vec![leaf, intermediate, root]);

    let rendered = diagnostic.multiline_description();
    assert!(
        rendered.contains("Verified certificate chain (from leaf to root):\n"),
        "{rendered}"
    );
    assert_eq!(
        rendered
            .matches("Certificate(version:")
            .count(),
        3,
        "{rendered}"
    );
    // Three certificates, each on its own line.
    let certificate_lines = rendered
        .lines()
        .filter(|line| line.starts_with("Certificate(version:"))
        .count();
    assert_eq!(certificate_lines, 3, "{rendered}");
}

#[test]
fn single_line_chain_variant_separates_certificates_with_commas() {
    let sample = sample_ders();
    let (leaf, intermediate, root) = sample_chain(&sample);
    let diagnostic = VerificationDiagnostic::chain_fails_to_meet_policy(
        vec![leaf, intermediate, root],
        PolicyFailureReason::new("expired"),
    );

    let rendered = diagnostic.to_string();
    assert!(rendered.contains("Reason: expired"), "{rendered}");
    assert!(
        rendered.contains("Chain (from leaf to root): ["),
        "{rendered}"
    );
    assert_eq!(
        rendered
            .matches("Certificate(version:")
            .count(),
        3,
        "{rendered}"
    );
}

#[test]
fn leaf_unhandled_critical_extension_renders_only_the_unhandled_oids() {
    let cert_der = unknown_critical_extension_der();
    let cert = cert(&cert_der);
    let diagnostic = VerificationDiagnostic::leaf_certificate_has_unhandled_critical_extension(
        cert,
        vec![OID_X509_EXT_BASIC_CONSTRAINTS],
    );

    let single = diagnostic.to_string();
    let multi = diagnostic.multiline_description();
    // The unrecognized extension is reported...
    assert!(
        single.contains("Unhandled extensions: [1.2.3.4.5]"),
        "{single}"
    );
    assert!(
        multi.contains("Unhandled extensions:\n1.2.3.4.5\n"),
        "{multi}"
    );
    // ...and the critical extension the policy does handle is not listed
    // as unhandled. It still appears in the certificate summary by name,
    // so check the unhandled list specifically.
    let unhandled = single
        .split("Unhandled extensions: [")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .unwrap();
    assert_eq!(unhandled, "1.2.3.4.5");
}

#[test]
fn leaf_with_only_handled_critical_extensions_reports_an_empty_unhandled_list() {
    let ca = self_signed_ca_with("All Handled", |_| {});
    let leaf_cert = cert(&ca.der);
    let diagnostic = VerificationDiagnostic::leaf_certificate_has_unhandled_critical_extension(
        leaf_cert,
        vec![OID_X509_EXT_BASIC_CONSTRAINTS],
    );

    let rendered = diagnostic.to_string();
    assert!(rendered.contains("Unhandled extensions: []"), "{rendered}");
}

#[test]
fn issuer_unhandled_critical_extension_renders_only_the_unhandled_oids() {
    let sample = sample_ders();
    let (leaf, _, _) = sample_chain(&sample);
    let issuer_der = unknown_critical_extension_der();
    let issuer = cert(&issuer_der);
    let diagnostic = VerificationDiagnostic::issuer_has_unhandled_critical_extension(
        issuer,
        vec![leaf],
        vec![OID_X509_EXT_BASIC_CONSTRAINTS],
    );

    let single = diagnostic.to_string();
    let multi = diagnostic.multiline_description();
    assert!(
        single.contains("Unhandled extensions: [- 1.2.3.4.5]"),
        "{single}"
    );
    assert!(
        multi.contains("Unhandled extensions:\n- 1.2.3.4.5\n"),
        "{multi}"
    );
    // basicConstraints is handled and must not be listed as unhandled.
    let unhandled = single
        .split("Unhandled extensions: [")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .unwrap();
    assert_eq!(unhandled, "- 1.2.3.4.5");
}

#[test]
fn issuer_unhandled_critical_extension_with_handling_policy_lists_nothing() {
    let sample = sample_ders();
    let (leaf, intermediate, _) = sample_chain(&sample);
    let diagnostic = VerificationDiagnostic::issuer_has_unhandled_critical_extension(
        intermediate,
        vec![leaf],
        vec![OID_X509_EXT_BASIC_CONSTRAINTS],
    );

    let rendered = diagnostic.to_string();
    assert!(rendered.contains("Unhandled extensions: []"), "{rendered}");
}

#[test]
fn issuer_variants_append_the_issuer_after_the_partial_chain() {
    let sample = sample_ders();
    let (leaf, intermediate, root) = sample_chain(&sample);
    let diagnostic =
        VerificationDiagnostic::issuer_has_not_signed_certificate(root, vec![leaf, intermediate]);

    let single = diagnostic.to_string();
    assert!(
        single.starts_with(
            "A candidate issuer of a certificate in the (partial) chain has not signed"
        ),
        "{single}"
    );
    // Two chain certificates plus the issuer.
    assert_eq!(
        single
            .matches("Certificate(version:")
            .count(),
        3,
        "{single}"
    );
    assert!(single.contains("CN=Diagnostic Root"), "{single}");
}

#[test]
fn already_in_chain_variant_names_the_repeated_issuer() {
    let sample = sample_ders();
    let (leaf, intermediate, root) = sample_chain(&sample);
    let diagnostic =
        VerificationDiagnostic::issuer_is_already_in_the_chain(vec![leaf, intermediate], root);

    let single = diagnostic.to_string();
    assert!(
        single.contains("Candidate issuer is already in partial chain and is therefore skipped"),
        "{single}"
    );
    assert!(
        single.contains("Candidate issuer which is already in the chain above: "),
        "{single}"
    );

    let multi = diagnostic.multiline_description();
    assert!(
        multi.contains("Partial chain (from leaf to tip):\n"),
        "{multi}"
    );
    assert!(
        multi.contains("Candidate issuer which is already in the chain above:\n"),
        "{multi}"
    );
}

#[test]
fn could_not_validate_leaf_certificate_carries_the_leaf() {
    let sample = sample_ders();
    let (leaf, _, _) = sample_chain(&sample);
    let diagnostic = VerificationDiagnostic::could_not_validate_leaf_certificate(leaf);

    let single = diagnostic.to_string();
    assert!(
        single.starts_with("Could not validate leaf certificate: Certificate(version:"),
        "{single}"
    );
    assert!(single.contains("CN=diagnostic-leaf"), "{single}");

    let multi = diagnostic.multiline_description();
    assert!(
        multi.starts_with("Could not validate leaf certificate:\nCertificate(version:"),
        "{multi}"
    );
}

#[test]
fn candidate_issuer_store_variants_name_their_store() {
    let sample = sample_ders();
    let (leaf, intermediate, root) = sample_chain(&sample);

    let from_roots = VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_root_store(
        vec![leaf.clone(), intermediate.clone()],
        vec![root],
    );
    assert!(
        from_roots
            .to_string()
            .contains("Candidate issuers in the root store: [")
    );

    let from_intermediates =
        VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_intermediate_store(
            vec![leaf],
            vec![intermediate],
        );
    assert!(
        from_intermediates
            .to_string()
            .contains("Candidate issuers in the intermediate store: [")
    );
}

#[test]
fn searching_for_issuer_renders_the_partial_chain() {
    let sample = sample_ders();
    let (leaf, intermediate, _) = sample_chain(&sample);
    let diagnostic =
        VerificationDiagnostic::searching_for_issuer_of_partial_chain(vec![leaf, intermediate]);

    let single = diagnostic.to_string();
    assert!(
        single.starts_with(
            "Searching for issuers of partial candidate chain. Chain (from leaf to tip): ["
        ),
        "{single}"
    );
    assert_eq!(
        single
            .matches("Certificate(version:")
            .count(),
        2,
        "{single}"
    );
}

#[test]
fn leaf_in_root_store_variant_renders_the_policy_reason() {
    let sample = sample_ders();
    let (leaf, _, _) = sample_chain(&sample);
    let diagnostic =
        VerificationDiagnostic::leaf_certificate_is_in_the_root_store_but_does_not_meet_policy(
            leaf,
            PolicyFailureReason::new("no server auth EKU"),
        );

    let single = diagnostic.to_string();
    assert!(
        single.contains("Reason: no server auth EKU Leaf Certificate: Certificate(version:"),
        "{single}"
    );

    let multi = diagnostic.multiline_description();
    assert!(multi.contains("Reason:\nno server auth EKU\n"), "{multi}");
}
