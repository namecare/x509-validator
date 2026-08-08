//! Human-readable certificate rendering.

use x509_validator::format_certificate;
use x509_validator_testkit::{cert, issue_ca, issue_leaf, self_signed_ca_with};

/// A byte-array dump would show up as a run of comma-separated decimal
/// numbers inside brackets; the summary must never contain one.
fn assert_no_byte_dump(rendered: &str) {
    assert!(!rendered.contains('\n'), "summary must be a single line");
    assert!(rendered.len() < 1024, "summary is suspiciously long: {} bytes", rendered.len());

    let digit_runs = rendered
        .split(|c: char| !c.is_ascii_digit() && c != ',' && c != ' ')
        .filter(|run| run.matches(',').count() >= 3)
        .count();
    assert_eq!(digit_runs, 0, "summary appears to contain a byte-array dump: {rendered}");
}

#[test]
fn formats_self_signed_ca() {
    let ca = self_signed_ca_with("Test Root CA", |_| {});
    let cert = cert(ca.der.clone());

    let rendered = format_certificate(&cert);

    assert!(rendered.starts_with("Certificate(version: v3, serialNumber: "), "{rendered}");
    assert!(rendered.ends_with(')'), "{rendered}");
    // Self-signed: issuer and subject are the same name.
    assert!(rendered.contains("issuer: CN=Test Root CA"), "{rendered}");
    assert!(rendered.contains("subject: CN=Test Root CA"), "{rendered}");
    assert!(rendered.contains("notValidBefore: "), "{rendered}");
    assert!(rendered.contains("notValidAfter: "), "{rendered}");
    assert!(rendered.contains("publicKey: "), "{rendered}");
    assert!(rendered.contains("signature: "), "{rendered}");
    // A CA must carry basic constraints, and rcgen marks them critical.
    assert!(rendered.contains("basicConstraints (critical)"), "{rendered}");
    assert_no_byte_dump(&rendered);
}

#[test]
fn serial_number_is_hex_not_decimal_bytes() {
    let ca = self_signed_ca_with("Serial Root", |_| {});
    let cert = cert(ca.der.clone());

    let rendered = format_certificate(&cert);
    let serial = rendered
        .split("serialNumber: ")
        .nth(1)
        .and_then(|rest| rest.split(", issuer:").next())
        .expect("serial field present");

    assert!(!serial.is_empty());
    assert!(
        serial.chars().all(|c| c.is_ascii_hexdigit() || c == ':'),
        "serial should be hex: {serial}"
    );
    assert_eq!(serial, cert.raw_serial_as_string());
}

#[test]
fn formats_leaf_with_sans() {
    let root = self_signed_ca_with("SAN Root", |_| {});
    let leaf_der = issue_leaf("leaf", &["www.example.com", "example.com"], &root);
    let cert = cert(leaf_der);

    let rendered = format_certificate(&cert);

    assert!(rendered.contains("subject: CN=leaf"), "{rendered}");
    assert!(rendered.contains("issuer: CN=SAN Root"), "{rendered}");
    assert!(rendered.contains("subjectAltName"), "{rendered}");
    // The extension list names extensions, it does not expand their
    // contents, so the SAN values themselves must not appear.
    assert!(!rendered.contains("www.example.com"), "{rendered}");
    assert_no_byte_dump(&rendered);
}

#[test]
fn formats_certificate_with_multiple_extensions() {
    let root = self_signed_ca_with("Multi Root", |_| {});
    let intermediate = issue_ca("Multi Intermediate", &root, Some(0), |params| {
        params.key_usages = vec![
            x509_validator_testkit::rcgen::KeyUsagePurpose::KeyCertSign,
            x509_validator_testkit::rcgen::KeyUsagePurpose::CrlSign,
        ];
        params.name_constraints = Some(x509_validator_testkit::name_constraints(
            vec![x509_validator_testkit::dns_subtree("example.com")],
            vec![],
        ));
    });
    let cert = cert(intermediate.der.clone());

    let rendered = format_certificate(&cert);

    let extensions = rendered
        .split("extensions: [")
        .nth(1)
        .and_then(|rest| rest.strip_suffix("])"))
        .expect("extension list present");

    assert!(extensions.contains("basicConstraints"), "{rendered}");
    assert!(extensions.contains("keyUsage"), "{rendered}");
    assert!(extensions.contains("nameConstraints"), "{rendered}");
    assert!(extensions.split(", ").count() >= 3, "{rendered}");
    assert!(extensions.contains("(critical)"), "{rendered}");
    assert_no_byte_dump(&rendered);
}
