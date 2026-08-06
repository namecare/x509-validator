//! Human-readable rendering of parsed certificates.
//!
//! `Certificate`'s derived `Debug` dumps every parsed field, including the
//! raw DER byte slices backing the public key, the signature and each
//! extension — hundreds of lines of numbers that are useless in a log line.
//! [`format_certificate`] renders the fields an operator actually needs to
//! identify a certificate, on a single line, and never emits raw bytes.

use x509_parser::der_parser::Oid;
use x509_parser::objects::{oid2sn, oid_registry};
use x509_validator_core::Certificate;

/// Renders `cert` as a single-line, human-readable summary.
///
/// Algorithm identifiers are rendered by their short name when the OID is
/// known, and by dotted-decimal OID otherwise. Key and signature *values*
/// are deliberately omitted; only the algorithms are shown.
pub fn format_certificate(cert: &Certificate<'_>) -> String {
    let tbs = &cert.tbs_certificate;
    let validity = tbs.validity();

    format!(
        "Certificate(version: {}, serialNumber: {}, issuer: {}, subject: {}, \
         notValidBefore: {}, notValidAfter: {}, publicKey: {}, signature: {}, extensions: {})",
        // `X509Version`'s own `Display` yields `V3`; the conventional
        // spelling in certificate tooling is lowercase.
        tbs.version.to_string().to_lowercase(),
        cert.raw_serial_as_string(),
        tbs.issuer,
        tbs.subject,
        validity.not_before,
        validity.not_after,
        algorithm_name(&tbs.subject_pki.algorithm.algorithm),
        algorithm_name(&cert.signature_algorithm.algorithm),
        format_extensions(cert),
    )
}

/// The short name registered for `oid`, or its dotted-decimal form when the
/// OID is not in the registry.
fn algorithm_name(oid: &Oid<'_>) -> String {
    match oid2sn(oid, oid_registry()) {
        Ok(name) => name.to_string(),
        Err(_) => oid.to_id_string(),
    }
}

/// The extensions present, as `[oid, oid (critical), ...]`. Extension
/// contents are never rendered — only which extensions are present and
/// whether each is marked critical.
fn format_extensions(cert: &Certificate<'_>) -> String {
    let rendered: Vec<String> = cert
        .tbs_certificate
        .iter_extensions()
        .map(|ext| {
            let name = algorithm_name(&ext.oid);
            if ext.critical {
                format!("{name} (critical)")
            } else {
                name
            }
        })
        .collect();

    format!("[{}]", rendered.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{issue_ca, issue_leaf, self_signed_ca_with};
    use x509_parser::prelude::FromDer;

    fn leak(der: Vec<u8>) -> &'static [u8] {
        Box::leak(der.into_boxed_slice())
    }

    fn parse(der: &'static [u8]) -> Certificate<'static> {
        Certificate::from_der(der).expect("parse certificate").1
    }

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
        let cert = parse(leak(ca.der.clone()));

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
        let cert = parse(leak(ca.der.clone()));

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
        let leaf_der = leak(issue_leaf("leaf", &["www.example.com", "example.com"], &root));
        let cert = parse(leaf_der);

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
            params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
            params.name_constraints = Some(crate::test_support::name_constraints(
                vec![crate::test_support::dns_subtree("example.com")],
                vec![],
            ));
        });
        let cert = parse(leak(intermediate.der.clone()));

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
}
