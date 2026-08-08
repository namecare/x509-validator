//! Human-readable rendering of parsed certificates.
//!
//! `Certificate`'s derived `Debug` dumps every parsed field, including the
//! raw DER byte slices backing the public key, the signature and each
//! extension — hundreds of lines of numbers that are useless in a log line.
//! [`format_certificate`] renders the fields an operator actually needs to
//! identify a certificate, on a single line, and never emits raw bytes.

use x509_validator_core::der_parser::Oid;
use x509_validator_core::objects::{oid2sn, oid_registry};
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
