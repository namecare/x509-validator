pub use x509_parser::certificate::*;
use x509_parser::error::X509Error;
use x509_parser::nom;
use x509_parser::objects::{oid_registry, oid2sn};
use x509_parser::prelude::FromDer;

use crate::GeneralName;
use crate::asn1_rs::Oid;
use crate::extensions::ParsedExtension;
use crate::oid_registry::{
    OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
};

pub type Certificate<'a> = X509Certificate<'a>;

pub trait CertificateExt<'a>: Sized {
    /// Parse a single DER-encoded certificate
    fn parse(der: &'a [u8]) -> Result<Self, X509Error>;

    /// The `subjectKeyIdentifier` bytes, if the extension is present and parses.
    fn subject_key_identifier(&self) -> Option<&'a [u8]>;

    /// The `authorityKeyIdentifier`'s `keyIdentifier` bytes, if present.
    fn authority_key_identifier(&self) -> Option<&'a [u8]>;

    /// Canonical DER bytes of the certificate's own subject name
    fn subject_key(&self) -> Vec<u8>;

    /// Canonical DER bytes of the certificate's issuer name
    fn issuer_key(&self) -> Vec<u8>;

    /// The `subjectAltName` entries, or an empty vector when the extension is
    /// absent or does not parse.
    fn subject_alternative_names(&self) -> Vec<GeneralName<'a>>;

    /// Whether two certificates denote the same logical certificate: same
    /// subject, same public key, same subject alternative names.
    fn has_same_identity_as(&self, other: &Self) -> bool;
}

impl<'a> CertificateExt<'a> for Certificate<'a> {
    fn parse(der: &'a [u8]) -> Result<Self, X509Error> {
        Certificate::from_der(der)
            .map(|(_, certificate)| certificate)
            .map_err(|err| match err {
                nom::Err::Error(e) | nom::Err::Failure(e) => e,
                nom::Err::Incomplete(_) => X509Error::InvalidCertificate,
            })
    }

    fn subject_key_identifier(&self) -> Option<&'a [u8]> {
        let ext = self
            .tbs_certificate
            .get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
            .ok()??;
        match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(key_id) => Some(key_id.0),
            _ => None,
        }
    }

    fn authority_key_identifier(&self) -> Option<&'a [u8]> {
        let ext = self
            .tbs_certificate
            .get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
            .ok()??;
        match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => aki
                .key_identifier
                .as_ref()
                .map(|id| id.0),
            _ => None,
        }
    }

    fn subject_key(&self) -> Vec<u8> {
        self.subject().as_raw().to_vec()
    }

    fn issuer_key(&self) -> Vec<u8> {
        self.issuer().as_raw().to_vec()
    }

    fn subject_alternative_names(&self) -> Vec<GeneralName<'a>> {
        self.tbs_certificate
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|ext| ext.value.general_names.clone())
            .unwrap_or_default()
    }

    fn has_same_identity_as(&self, other: &Self) -> bool {
        self.subject() == other.subject()
            && self.public_key() == other.public_key()
            && self.subject_alternative_names() == other.subject_alternative_names()
    }
}

/// Renders `cert` as a single-line, human-readable summary.
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

/// The short name registered for `oid`
fn algorithm_name(oid: &Oid<'_>) -> String {
    match oid2sn(oid, oid_registry()) {
        Ok(name) => name.to_string(),
        Err(_) => oid.to_id_string(),
    }
}

/// The extensions present, as `[oid, oid (critical), ...]`.
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
    use x509_validator_testkit::{cert, issue_ca, issue_leaf, self_signed_ca_with};

    use crate::certificate::format_certificate;

    fn assert_no_byte_dump(rendered: &str) {
        assert!(!rendered.contains('\n'), "summary must be a single line");
        assert!(
            rendered.len() < 1024,
            "summary is suspiciously long: {} bytes",
            rendered.len()
        );

        let digit_runs = rendered
            .split(|c: char| !c.is_ascii_digit() && c != ',' && c != ' ')
            .filter(|run| run.matches(',').count() >= 3)
            .count();
        assert_eq!(
            digit_runs, 0,
            "summary appears to contain a byte-array dump: {rendered}"
        );
    }

    #[test]
    fn formats_self_signed_ca() {
        let ca = self_signed_ca_with("Test Root CA", |_| {});
        let cert = cert(&ca.der);

        let rendered = format_certificate(&cert);

        assert!(
            rendered.starts_with("Certificate(version: v3, serialNumber: "),
            "{rendered}"
        );
        assert!(rendered.ends_with(')'), "{rendered}");
        // Self-signed: issuer and subject are the same name.
        assert!(rendered.contains("issuer: CN=Test Root CA"), "{rendered}");
        assert!(rendered.contains("subject: CN=Test Root CA"), "{rendered}");
        assert!(rendered.contains("notValidBefore: "), "{rendered}");
        assert!(rendered.contains("notValidAfter: "), "{rendered}");
        assert!(rendered.contains("publicKey: "), "{rendered}");
        assert!(rendered.contains("signature: "), "{rendered}");
        // A CA must carry basic constraints, and rcgen marks them critical.
        assert!(
            rendered.contains("basicConstraints (critical)"),
            "{rendered}"
        );
        assert_no_byte_dump(&rendered);
    }

    #[test]
    fn serial_number_is_hex_not_decimal_bytes() {
        let ca = self_signed_ca_with("Serial Root", |_| {});
        let cert = cert(&ca.der);

        let rendered = format_certificate(&cert);
        let serial = rendered
            .split("serialNumber: ")
            .nth(1)
            .and_then(|rest| rest.split(", issuer:").next())
            .expect("serial field present");

        assert!(!serial.is_empty());
        assert!(
            serial
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':'),
            "serial should be hex: {serial}"
        );
        assert_eq!(serial, cert.raw_serial_as_string());
    }

    #[test]
    fn formats_leaf_with_sans() {
        let root = self_signed_ca_with("SAN Root", |_| {});
        let leaf_der = issue_leaf("leaf", &["www.example.com", "example.com"], &root);
        let cert = cert(&leaf_der);

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
        let cert = cert(&intermediate.der);

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
