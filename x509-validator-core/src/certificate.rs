pub use x509_parser::certificate::*;

use x509_parser::error::X509Error;
use x509_parser::nom;
use x509_parser::prelude::FromDer;

use crate::extensions::ParsedExtension;
use crate::oid_registry::{OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER};
use crate::GeneralName;

/// The concrete certificate type this crate (and its consumers) validate.
pub type Certificate<'a> = x509_parser::certificate::X509Certificate<'a>;

/// Accessors and comparisons over a certificate that `x509-parser` does not
/// provide directly.
pub trait CertificateExt<'a>: Sized {
    /// Parse a single DER-encoded certificate, discarding any trailing bytes.
    ///
    /// Convenience over [`FromDer::from_der`], which returns the remaining
    /// input alongside the certificate and wraps its error in `nom::Err`.
    fn parse(der: &'a [u8]) -> Result<Self, X509Error>;

    /// The `subjectKeyIdentifier` bytes, if the extension is present and parses.
    fn subject_key_identifier(&self) -> Option<&'a [u8]>;

    /// The `authorityKeyIdentifier`'s `keyIdentifier` bytes, if present.
    fn authority_key_identifier(&self) -> Option<&'a [u8]>;

    /// Canonical DER bytes of the certificate's own subject name, usable as a
    /// lookup key.
    fn subject_key(&self) -> Vec<u8>;

    /// Canonical DER bytes of the certificate's issuer name, in the same
    /// representation as `subject_key` so entries stored by subject can be
    /// found by an issuer-name lookup.
    fn issuer_key(&self) -> Vec<u8>;

    /// The `subjectAltName` entries, or an empty vector when the extension is
    /// absent or does not parse.
    fn subject_alternative_names(&self) -> Vec<GeneralName<'a>>;

    /// Whether two certificates denote the same logical certificate: same
    /// subject, same public key, same subject alternative names. Deliberately
    /// not full DER equality.
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
            ParsedExtension::AuthorityKeyIdentifier(aki) => aki.key_identifier.as_ref().map(|id| id.0),
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
