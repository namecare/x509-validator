pub mod verifier;
pub use verifier::*;

pub mod error;
pub mod unverified_chain;
pub mod validated_chain;

// Core is the single entry point for the X.509 types its consumers need:
// dependent crates depend on core alone, never on `x509-parser` or
// `oid-registry` directly.
//
// The domain types below are aliases rather than re-exports. Consumers name
// the alias, so the underlying representation can be swapped for a different
// parser (or an owned type of our own) by editing this file alone.

/// The concrete certificate type this crate (and its consumers) validate.
pub type Certificate<'a> = x509_parser::certificate::X509Certificate<'a>;

/// An object identifier.
pub type Oid<'a> = x509_parser::der_parser::Oid<'a>;

/// A `subjectAltName` / `issuerAltName` entry.
pub type GeneralName<'a> = x509_parser::extensions::GeneralName<'a>;

/// A name-constraints subtree entry.
pub type GeneralSubtree<'a> = x509_parser::extensions::GeneralSubtree<'a>;

/// A decoded certificate extension.
pub type ParsedExtension<'a> = x509_parser::extensions::ParsedExtension<'a>;

/// An `AlgorithmIdentifier` (signature or public-key algorithm, with params).
pub type AlgorithmIdentifier<'a> = x509_parser::x509::AlgorithmIdentifier<'a>;

/// A certificate's `subjectPublicKeyInfo`.
pub type SubjectPublicKeyInfo<'a> = x509_parser::x509::SubjectPublicKeyInfo<'a>;

/// RSASSA-PSS signature parameters.
pub type RsaSsaPssParams<'a> = x509_parser::signature_algorithm::RsaSsaPssParams<'a>;

/// An untyped ASN.1 value, as yielded by extension parsing.
pub type Any<'a> = x509_parser::asn1_rs::Any<'a>;

/// The certificate structure version (v1/v2/v3).
///
/// A plain re-export, not an alias: this is a fieldless enum consumers match
/// on by variant, so aliasing it would not let the variants follow.
pub use x509_parser::x509::X509Version;

/// DER decoding. A trait, so it is re-exported rather than aliased.
pub use x509_parser::prelude::FromDer;

// Pass-through modules, mirroring the parser's own layout. These carry the
// surface not worth aliasing individually — OID constants above all — so
// consumers reach them at a familiar path, e.g.
// `x509_validator_core::oid_registry::OID_X509_EXT_KEY_USAGE`.

pub mod der_parser {
    pub use x509_parser::der_parser::*;
}

pub mod oid_registry {
    pub use x509_parser::oid_registry::*;
}

pub mod extensions {
    pub use x509_parser::extensions::*;
}

pub mod x509 {
    pub use x509_parser::x509::*;
}

pub mod objects {
    pub use x509_parser::objects::*;
}

pub mod signature_algorithm {
    pub use x509_parser::signature_algorithm::*;
}

pub mod certificate {
    pub use x509_parser::certificate::*;
}

pub mod prelude {
    pub use x509_parser::prelude::*;
}

pub mod asn1_rs {
    pub use x509_parser::asn1_rs::*;
}