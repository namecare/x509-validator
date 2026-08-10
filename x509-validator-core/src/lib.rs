pub mod validator;
pub use validator::*;

pub mod certificate;
pub mod error;
pub mod unverified_chain;
pub mod validated_chain;

pub use certificate::{Certificate, CertificateExt};

pub type Oid<'a> = x509_parser::der_parser::Oid<'a>;
pub type GeneralName<'a> = x509_parser::extensions::GeneralName<'a>;
pub type GeneralSubtree<'a> = x509_parser::extensions::GeneralSubtree<'a>;
pub type ParsedExtension<'a> = x509_parser::extensions::ParsedExtension<'a>;
pub type AlgorithmIdentifier<'a> = x509_parser::x509::AlgorithmIdentifier<'a>;
pub type SubjectPublicKeyInfo<'a> = x509_parser::x509::SubjectPublicKeyInfo<'a>;
pub type RsaSsaPssParams<'a> = x509_parser::signature_algorithm::RsaSsaPssParams<'a>;
pub type Any<'a> = x509_parser::asn1_rs::Any<'a>;

pub use x509_parser::x509::X509Version;
pub use x509_parser::prelude::FromDer;

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

pub mod prelude {
    pub use x509_parser::prelude::*;
}

pub mod asn1_rs {
    pub use x509_parser::asn1_rs::*;
}