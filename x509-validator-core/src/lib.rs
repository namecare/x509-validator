pub mod verifier;
pub use verifier::*;

pub mod error;
pub mod unverified_chain;
pub mod validated_chain;

pub use x509_parser::certificate::X509Certificate;

/// The concrete certificate type this crate (and its consumers) validate.
pub type Certificate<'a> = X509Certificate<'a>;
