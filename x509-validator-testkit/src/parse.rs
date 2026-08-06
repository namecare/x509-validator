use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use x509_validator_core::{Certificate, FromDer};

/// Leaks DER bytes to obtain the `'static` lifetime that borrowed
/// `Certificate` values require. Tests are short-lived processes, so the
/// leak is deliberate and bounded.
pub fn leak(der: Vec<u8>) -> &'static [u8] {
    Box::leak(der.into_boxed_slice())
}

/// Parses owned DER into a `Certificate` borrowing leaked bytes.
pub fn cert(der: Vec<u8>) -> Certificate<'static> {
    Certificate::from_der(leak(der)).expect("parse certificate").1
}

/// Builds an unverified chain from DER, in leaf-to-root order.
pub fn chain_of(ders: Vec<Vec<u8>>) -> UnverifiedCertificateChain<'static> {
    UnverifiedCertificateChain::new(ders.into_iter().map(cert).collect())
}
