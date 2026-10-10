use x509_validator::unverified_chain::UnverifiedCertificateChain;
use x509_validator::{Certificate, CertificateExt};

/// Parses DER into a `Certificate` borrowing those bytes.
pub fn cert(der: &[u8]) -> Certificate<'_> {
    Certificate::parse(der).expect("parse certificate")
}

/// Owns the DER a chain is parsed from.
pub struct Ders {
    ders: Vec<Vec<u8>>,
}

impl Ders {
    /// Takes ownership of DER, in leaf-to-root order.
    pub fn new(ders: Vec<Vec<u8>>) -> Self {
        Self { ders }
    }

    /// An unverified chain borrowing this holder's DER, leaf-first.
    pub fn chain(&self) -> UnverifiedCertificateChain<'_> {
        UnverifiedCertificateChain::new(
            self.ders
                .iter()
                .map(|der| cert(der))
                .collect(),
        )
    }

    /// The certificates borrowing this holder's DER, leaf-first.
    pub fn certificates(&self) -> Vec<Certificate<'_>> {
        self.ders
            .iter()
            .map(|der| cert(der))
            .collect()
    }

    /// The DER at `index`, leaf-first.
    pub fn der(&self, index: usize) -> &[u8] {
        &self.ders[index]
    }
}

/// Holds owned DER, in leaf-to-root order, so a chain can borrow from it.
///
/// Call [`Ders::chain`] on the result: the holder must be bound to a local,
/// since the chain borrows it.
pub fn chain_of(ders: Vec<Vec<u8>>) -> Ders {
    Ders::new(ders)
}
