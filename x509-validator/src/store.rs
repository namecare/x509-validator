use std::collections::HashMap;
use x509_validator_core::{Certificate, CertificateExt};

/// A collection of certificates for use in verification.
#[derive(Debug, Clone)]
pub struct CertificateStore<'a> {
    by_subject: HashMap<Vec<u8>, Vec<Certificate<'a>>>, // keyed by subject's raw DER bytes
}

impl<'a> Default for CertificateStore<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> CertificateStore<'a> {
    pub fn new() -> Self {
        Self { by_subject: HashMap::new() }
    }

    /// Initialize a certificate store from a sequence of certificates.
    pub fn from_iter(certificates: impl IntoIterator<Item = Certificate<'a>>) -> Self {
        let mut store = Self::new();
        for cert in certificates {
            store.append(cert);
        }
        store
    }

    pub fn append(&mut self, certificate: Certificate<'a>) {
        let key = subject_key(&certificate);
        self.by_subject.entry(key).or_default().push(certificate);
    }

    pub fn find_by_subject(&self, subject_key: &[u8]) -> &[Certificate<'a>] {
        self.by_subject.get(subject_key).map(Vec::as_slice).unwrap_or(&[])
    }
}

/// Canonical lookup key for a certificate's subject: its raw DER bytes.
pub fn subject_key(certificate: &Certificate) -> Vec<u8> {
    certificate.subject_key()
}
