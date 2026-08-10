use std::collections::HashMap;

use crate::{Certificate, CertificateExt};

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

/// Initialize a certificate store from a sequence of certificates.
impl<'a> FromIterator<Certificate<'a>> for CertificateStore<'a> {
    fn from_iter<T: IntoIterator<Item = Certificate<'a>>>(certificates: T) -> Self {
        let mut store = Self::new();
        for cert in certificates {
            store.append(cert);
        }
        store
    }
}

impl<'a> CertificateStore<'a> {
    pub fn new() -> Self {
        Self {
            by_subject: HashMap::new(),
        }
    }

    pub fn append(&mut self, certificate: Certificate<'a>) {
        let key = certificate.subject_key();
        self.by_subject
            .entry(key)
            .or_default()
            .push(certificate);
    }

    pub fn find_by_subject(&self, subject_key: &[u8]) -> &[Certificate<'a>] {
        self.by_subject
            .get(subject_key)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}
