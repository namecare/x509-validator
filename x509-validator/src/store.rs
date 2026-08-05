use std::collections::HashMap;
use x509_validator_core::Certificate;

/// Holds certificates indexed by subject name for fast issuer lookup during
/// chain building.
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
    certificate.subject().as_raw().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::self_signed_ca;
    use x509_parser::prelude::FromDer;

    fn cert(subject_cn: &str) -> Certificate<'static> {
        let der = self_signed_ca(subject_cn);
        let der: &'static [u8] = Box::leak(der.into_boxed_slice());
        Certificate::from_der(der).unwrap().1
    }

    #[test]
    fn append_and_find_by_subject_round_trip() {
        let mut store = CertificateStore::new();
        let c = cert("subject-a");
        let key = subject_key(&c);
        store.append(c);

        let found = store.find_by_subject(&key);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn find_by_subject_returns_empty_slice_for_unknown_subject() {
        let store: CertificateStore = CertificateStore::new();
        assert!(store.find_by_subject(b"nope").is_empty());
    }

    #[test]
    fn two_certificates_sharing_a_subject_are_both_returned() {
        let a = cert("shared-subject");
        let b = cert("shared-subject");
        let key = subject_key(&a);

        let mut store = CertificateStore::new();
        store.append(a);
        store.append(b);

        let found = store.find_by_subject(&key);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn from_iter_populates_store() {
        let c1 = cert("s1");
        let c2 = cert("s2");
        let key1 = subject_key(&c1);
        let key2 = subject_key(&c2);

        let store = CertificateStore::from_iter(vec![c1, c2]);
        assert_eq!(store.find_by_subject(&key1).len(), 1);
        assert_eq!(store.find_by_subject(&key2).len(), 1);
    }
}