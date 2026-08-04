use crate::view::{CertificateView, NameView};
use std::collections::HashMap;

/// Holds certificates indexed by subject name for fast issuer lookup during
/// chain building. Sync-only (no async trust-store loading).
#[derive(Debug, Clone)]
pub struct CertificateStore<C: CertificateView> {
    by_subject: HashMap<Vec<u8>, Vec<C>>, // keyed by NameView::canonical_der() bytes
}

impl<C: CertificateView + Clone> Default for CertificateStore<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: CertificateView + Clone> CertificateStore<C> {
    pub fn new() -> Self {
        Self {
            by_subject: HashMap::new(),
        }
    }

    pub fn from_iter(certificates: impl IntoIterator<Item = C>) -> Self {
        let mut store = Self::new();
        for cert in certificates {
            store.append(cert);
        }
        store
    }

    pub fn append(&mut self, certificate: C) {
        let key = subject_key(&certificate);
        self.by_subject.entry(key).or_default().push(certificate);
    }

    pub fn find_by_subject(&self, subject_key: &[u8]) -> &[C] {
        self.by_subject
            .get(subject_key)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// Canonical lookup key for a Name. `NameView` doesn't require `Hash` (parser
/// backends may not want to implement it), so the store hashes a stable
/// byte representation instead, using `NameView::canonical_der()`.
pub fn subject_key<C: CertificateView>(certificate: &C) -> Vec<u8> {
    certificate.subject().canonical_der().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::{
        AuthorityKeyIdentifier, BasicConstraints, ExtensionsView, GeneralNameKind, NameConstraints,
        NameView, Oid, PublicKeyInfoView, SignatureAlgorithmId, SubjectKeyIdentifier, Timestamp,
    };

    #[derive(Debug, Clone)]
    struct FakeName {
        der_bytes: Vec<u8>,
    }

    impl PartialEq for FakeName {
        fn eq(&self, other: &Self) -> bool {
            self.der_bytes == other.der_bytes
        }
    }
    impl Eq for FakeName {}

    impl NameView for FakeName {
        fn general_names(&self) -> Vec<(GeneralNameKind, Vec<u8>)> {
            vec![(GeneralNameKind::DirectoryName, self.der_bytes.clone())]
        }

        fn canonical_der(&self) -> &[u8] {
            &self.der_bytes
        }
        fn common_name(&self) -> Option<Vec<u8>> {
            None
        }
    }

    #[derive(Debug)]
    struct FakeExtensions;

    impl ExtensionsView for FakeExtensions {
        type Error = std::io::Error;

        fn oids(&self) -> Vec<(Oid, bool)> {
            vec![]
        }
        fn bytes_for(&self, _oid: &Oid) -> Option<&[u8]> {
            None
        }
        fn basic_constraints(&self) -> Result<Option<BasicConstraints>, Self::Error> {
            Ok(None)
        }
        fn name_constraints(&self) -> Result<Option<NameConstraints>, Self::Error> {
            Ok(None)
        }
        fn key_usage_present(&self) -> Result<bool, Self::Error> {
            Ok(false)
        }
        fn extended_key_usage_contains_ocsp_signing(&self) -> Result<bool, Self::Error> {
            Ok(false)
        }
        fn subject_alt_names(&self) -> Result<Option<Vec<(GeneralNameKind, Vec<u8>)>>, Self::Error> {
            Ok(None)
        }
        fn authority_key_identifier(&self) -> Result<Option<AuthorityKeyIdentifier>, Self::Error> {
            Ok(None)
        }
        fn subject_key_identifier(&self) -> Result<Option<SubjectKeyIdentifier>, Self::Error> {
            Ok(None)
        }
    }

    #[derive(Debug, Clone)]
    struct FakePublicKeyInfo {
        der_bytes: Vec<u8>,
    }

    impl PartialEq for FakePublicKeyInfo {
        fn eq(&self, other: &Self) -> bool {
            self.der_bytes == other.der_bytes
        }
    }
    impl Eq for FakePublicKeyInfo {}

    impl PublicKeyInfoView for FakePublicKeyInfo {
        fn subject_public_key_info_der(&self) -> &[u8] {
            &self.der_bytes
        }
    }

    #[derive(Debug, Clone)]
    struct FakeCertificate {
        subject_name: FakeName,
        issuer_name: FakeName,
        public_key: FakePublicKeyInfo,
    }

    impl CertificateView for FakeCertificate {
        type Name = FakeName;
        type Extensions = FakeExtensions;
        type PublicKeyInfo = FakePublicKeyInfo;
        type Error = std::io::Error;

        fn from_der(_der: &[u8]) -> Result<Self, Self::Error> {
            Err(std::io::Error::other("FakeCertificate does not support from_der"))
        }

        fn subject(&self) -> &Self::Name {
            &self.subject_name
        }
        fn issuer(&self) -> &Self::Name {
            &self.issuer_name
        }
        fn is_v1(&self) -> bool {
            false
        }
        fn has_extensions(&self) -> bool {
            false
        }
        fn not_before(&self) -> Timestamp {
            0
        }
        fn not_after(&self) -> Timestamp {
            0
        }
        fn extensions(&self) -> &Self::Extensions {
            &FakeExtensions
        }
        fn public_key_info(&self) -> &Self::PublicKeyInfo {
            &self.public_key
        }
        fn signature_algorithm(&self) -> SignatureAlgorithmId {
            SignatureAlgorithmId::EcdsaP256Sha256
        }
        fn signature(&self) -> &[u8] {
            &[]
        }
        fn tbs_der(&self) -> &[u8] {
            &[]
        }
    }

    fn cert(subject: &[u8], issuer: &[u8], key: &[u8]) -> FakeCertificate {
        FakeCertificate {
            subject_name: FakeName {
                der_bytes: subject.to_vec(),
            },
            issuer_name: FakeName {
                der_bytes: issuer.to_vec(),
            },
            public_key: FakePublicKeyInfo {
                der_bytes: key.to_vec(),
            },
        }
    }

    #[test]
    fn append_and_find_by_subject_round_trip() {
        let mut store = CertificateStore::new();
        let c = cert(b"subject-a", b"issuer-a", b"key-a");
        store.append(c.clone());

        let found = store.find_by_subject(b"subject-a");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].public_key.der_bytes, b"key-a");
    }

    #[test]
    fn find_by_subject_returns_empty_slice_for_unknown_subject() {
        let store: CertificateStore<FakeCertificate> = CertificateStore::new();
        assert!(store.find_by_subject(b"nope").is_empty());
    }

    #[test]
    fn two_certificates_sharing_a_subject_are_both_returned() {
        let mut store = CertificateStore::new();
        store.append(cert(b"shared-subject", b"issuer-a", b"key-a"));
        store.append(cert(b"shared-subject", b"issuer-b", b"key-b"));

        let found = store.find_by_subject(b"shared-subject");
        assert_eq!(found.len(), 2);
        let keys: Vec<&[u8]> = found.iter().map(|c| c.public_key.der_bytes.as_slice()).collect();
        assert!(keys.contains(&b"key-a".as_slice()));
        assert!(keys.contains(&b"key-b".as_slice()));
    }

    #[test]
    fn from_iter_populates_store() {
        let store = CertificateStore::from_iter(vec![
            cert(b"s1", b"i1", b"k1"),
            cert(b"s2", b"i2", b"k2"),
        ]);
        assert_eq!(store.find_by_subject(b"s1").len(), 1);
        assert_eq!(store.find_by_subject(b"s2").len(), 1);
    }
}