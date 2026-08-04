use x509_validator_core::{
    CertificateView, ExtensionsView, GeneralNameKind, NameView, Oid, PublicKeyInfoView,
    SignatureAlgorithmId, Timestamp,
};

// Minimal fake implementation for smoke testing
#[derive(Debug)]
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

impl PartialEq for FakeExtensions {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl ExtensionsView for FakeExtensions {
    type Error = std::io::Error;

    fn oids(&self) -> Vec<(Oid, bool)> {
        vec![]
    }

    fn bytes_for(&self, _oid: &Oid) -> Option<&[u8]> {
        None
    }

    fn basic_constraints(
        &self,
    ) -> Result<Option<x509_validator_core::BasicConstraints>, Self::Error> {
        Ok(None)
    }

    fn name_constraints(
        &self,
    ) -> Result<Option<x509_validator_core::NameConstraints>, Self::Error> {
        Ok(None)
    }

    fn key_usage_present(&self) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn extended_key_usage_contains_ocsp_signing(&self) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn subject_alt_names(
        &self,
    ) -> Result<Option<Vec<(GeneralNameKind, Vec<u8>)>>, Self::Error> {
        Ok(None)
    }

    fn authority_key_identifier(
        &self,
    ) -> Result<Option<x509_validator_core::AuthorityKeyIdentifier>, Self::Error> {
        Ok(None)
    }

    fn subject_key_identifier(
        &self,
    ) -> Result<Option<x509_validator_core::SubjectKeyIdentifier>, Self::Error> {
        Ok(None)
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
struct FakeCertificate {
    subject_name: FakeName,
    issuer_name: FakeName,
    not_before: Timestamp,
    not_after: Timestamp,
    signature_algo: SignatureAlgorithmId,
    signature_bytes: Vec<u8>,
    tbs_bytes: Vec<u8>,
    public_key: FakePublicKeyInfo,
}

impl CertificateView for FakeCertificate {
    type Name = FakeName;
    type Extensions = FakeExtensions;
    type PublicKeyInfo = FakePublicKeyInfo;

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
        self.not_before
    }

    fn not_after(&self) -> Timestamp {
        self.not_after
    }

    fn extensions(&self) -> &Self::Extensions {
        &FakeExtensions
    }

    fn public_key_info(&self) -> &Self::PublicKeyInfo {
        &self.public_key
    }

    fn signature_algorithm(&self) -> SignatureAlgorithmId {
        self.signature_algo
    }

    fn signature(&self) -> &[u8] {
        &self.signature_bytes
    }

    fn tbs_der(&self) -> &[u8] {
        &self.tbs_bytes
    }
}

#[test]
fn smoke_test_certificate_view() {
    let cert = FakeCertificate {
        subject_name: FakeName {
            der_bytes: vec![0x30, 0x10],
        },
        issuer_name: FakeName {
            der_bytes: vec![0x30, 0x20],
        },
        not_before: 1609459200, // 2021-01-01 00:00:00
        not_after: 1640995200,  // 2022-01-01 00:00:00
        signature_algo: SignatureAlgorithmId::EcdsaP256Sha256,
        signature_bytes: vec![0x30, 0x40],
        tbs_bytes: vec![0x30, 0x50],
        public_key: FakePublicKeyInfo {
            der_bytes: vec![0x30, 0x60],
        },
    };

    // Test accessor methods
    assert_eq!(cert.is_v1(), false);
    assert_eq!(cert.has_extensions(), false);
    assert_eq!(cert.not_before(), 1609459200);
    assert_eq!(cert.not_after(), 1640995200);
    assert_eq!(cert.signature_algorithm(), SignatureAlgorithmId::EcdsaP256Sha256);
    assert_eq!(cert.signature(), &vec![0x30, 0x40][..]);
    assert_eq!(cert.tbs_der(), &vec![0x30, 0x50][..]);

    // Test Name trait
    let subject_names = cert.subject().general_names();
    assert_eq!(subject_names.len(), 1);
    assert_eq!(subject_names[0].0, GeneralNameKind::DirectoryName);
    assert_eq!(cert.subject().canonical_der(), &vec![0x30, 0x10][..]);

    // Test PublicKeyInfo trait
    assert_eq!(
        cert.public_key_info().subject_public_key_info_der(),
        &vec![0x30, 0x60][..]
    );

    // Test Extensions trait
    let oids = cert.extensions().oids();
    assert_eq!(oids.len(), 0);
}