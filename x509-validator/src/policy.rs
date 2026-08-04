use x509_validator_core::{CertificateView, Oid};
use std::fmt;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

/// Result of evaluating a certificate chain against a policy. `Ok(())` indicates
/// the chain meets policy requirements; `Err(reason)` indicates policy failure.
pub type PolicyEvaluationResult = Result<(), PolicyFailureReason>;

#[derive(Clone)]
pub struct PolicyFailureReason(String);

impl PolicyFailureReason {
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

impl fmt::Display for PolicyFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for PolicyFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for PolicyFailureReason {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// Evaluates certificate chains against custom policies. Sync (no async).
pub trait VerifierPolicy<C: CertificateView> {
    fn verifying_critical_extensions(&self) -> Vec<Oid>;
    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain<C>) -> PolicyEvaluationResult;
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_validator_core::{ExtensionsView, GeneralNameKind, NameView, PublicKeyInfoView, SignatureAlgorithmId, Timestamp};
    use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
    // Minimal fake implementations for testing

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

        fn basic_constraints(&self) -> Result<Option<x509_validator_core::BasicConstraints>, Self::Error> {
            Ok(None)
        }

        fn name_constraints(&self) -> Result<Option<x509_validator_core::NameConstraints>, Self::Error> {
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

        fn authority_key_identifier(&self) -> Result<Option<x509_validator_core::AuthorityKeyIdentifier>, Self::Error> {
            Ok(None)
        }

        fn subject_key_identifier(&self) -> Result<Option<x509_validator_core::SubjectKeyIdentifier>, Self::Error> {
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

    struct AlwaysMeetsPolicy;

    impl<C: CertificateView> VerifierPolicy<C> for AlwaysMeetsPolicy {
        fn verifying_critical_extensions(&self) -> Vec<Oid> {
            vec![]
        }
        fn chain_meets_policy_requirements(&mut self, _chain: &UnverifiedCertificateChain<C>) -> PolicyEvaluationResult {
            Ok(())
        }
    }

    // Compile-only proof that VerifierPolicy is usable as a trait object
    // over some concrete C.
    fn _assert_object_safe<C: CertificateView>(_: Box<dyn VerifierPolicy<C>>) {}

    #[test]
    fn test_unverified_chain_with_policy() {
        let cert = FakeCertificate {
            subject_name: FakeName {
                der_bytes: vec![0x30, 0x10],
            },
            issuer_name: FakeName {
                der_bytes: vec![0x30, 0x20],
            },
            not_before: 1609459200,
            not_after: 1640995200,
            signature_algo: SignatureAlgorithmId::EcdsaP256Sha256,
            signature_bytes: vec![0x30, 0x40],
            tbs_bytes: vec![0x30, 0x50],
            public_key: FakePublicKeyInfo {
                der_bytes: vec![0x30, 0x60],
            },
        };

        let chain = UnverifiedCertificateChain::new(vec![cert]);
        let mut policy = AlwaysMeetsPolicy;

        let result = policy.chain_meets_policy_requirements(&chain);
        assert_eq!(result, Ok(()));
    }
}
