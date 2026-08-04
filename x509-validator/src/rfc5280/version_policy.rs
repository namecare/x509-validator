use x509_validator_core::{CertificateView, Oid};
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use crate::policy::{VerifierPolicy, PolicyEvaluationResult, PolicyFailureReason};

/// A sub-policy of `RFC5280Policy` that polices that version 1 certificates
/// do not contain extensions.
pub struct VersionPolicy;

impl<C: CertificateView> VerifierPolicy<C> for VersionPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid> {
        vec![]
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain<C>) -> PolicyEvaluationResult {
        for certificate in chain.iter() {
            if certificate.is_v1() && certificate.has_extensions() {
                return Err(PolicyFailureReason::new(format!(
                    "version 1 certificate contains extensions but should not: {:?}",
                    certificate
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_validator_core::{ExtensionsView, GeneralNameKind, NameView, PublicKeyInfoView, SignatureAlgorithmId, Timestamp};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeName {
        der: Vec<u8>,
    }

    impl NameView for FakeName {
        fn general_names(&self) -> Vec<(GeneralNameKind, Vec<u8>)> {
            vec![]
        }
        fn canonical_der(&self) -> &[u8] {
            &self.der
        }
        fn common_name(&self) -> Option<Vec<u8>> {
            None
        }
    }

    #[derive(Debug, Clone, Default)]
    struct FakeExtensions;

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

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakePublicKeyInfo(Vec<u8>);

    impl PublicKeyInfoView for FakePublicKeyInfo {
        fn subject_public_key_info_der(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Debug, Clone)]
    struct FakeCertificate {
        subject: FakeName,
        issuer: FakeName,
        is_v1: bool,
        has_extensions: bool,
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
            &self.subject
        }
        fn issuer(&self) -> &Self::Name {
            &self.issuer
        }
        fn is_v1(&self) -> bool {
            self.is_v1
        }
        fn has_extensions(&self) -> bool {
            self.has_extensions
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

    fn cert(is_v1: bool, has_extensions: bool) -> FakeCertificate {
        FakeCertificate {
            subject: FakeName { der: b"subject".to_vec() },
            issuer: FakeName { der: b"issuer".to_vec() },
            is_v1,
            has_extensions,
            public_key: FakePublicKeyInfo(b"key".to_vec()),
        }
    }

    #[test]
    fn v1_certificate_without_extensions_is_accepted() {
        let chain = UnverifiedCertificateChain::new(vec![cert(true, false)]);
        let mut policy = VersionPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn v3_certificate_with_extensions_is_accepted() {
        let chain = UnverifiedCertificateChain::new(vec![cert(false, true)]);
        let mut policy = VersionPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn v1_certificate_with_extensions_is_rejected() {
        let chain = UnverifiedCertificateChain::new(vec![cert(true, true)]);
        let mut policy = VersionPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn one_bad_certificate_in_a_chain_fails_the_whole_chain() {
        let chain = UnverifiedCertificateChain::new(vec![cert(false, true), cert(true, true)]);
        let mut policy = VersionPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }
}
