use x509_validator_core::{CertificateView, Oid, Timestamp};
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use crate::{VerifierPolicy, PolicyEvaluationResult, PolicyFailureReason};

/// A sub-policy of `RFC5280Policy` that polices expiry against a fixed
/// validation time, chosen at construction time (this crate has no
/// dependency on a system clock, so "now" must always be supplied by the
/// caller rather than sampled internally).
pub struct ExpiryPolicy {
    validation_time: Timestamp,
}

impl ExpiryPolicy {
    pub fn new(validation_time: Timestamp) -> Self {
        Self { validation_time }
    }
}

impl<C: CertificateView> VerifierPolicy<C> for ExpiryPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid> {
        vec![]
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain<C>) -> PolicyEvaluationResult {
        for cert in chain.iter() {
            let not_before = cert.not_before();
            let not_after = cert.not_after();

            if not_before > not_after {
                return Err(PolicyFailureReason::new(format!(
                    "certificate {:?} has invalid expiry, not_after is earlier than not_before",
                    cert
                )));
            }

            if self.validation_time < not_before {
                return Err(PolicyFailureReason::new(format!("certificate {:?} is not yet valid", cert)));
            }

            if self.validation_time > not_after {
                return Err(PolicyFailureReason::new("certificate has expired"));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_validator_core::{ExtensionsView, GeneralNameKind, NameView, PublicKeyInfoView, SignatureAlgorithmId};

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
        not_before: Timestamp,
        not_after: Timestamp,
        public_key: FakePublicKeyInfo,
    }

    impl CertificateView for FakeCertificate {
        type Name = FakeName;
        type Extensions = FakeExtensions;
        type PublicKeyInfo = FakePublicKeyInfo;

        fn subject(&self) -> &Self::Name {
            &self.subject
        }
        fn issuer(&self) -> &Self::Name {
            &self.issuer
        }
        fn is_v1(&self) -> bool {
            false
        }
        fn has_extensions(&self) -> bool {
            true
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
            SignatureAlgorithmId::EcdsaP256Sha256
        }
        fn signature(&self) -> &[u8] {
            &[]
        }
        fn tbs_der(&self) -> &[u8] {
            &[]
        }
    }

    fn cert(not_before: Timestamp, not_after: Timestamp) -> FakeCertificate {
        FakeCertificate {
            subject: FakeName { der: b"subject".to_vec() },
            issuer: FakeName { der: b"issuer".to_vec() },
            not_before,
            not_after,
            public_key: FakePublicKeyInfo(b"key".to_vec()),
        }
    }

    #[test]
    fn certificate_within_validity_window_is_accepted() {
        let chain = UnverifiedCertificateChain::new(vec![cert(1000, 2000)]);
        let mut policy = ExpiryPolicy::new(1500);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn certificate_exactly_at_not_before_is_accepted() {
        let chain = UnverifiedCertificateChain::new(vec![cert(1000, 2000)]);
        let mut policy = ExpiryPolicy::new(1000);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn certificate_exactly_at_not_after_is_accepted() {
        let chain = UnverifiedCertificateChain::new(vec![cert(1000, 2000)]);
        let mut policy = ExpiryPolicy::new(2000);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn certificate_not_yet_valid_is_rejected() {
        let chain = UnverifiedCertificateChain::new(vec![cert(1000, 2000)]);
        let mut policy = ExpiryPolicy::new(500);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn expired_certificate_is_rejected() {
        let chain = UnverifiedCertificateChain::new(vec![cert(1000, 2000)]);
        let mut policy = ExpiryPolicy::new(2500);
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("certificate has expired")
        );
    }

    #[test]
    fn certificate_with_inverted_validity_window_is_rejected() {
        let chain = UnverifiedCertificateChain::new(vec![cert(2000, 1000)]);
        let mut policy = ExpiryPolicy::new(1500);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }
}
