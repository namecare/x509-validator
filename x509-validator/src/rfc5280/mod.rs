pub mod version_policy;
pub mod expiry_policy;
pub mod basic_constraints_policy;
pub mod dns_names;
pub mod ip_constraints;
pub mod uri_constraints;
pub mod name_constraints_policy;

pub use version_policy::VersionPolicy;
pub use expiry_policy::ExpiryPolicy;
pub use basic_constraints_policy::BasicConstraintsPolicy;
pub use name_constraints_policy::NameConstraintsPolicy;

use x509_validator_core::{CertificateView, Oid, Timestamp};
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use crate::{VerifierPolicy, PolicyEvaluationResult};

/// Composes VersionPolicy + ExpiryPolicy + BasicConstraintsPolicy +
/// NameConstraintsPolicy via plain field composition (not a macro).
/// Claims basicConstraints, nameConstraints, and keyUsage OIDs — keyUsage
/// is claimed but deliberately unenforced (see BasicConstraintsPolicy).
pub struct RFC5280Policy {
    version_policy: VersionPolicy,
    expiry_policy: Option<ExpiryPolicy>,
    basic_constraints_policy: BasicConstraintsPolicy,
    name_constraints_policy: NameConstraintsPolicy,
}

impl RFC5280Policy {
    pub fn new(now: Timestamp) -> Self {
        Self {
            version_policy: VersionPolicy,
            expiry_policy: Some(ExpiryPolicy::new(now)),
            basic_constraints_policy: BasicConstraintsPolicy,
            name_constraints_policy: NameConstraintsPolicy,
        }
    }

    /// A variant that skips expiry checking entirely — useful for testing
    /// against fixed historical certificates without needing a matching
    /// fixed validation time for every other check too.
    pub fn with_validity_check_disabled() -> Self {
        Self {
            version_policy: VersionPolicy,
            expiry_policy: None,
            basic_constraints_policy: BasicConstraintsPolicy,
            name_constraints_policy: NameConstraintsPolicy,
        }
    }
}

impl<C: CertificateView> VerifierPolicy<C> for RFC5280Policy {
    fn verifying_critical_extensions(&self) -> Vec<Oid> {
        let mut oids = <VersionPolicy as VerifierPolicy<C>>::verifying_critical_extensions(&self.version_policy);
        oids.extend(<BasicConstraintsPolicy as VerifierPolicy<C>>::verifying_critical_extensions(&self.basic_constraints_policy));
        oids.extend(<NameConstraintsPolicy as VerifierPolicy<C>>::verifying_critical_extensions(&self.name_constraints_policy));
        oids.push(key_usage_oid()); // claimed but unenforced, see module docs above
        oids
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain<C>) -> PolicyEvaluationResult {
        VerifierPolicy::<C>::chain_meets_policy_requirements(&mut self.version_policy, chain)?;
        if let Some(expiry) = &mut self.expiry_policy {
            expiry.chain_meets_policy_requirements(chain)?;
        }
        self.basic_constraints_policy.chain_meets_policy_requirements(chain)?;
        self.name_constraints_policy.chain_meets_policy_requirements(chain)?;
        Ok(())
    }
}

/// id-ce-keyUsage, RFC 5280 §4.2.1.3: 2.5.29.15. Claimed here but
/// deliberately unenforced — see BasicConstraintsPolicy's module docs.
fn key_usage_oid() -> Oid {
    Oid(vec![0x55, 0x1D, 0x0F])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyFailureReason;
    use x509_validator_core::{
        AuthorityKeyIdentifier, BasicConstraints, ExtensionsView, GeneralNameKind, NameConstraints,
        NameView, PublicKeyInfoView, SignatureAlgorithmId, SubjectKeyIdentifier,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeName {
        der: Vec<u8>,
        names: Vec<(GeneralNameKind, Vec<u8>)>,
    }

    impl NameView for FakeName {
        fn general_names(&self) -> Vec<(GeneralNameKind, Vec<u8>)> {
            self.names.clone()
        }
        fn canonical_der(&self) -> &[u8] {
            &self.der
        }
        fn common_name(&self) -> Option<Vec<u8>> {
            None
        }
    }

    #[derive(Debug, Clone, Default)]
    struct FakeExtensions {
        basic_constraints: Option<(bool, Option<u32>)>,
        name_constraints: Option<(Vec<(GeneralNameKind, Vec<u8>)>, Vec<(GeneralNameKind, Vec<u8>)>)>,
    }

    impl ExtensionsView for FakeExtensions {
        type Error = std::io::Error;

        fn oids(&self) -> Vec<(Oid, bool)> {
            vec![]
        }
        fn bytes_for(&self, _oid: &Oid) -> Option<&[u8]> {
            None
        }
        fn basic_constraints(&self) -> Result<Option<BasicConstraints>, Self::Error> {
            Ok(self.basic_constraints.map(|(is_ca, max_path_length)| BasicConstraints {
                is_ca,
                max_path_length,
            }))
        }
        fn name_constraints(&self) -> Result<Option<NameConstraints>, Self::Error> {
            Ok(self.name_constraints.clone().map(|(permitted, excluded)| NameConstraints {
                permitted_subtrees: permitted,
                excluded_subtrees: excluded,
            }))
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
        not_before: Timestamp,
        not_after: Timestamp,
        extensions: FakeExtensions,
        public_key: FakePublicKeyInfo,
    }

    impl PartialEq for FakeCertificate {
        fn eq(&self, other: &Self) -> bool {
            self.subject == other.subject && self.issuer == other.issuer && self.public_key == other.public_key
        }
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
            self.not_before
        }
        fn not_after(&self) -> Timestamp {
            self.not_after
        }
        fn extensions(&self) -> &Self::Extensions {
            &self.extensions
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

    /// A certificate that passes VersionPolicy (v3 with extensions),
    /// ExpiryPolicy (valid 1000..2000) and BasicConstraintsPolicy.
    fn good_cert(subject: &str, issuer: &str, is_ca: bool, names: Vec<(GeneralNameKind, Vec<u8>)>) -> FakeCertificate {
        FakeCertificate {
            subject: FakeName {
                der: subject.as_bytes().to_vec(),
                names,
            },
            issuer: FakeName {
                der: issuer.as_bytes().to_vec(),
                names: vec![],
            },
            is_v1: false,
            has_extensions: true,
            not_before: 1000,
            not_after: 2000,
            extensions: FakeExtensions {
                basic_constraints: if is_ca { Some((true, None)) } else { None },
                name_constraints: None,
            },
            public_key: FakePublicKeyInfo(format!("{subject}-key").into_bytes()),
        }
    }

    fn dns(name: &str) -> (GeneralNameKind, Vec<u8>) {
        (GeneralNameKind::DnsName, name.as_bytes().to_vec())
    }

    fn chain_of(certs: Vec<FakeCertificate>) -> UnverifiedCertificateChain<FakeCertificate> {
        UnverifiedCertificateChain::new(certs)
    }

    #[test]
    fn chain_passing_all_sub_policies_is_accepted() {
        let leaf = good_cert("leaf", "root", false, vec![dns("www.example.com")]);
        let root = good_cert("root", "root", true, vec![]);
        let chain = chain_of(vec![leaf, root]);

        let mut policy = RFC5280Policy::new(1500);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn chain_failing_only_name_constraints_is_rejected() {
        // Identical to the accepted chain above except that the root now
        // excludes the leaf's DNS name — proving NameConstraintsPolicy is
        // genuinely wired into the composition.
        let leaf = good_cert("leaf", "root", false, vec![dns("www.example.com")]);
        let mut root = good_cert("root", "root", true, vec![]);
        root.extensions.name_constraints = Some((vec![], vec![dns("example.com")]));
        let chain = chain_of(vec![leaf, root]);

        let mut policy = RFC5280Policy::new(1500);
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("name is in an excluded subtree")
        );
    }

    #[test]
    fn chain_failing_only_basic_constraints_is_rejected() {
        let leaf = good_cert("leaf", "root", false, vec![]);
        let root = good_cert("root", "root", false, vec![]);
        let chain = chain_of(vec![leaf, root]);

        let mut policy = RFC5280Policy::new(1500);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn chain_failing_only_expiry_is_rejected() {
        let leaf = good_cert("leaf", "root", false, vec![]);
        let root = good_cert("root", "root", true, vec![]);
        let chain = chain_of(vec![leaf, root]);

        let mut policy = RFC5280Policy::new(9999);
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("certificate has expired")
        );
    }

    #[test]
    fn with_validity_check_disabled_accepts_an_expired_chain() {
        let leaf = good_cert("leaf", "root", false, vec![]);
        let root = good_cert("root", "root", true, vec![]);
        let chain = chain_of(vec![leaf, root]);

        // The same chain at the same "now" is rejected with expiry enabled.
        let mut enabled = RFC5280Policy::new(9999);
        assert!(enabled.chain_meets_policy_requirements(&chain).is_err());

        let mut disabled = RFC5280Policy::with_validity_check_disabled();
        assert_eq!(disabled.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn with_validity_check_disabled_still_enforces_the_other_policies() {
        let leaf = good_cert("leaf", "root", false, vec![dns("www.example.com")]);
        let mut root = good_cert("root", "root", true, vec![]);
        root.extensions.name_constraints = Some((vec![], vec![dns("example.com")]));
        let chain = chain_of(vec![leaf, root]);

        let mut policy = RFC5280Policy::with_validity_check_disabled();
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("name is in an excluded subtree")
        );
    }

    #[test]
    fn verifying_critical_extensions_includes_all_three_oids() {
        let policy = RFC5280Policy::new(1500);
        let oids = <RFC5280Policy as VerifierPolicy<FakeCertificate>>::verifying_critical_extensions(&policy);

        let basic_constraints = Oid(vec![0x55, 0x1D, 0x13]);
        let name_constraints = Oid(vec![0x55, 0x1D, 0x1E]);
        let key_usage = Oid(vec![0x55, 0x1D, 0x0F]);

        assert!(oids.contains(&basic_constraints), "missing basicConstraints OID");
        assert!(oids.contains(&name_constraints), "missing nameConstraints OID");
        assert!(oids.contains(&key_usage), "missing keyUsage OID");
    }
}
