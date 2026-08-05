pub mod version_policy;
pub mod expiry_policy;
pub mod basic_constraints_policy;
pub mod dns_names;
pub mod ip_constraints;
pub mod uri_constraints;
pub mod name_constraints_policy;

pub use version_policy::VersionPolicy;
pub use expiry_policy::{ExpiryPolicy, Timestamp};
pub use basic_constraints_policy::BasicConstraintsPolicy;
pub use name_constraints_policy::NameConstraintsPolicy;

use crate::{VerifierPolicy, PolicyEvaluationResult};
use x509_parser::der_parser::Oid;
use x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

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

impl VerifierPolicy for RFC5280Policy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        let mut oids = self.version_policy.verifying_critical_extensions();
        oids.extend(self.basic_constraints_policy.verifying_critical_extensions());
        oids.extend(self.name_constraints_policy.verifying_critical_extensions());
        oids.push(key_usage_oid()); // claimed but unenforced, see module docs above
        oids
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        self.version_policy.chain_meets_policy_requirements(chain)?;
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
fn key_usage_oid() -> Oid<'static> {
    OID_X509_EXT_KEY_USAGE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{dns_subtree, issue_leaf, name_constraints, self_signed_ca_with};
    use crate::PolicyFailureReason;
    use rcgen::CertificateParams;
    use time::{Duration, OffsetDateTime};
    use x509_parser::prelude::FromDer;
    use x509_validator_core::Certificate;
    use x509_parser::oid_registry::{OID_X509_EXT_BASIC_CONSTRAINTS, OID_X509_EXT_NAME_CONSTRAINTS};

    fn chain_of(ders: Vec<Vec<u8>>) -> UnverifiedCertificateChain<'static> {
        let certs = ders
            .into_iter()
            .map(|der| {
                let der: &'static [u8] = Box::leak(der.into_boxed_slice());
                Certificate::from_der(der).unwrap().1
            })
            .collect();
        UnverifiedCertificateChain::new(certs)
    }

    fn with_validity(not_before: Timestamp, not_after: Timestamp) -> impl FnOnce(&mut CertificateParams) {
        move |params: &mut CertificateParams| {
            params.not_before = OffsetDateTime::UNIX_EPOCH + Duration::seconds(not_before);
            params.not_after = OffsetDateTime::UNIX_EPOCH + Duration::seconds(not_after);
        }
    }

    #[test]
    fn chain_passing_all_sub_policies_is_accepted() {
        let root = self_signed_ca_with("root", with_validity(1000, 2000));
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let chain = chain_of(vec![leaf, root.der]);

        let mut policy = RFC5280Policy::new(1500);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn chain_failing_only_name_constraints_is_rejected() {
        // Identical to the accepted chain above except that the root now
        // excludes the leaf's DNS name — proving NameConstraintsPolicy is
        // genuinely wired into the composition.
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            with_validity(1000, 2000)(params);
            params.name_constraints = Some(name_constraints(vec![], vec![dns_subtree("example.com")]));
        });
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let chain = chain_of(vec![leaf, root.der]);

        let mut policy = RFC5280Policy::new(1500);
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("name is in an excluded subtree")
        );
    }

    #[test]
    fn chain_failing_only_basic_constraints_is_rejected() {
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            with_validity(1000, 2000)(params);
            params.is_ca = rcgen::IsCa::NoCa;
        });
        let leaf = issue_leaf("leaf", &[], &root);
        let chain = chain_of(vec![leaf, root.der]);

        let mut policy = RFC5280Policy::new(1500);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn chain_failing_only_expiry_is_rejected() {
        let root = self_signed_ca_with("root", with_validity(1000, 2000));
        let leaf = issue_leaf("leaf", &[], &root);
        let chain = chain_of(vec![leaf, root.der]);

        let mut policy = RFC5280Policy::new(9999);
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("certificate has expired")
        );
    }

    #[test]
    fn with_validity_check_disabled_accepts_an_expired_chain() {
        let root = self_signed_ca_with("root", with_validity(1000, 2000));
        let leaf = issue_leaf("leaf", &[], &root);
        let chain = chain_of(vec![leaf, root.der]);

        // The same chain at the same "now" is rejected with expiry enabled.
        let mut enabled = RFC5280Policy::new(9999);
        assert!(enabled.chain_meets_policy_requirements(&chain).is_err());

        let root2 = self_signed_ca_with("root", with_validity(1000, 2000));
        let leaf2 = issue_leaf("leaf", &[], &root2);
        let chain2 = chain_of(vec![leaf2, root2.der]);
        let mut disabled = RFC5280Policy::with_validity_check_disabled();
        assert_eq!(disabled.chain_meets_policy_requirements(&chain2), Ok(()));
    }

    #[test]
    fn with_validity_check_disabled_still_enforces_the_other_policies() {
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            with_validity(1000, 2000)(params);
            params.name_constraints = Some(name_constraints(vec![], vec![dns_subtree("example.com")]));
        });
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let chain = chain_of(vec![leaf, root.der]);

        let mut policy = RFC5280Policy::with_validity_check_disabled();
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("name is in an excluded subtree")
        );
    }

    #[test]
    fn verifying_critical_extensions_includes_all_three_oids() {
        let policy = RFC5280Policy::new(1500);
        let oids = policy.verifying_critical_extensions();

        assert!(oids.contains(&OID_X509_EXT_BASIC_CONSTRAINTS), "missing basicConstraints OID");
        assert!(oids.contains(&OID_X509_EXT_NAME_CONSTRAINTS), "missing nameConstraints OID");
        assert!(oids.contains(&key_usage_oid()), "missing keyUsage OID");
    }
}