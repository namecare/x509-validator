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
use x509_validator_core::der_parser::Oid;
use x509_validator_core::oid_registry::OID_X509_EXT_KEY_USAGE;
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