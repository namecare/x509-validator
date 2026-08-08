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

/// A [`VerifierPolicy`] that implements the core chain verification policies from RFC 5280.
///
/// Almost all verifiers should use this policy as the initial component of their policy set. The policy checks the
/// following things:
///
/// 1. Version. v1 certificates with extensions are rejected.
/// 2. Expiry. Expired certificates are rejected.
/// 3. Basic Constraints. Police the constraints contained in the basicConstraints extension.
/// 4. Name Constraints. Police the constraints contained in the nameConstraints extension.
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
        // The presence of keyUsage here requires some explanation, because this policy doesn't _actually_ compute
        // on it in any way.
        //
        // The unfortunate reality of keyUsage is that, while RFC 5280 requires us to validate it, CAs have historically
        // done a very poor job of actually implementing it. The result is that policing KeyUsage produces minimal value
        // in terms of increased security, but produces a substantial uptick in the number of unbuildable chains. So
        // we _pretend_ to police the key usage, and just...don't.
        oids.push(key_usage_oid());
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

fn key_usage_oid() -> Oid<'static> {
    OID_X509_EXT_KEY_USAGE
}