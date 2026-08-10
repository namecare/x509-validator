use crate::policy::{PolicyEvaluationResult, PolicyFailureReason, ValidationPolicy};
use crate::der_parser::Oid;
use crate::unverified_chain::UnverifiedCertificateChain;
use crate::x509::X509Version;

/// A sub-policy of the [`RFC5280Policy`] that polices that version 1 certificates do not contain extensions.
///
/// [`RFC5280Policy`]: crate::rfc5280::RFC5280Policy
pub struct VersionPolicy;

impl ValidationPolicy for VersionPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![]
    }

    fn chain_meets_policy_requirements(&self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        for certificate in chain.iter() {
            let is_v1 = certificate.tbs_certificate.version == X509Version::V1;
            let has_extensions = !certificate.tbs_certificate.extensions().is_empty();
            if is_v1 && has_extensions {
                return Err(PolicyFailureReason::new(format!(
                    "version 1 certificate contains extensions but should not: {:?}",
                    certificate
                )));
            }
        }
        Ok(())
    }
}