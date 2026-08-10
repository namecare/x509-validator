use crate::der_parser::Oid;
use crate::unverified_chain::UnverifiedCertificateChain;
use crate::{PolicyEvaluationResult, PolicyFailureReason, ValidationPolicy};

pub type Timestamp = i64;

/// A sub-policy of the [`RFC5280Policy`] that polices expiry.
///
/// [`RFC5280Policy`]: crate::rfc5280::RFC5280Policy
pub struct ExpiryPolicy {
    validation_time: Timestamp,
}

impl ExpiryPolicy {
    /// Creates an instance with a *fixed* expiry validation time.
    ///
    /// - Parameter validation_time: The *fixed* time to compare against when determining if the certificates in the
    ///   chain have expired.
    pub fn new(validation_time: Timestamp) -> Self {
        Self { validation_time }
    }
}

impl ValidationPolicy for ExpiryPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![]
    }

    fn chain_meets_policy_requirements(
        &self,
        chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        // This is an easy check: confirm all the certs are valid.
        //
        // Note that we do this computation on the TBSCertificate Validity struct, not the public date fields. This is
        // to avoid expensive repeated transformations into date fields.
        for cert in chain.iter() {
            let validity = cert.tbs_certificate.validity();
            let not_before = validity.not_before.timestamp();
            let not_after = validity.not_after.timestamp();

            if not_before > not_after {
                return Err(PolicyFailureReason::new(format!(
                    "certificate {:?} has invalid expiry, not_after is earlier than not_before",
                    cert
                )));
            }

            if self.validation_time < not_before {
                return Err(PolicyFailureReason::new(format!(
                    "certificate {:?} is not yet valid",
                    cert
                )));
            }

            if self.validation_time > not_after {
                return Err(PolicyFailureReason::new("certificate has expired"));
            }
        }

        Ok(())
    }
}
