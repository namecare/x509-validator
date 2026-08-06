use crate::{VerifierPolicy, PolicyEvaluationResult, PolicyFailureReason};
use x509_validator_core::der_parser::Oid;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

pub type Timestamp = i64;

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

impl VerifierPolicy for ExpiryPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![]
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
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
                return Err(PolicyFailureReason::new(format!("certificate {:?} is not yet valid", cert)));
            }

            if self.validation_time > not_after {
                return Err(PolicyFailureReason::new("certificate has expired"));
            }
        }

        Ok(())
    }
}