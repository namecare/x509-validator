use crate::{VerifierPolicy, PolicyEvaluationResult, PolicyFailureReason};
use x509_parser::der_parser::Oid;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::self_signed_ca_with;
    use rcgen::CertificateParams;
    use time::{Duration, OffsetDateTime};
    use x509_parser::prelude::FromDer;
    use x509_validator_core::Certificate;

    fn cert_with_validity(not_before: Timestamp, not_after: Timestamp) -> Vec<u8> {
        self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.not_before = OffsetDateTime::UNIX_EPOCH + Duration::seconds(not_before);
            params.not_after = OffsetDateTime::UNIX_EPOCH + Duration::seconds(not_after);
        })
        .der
    }

    fn chain_of(der: Vec<u8>) -> UnverifiedCertificateChain<'static> {
        let der: &'static [u8] = Box::leak(der.into_boxed_slice());
        let cert = Certificate::from_der(der).unwrap().1;
        UnverifiedCertificateChain::new(vec![cert])
    }

    #[test]
    fn certificate_within_validity_window_is_accepted() {
        let chain = chain_of(cert_with_validity(1000, 2000));
        let mut policy = ExpiryPolicy::new(1500);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn certificate_exactly_at_not_before_is_accepted() {
        let chain = chain_of(cert_with_validity(1000, 2000));
        let mut policy = ExpiryPolicy::new(1000);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn certificate_exactly_at_not_after_is_accepted() {
        let chain = chain_of(cert_with_validity(1000, 2000));
        let mut policy = ExpiryPolicy::new(2000);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn certificate_not_yet_valid_is_rejected() {
        let chain = chain_of(cert_with_validity(1000, 2000));
        let mut policy = ExpiryPolicy::new(500);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn expired_certificate_is_rejected() {
        let chain = chain_of(cert_with_validity(1000, 2000));
        let mut policy = ExpiryPolicy::new(2500);
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("certificate has expired")
        );
    }
}