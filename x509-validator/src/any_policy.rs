use crate::der_parser::Oid;
use crate::policy::{PolicyEvaluationResult, ValidationPolicy};
use crate::unverified_chain::UnverifiedCertificateChain;

/// [`AnyPolicy`] can be used to erase the concrete type of some [`ValidationPolicy`].
/// Only use [`AnyPolicy`] if type erasure is necessary.
/// Instead try to use conditional inclusion of different policies through their concrete types.
///
/// Use [`AnyPolicy`] at the top level during construction of a validator to get a validator of type
pub struct AnyPolicy {
    policy: Box<dyn ValidationPolicy>,
}

impl AnyPolicy {
    /// Erases the type of some [`ValidationPolicy`] to [`AnyPolicy`].
    /// - Parameter policy: the concrete [`ValidationPolicy`]
    pub fn new(policy: impl ValidationPolicy + 'static) -> Self {
        Self {
            policy: Box::new(policy),
        }
    }
}

impl ValidationPolicy for AnyPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        self.policy
            .verifying_critical_extensions()
    }

    fn chain_meets_policy_requirements(
        &self,
        chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        self.policy
            .chain_meets_policy_requirements(chain)
    }
}

#[cfg(test)]
mod tests {
    use x509_validator_testkit::{cert, self_signed_ca};

    use super::*;
    use crate::oid_registry::{
        OID_X509_EXT_BASIC_CONSTRAINTS, OID_X509_EXT_KEY_USAGE, OID_X509_EXT_NAME_CONSTRAINTS,
    };
    use crate::policy::PolicyFailureReason;

    struct StubPolicy {
        extensions: Vec<Oid<'static>>,
        result: PolicyEvaluationResult,
    }

    impl StubPolicy {
        fn meets() -> Self {
            Self {
                extensions: vec![],
                result: Ok(()),
            }
        }

        fn fails(reason: &str) -> Self {
            Self {
                extensions: vec![],
                result: Err(PolicyFailureReason::new(reason)),
            }
        }

        fn verifying(extensions: Vec<Oid<'static>>) -> Self {
            Self {
                extensions,
                result: Ok(()),
            }
        }
    }

    impl ValidationPolicy for StubPolicy {
        fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
            self.extensions.clone()
        }

        fn chain_meets_policy_requirements(
            &self,
            _chain: &UnverifiedCertificateChain<'_>,
        ) -> PolicyEvaluationResult {
            self.result.clone()
        }
    }

    #[test]
    fn erasure_preserves_the_failure_reason_verbatim() {
        let der = self_signed_ca("root");
        let chain = UnverifiedCertificateChain::new(vec![cert(&der)]);

        let policy = AnyPolicy::new(StubPolicy::fails("leaf is not a server certificate"));

        assert_eq!(
            policy.chain_meets_policy_requirements(&chain),
            Err(PolicyFailureReason::new("leaf is not a server certificate"))
        );
    }

    #[test]
    fn erasure_preserves_the_extension_list_and_its_order() {
        let extensions = vec![
            OID_X509_EXT_BASIC_CONSTRAINTS,
            OID_X509_EXT_KEY_USAGE,
            OID_X509_EXT_NAME_CONSTRAINTS,
        ];

        let policy = AnyPolicy::new(StubPolicy::verifying(extensions.clone()));

        assert_eq!(policy.verifying_critical_extensions(), extensions);
    }

    #[test]
    fn erased_policies_of_different_concrete_types_share_one_type() {
        let der = self_signed_ca("root");
        let chain = UnverifiedCertificateChain::new(vec![cert(&der)]);

        // The point of erasure: unrelated policy types become one type, so they can be
        // collected together and chosen between at runtime. Nesting must stay transparent.
        let policies = [
            AnyPolicy::new(StubPolicy::meets()),
            AnyPolicy::new(AnyPolicy::new(StubPolicy::fails("no"))),
        ];

        let results: Vec<_> = policies
            .iter()
            .map(|p| p.chain_meets_policy_requirements(&chain))
            .collect();

        assert_eq!(results, [Ok(()), Err(PolicyFailureReason::new("no"))]);
    }
}
