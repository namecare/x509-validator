use crate::der_parser::Oid;
use crate::policy::{PolicyEvaluationResult, ValidationPolicy};
use crate::unverified_chain::UnverifiedCertificateChain;

/// Use this to build a policy where all of the sub-policies must be met for the overall policy to be met.
/// This is only useful within a [`OneOfPolicies`] block, because at the top-level, it is already required for all
/// policies to be met, so adding this at the top-level is redundant.
/// For example, the following policy requires that `RFC5280Policy` is always met, and then either policy C is met, or
/// A and B are both met. If A and B are both met, then C does not have to be met. If C is met, then neither A nor B
/// need to be met.
///
/// ```ignore
/// let policy = x509_validator::policy! {
///     RFC5280Policy::new(validation_time);
///     PolicyA::new()
/// };
/// ```
///
/// Compose multiple policies with the [`policy!`] macro, which builds the appropriate nested
/// [`Tuple2`](crate::policy_builder::Tuple2) chain to pass here.
///
/// [`OneOfPolicies`]: crate::one_of_policies::OneOfPolicies
/// [`policy!`]: crate::policy!
pub struct AllOfPolicies<P> {
    policy: P,
}

impl<P> AllOfPolicies<P> {
    pub fn new(policy: P) -> Self {
        Self { policy }
    }
}

impl<P: ValidationPolicy> ValidationPolicy for AllOfPolicies<P> {
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
