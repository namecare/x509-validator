//! Policy trait composition and object safety.

use x509_validator::oid_registry::{
    OID_X509_EXT_BASIC_CONSTRAINTS, OID_X509_EXT_KEY_USAGE, OID_X509_EXT_NAME_CONSTRAINTS,
};
use x509_validator::unverified_chain::UnverifiedCertificateChain;
use x509_validator::{Oid, PolicyEvaluationResult, ValidationPolicy, PolicyFailureReason};
use x509_validator_testkit::{chain_of, self_signed_ca};
use x509_validator::policy_builder::{Tuple2, Either, WrappedOptional, OneOfTuple2, OneOfWrappedOptional};
use x509_validator::{policy, one_of};

struct AlwaysMeetsPolicy;

impl ValidationPolicy for AlwaysMeetsPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![]
    }
    fn chain_meets_policy_requirements(&self, _chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        Ok(())
    }
}

struct AlwaysFailsPolicy;

impl ValidationPolicy for AlwaysFailsPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![]
    }
    fn chain_meets_policy_requirements(&self, _chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        Err(PolicyFailureReason::new("always fails"))
    }
}

struct PolicyWithExtensions {
    extensions: Vec<Oid<'static>>,
    meets_policy: bool,
}

impl PolicyWithExtensions {
    fn meets(extensions: Vec<Oid<'static>>) -> Self {
        Self { extensions, meets_policy: true }
    }
    #[allow(dead_code)]
    fn fails(extensions: Vec<Oid<'static>>) -> Self {
        Self { extensions, meets_policy: false }
    }
}

impl ValidationPolicy for PolicyWithExtensions {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        self.extensions.clone()
    }
    fn chain_meets_policy_requirements(&self, _chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        if self.meets_policy {
            Ok(())
        } else {
            Err(PolicyFailureReason::new("PolicyWithExtensions configured to fail"))
        }
    }
}

// Compile-only proof that ValidationPolicy is usable as a trait object.
fn _assert_object_safe(_: Box<dyn ValidationPolicy>) {}

#[test]
fn test_unverified_chain_with_policy() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy = AlwaysMeetsPolicy;

    let result = policy.chain_meets_policy_requirements(&chain);
    assert_eq!(result, Ok(()));
}

#[test]
fn tuple2_passes_when_both_policies_pass() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy = Tuple2::new(AlwaysMeetsPolicy, AlwaysMeetsPolicy);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn tuple2_fails_when_first_policy_fails() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy = Tuple2::new(AlwaysFailsPolicy, AlwaysMeetsPolicy);
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn tuple2_fails_when_second_policy_fails() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy = Tuple2::new(AlwaysMeetsPolicy, AlwaysFailsPolicy);
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn either_first_variant_evaluates_first_policy() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy: Either<AlwaysMeetsPolicy, AlwaysFailsPolicy> = Either::First(AlwaysMeetsPolicy);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn either_second_variant_evaluates_second_policy() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy: Either<AlwaysFailsPolicy, AlwaysMeetsPolicy> = Either::Second(AlwaysMeetsPolicy);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn either_does_not_evaluate_the_inactive_variant() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    // First is AlwaysFailsPolicy but inactive (Second variant chosen) — overall must pass.
    let policy: Either<AlwaysFailsPolicy, AlwaysMeetsPolicy> = Either::Second(AlwaysMeetsPolicy);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn wrapped_optional_none_auto_passes() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy: WrappedOptional<AlwaysFailsPolicy> = WrappedOptional::new(None);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn wrapped_optional_some_delegates_to_inner_policy() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy = WrappedOptional::new(Some(AlwaysFailsPolicy));
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn all_of_policies_wraps_a_single_policy() {
    use x509_validator::AllOfPolicies;
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy = AllOfPolicies::new(AlwaysMeetsPolicy);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn all_of_policies_wraps_a_tuple2_chain() {
    use x509_validator::AllOfPolicies;
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy = AllOfPolicies::new(Tuple2::new(AlwaysMeetsPolicy, AlwaysFailsPolicy));
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn one_of_policies_wraps_a_single_policy() {
    use x509_validator::OneOfPolicies;
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy = OneOfPolicies::new(AlwaysMeetsPolicy);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn one_of_policies_wraps_an_either_choice() {
    use x509_validator::OneOfPolicies;
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy: OneOfPolicies<Either<AlwaysFailsPolicy, AlwaysMeetsPolicy>> =
        OneOfPolicies::new(Either::Second(AlwaysMeetsPolicy));
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn one_of_policies_fails_when_the_active_either_arm_fails() {
    use x509_validator::OneOfPolicies;
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy: OneOfPolicies<Either<AlwaysFailsPolicy, AlwaysMeetsPolicy>> =
        OneOfPolicies::new(Either::First(AlwaysFailsPolicy));
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn policy_macro_single_expression_has_no_wrapper() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let built = policy! { AlwaysMeetsPolicy };
    assert_eq!(built.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn policy_macro_flat_sequence_is_an_and_chain() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let built = policy! {
        AlwaysMeetsPolicy;
        AlwaysMeetsPolicy;
        AlwaysMeetsPolicy
    };
    assert_eq!(built.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn policy_macro_flat_sequence_fails_if_any_member_fails() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let built = policy! {
        AlwaysMeetsPolicy;
        AlwaysFailsPolicy;
        AlwaysMeetsPolicy
    };
    assert!(built.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn policy_macro_if_else_picks_the_true_branch() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let cond = true;
    let built = policy! {
        if (cond) {
            AlwaysMeetsPolicy
        } else {
            AlwaysFailsPolicy
        }
    };
    assert_eq!(built.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn policy_macro_if_else_picks_the_false_branch() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let cond = false;
    let built = policy! {
        if (cond) {
            AlwaysFailsPolicy
        } else {
            AlwaysMeetsPolicy
        }
    };
    assert_eq!(built.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn policy_macro_bare_if_true_evaluates_inner_policy() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let cond = true;
    let built = policy! {
        if (cond) {
            AlwaysFailsPolicy
        }
    };
    assert!(built.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn policy_macro_bare_if_false_auto_passes() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let cond = false;
    let built = policy! {
        if (cond) {
            AlwaysFailsPolicy
        }
    };
    assert_eq!(built.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn policy_macro_mixes_sequence_and_conditional() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let online = true;
    let built = policy! {
        AlwaysMeetsPolicy;
        if (online) {
            AlwaysMeetsPolicy
        }
    };
    assert_eq!(built.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn policy_macro_mixes_sequence_and_if_else() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let online = false;
    let built = policy! {
        AlwaysMeetsPolicy;
        if (online) {
            AlwaysFailsPolicy
        } else {
            AlwaysMeetsPolicy
        };
        AlwaysMeetsPolicy
    };
    assert_eq!(built.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn one_of_tuple2_tries_first_before_second() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy = OneOfTuple2::new(AlwaysMeetsPolicy, AlwaysFailsPolicy);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn one_of_tuple2_falls_back_to_second_on_first_failure() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy = OneOfTuple2::new(AlwaysFailsPolicy, AlwaysMeetsPolicy);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn one_of_tuple2_fails_with_joined_reason_when_both_fail() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy = OneOfTuple2::new(AlwaysFailsPolicy, AlwaysFailsPolicy);
    let result = policy.chain_meets_policy_requirements(&chain);
    let err = result.expect_err("both alternatives fail");
    assert!(err.to_string().contains("and"), "expected joined failure reason, got: {err}");
}

#[test]
fn one_of_tuple2_extensions_are_intersection_not_union() {
    let first = PolicyWithExtensions::meets(vec![OID_X509_EXT_KEY_USAGE, OID_X509_EXT_BASIC_CONSTRAINTS]);
    let second = PolicyWithExtensions::meets(vec![OID_X509_EXT_BASIC_CONSTRAINTS, OID_X509_EXT_NAME_CONSTRAINTS]);
    let policy = OneOfTuple2::new(first, second);
    assert_eq!(policy.verifying_critical_extensions(), vec![OID_X509_EXT_BASIC_CONSTRAINTS]);
}

#[test]
fn one_of_wrapped_optional_none_fails() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let policy: OneOfWrappedOptional<AlwaysMeetsPolicy> = OneOfWrappedOptional::new(None);
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn one_of_macro_tries_alternatives_in_order() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let built = one_of! {
        AlwaysFailsPolicy;
        AlwaysMeetsPolicy
    };
    assert_eq!(built.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn one_of_macro_if_else_uses_either() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let cond = true;
    let built = one_of! {
        if (cond) {
            AlwaysMeetsPolicy
        } else {
            AlwaysFailsPolicy
        }
    };
    assert_eq!(built.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn one_of_macro_bare_if_false_fails_not_auto_passes() {
    let chain = chain_of(vec![self_signed_ca("root")]);
    let cond = false;
    let built = one_of! {
        if (cond) {
            AlwaysMeetsPolicy
        }
    };
    assert!(built.chain_meets_policy_requirements(&chain).is_err());
}
