use crate::PolicyFailureReason;
use crate::der_parser::Oid;
use crate::policy::{PolicyEvaluationResult, ValidationPolicy};
use crate::unverified_chain::UnverifiedCertificateChain;

/// Combines two [`ValidationPolicy`] values so that both must be met for the combination to be met.
/// Built by the [`policy!`] macro when composing a flat sequence of policies; can also be constructed
/// directly for manual, non-macro composition.
///
/// [`policy!`]: crate::policy!
pub struct Tuple2<A, B> {
    first: A,
    second: B,
}

impl<A, B> Tuple2<A, B> {
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

impl<A: ValidationPolicy, B: ValidationPolicy> ValidationPolicy for Tuple2<A, B> {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        let mut exts = self
            .first
            .verifying_critical_extensions();
        exts.extend(
            self.second
                .verifying_critical_extensions(),
        );
        exts
    }

    fn chain_meets_policy_requirements(
        &self,
        chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        self.first
            .chain_meets_policy_requirements(chain)?;
        self.second
            .chain_meets_policy_requirements(chain)
    }
}

/// Chooses between two [`ValidationPolicy`] values at construction time; only the active variant is
/// evaluated. Built by the [`policy!`] macro when composing an `if`/`else` block.
///
/// [`policy!`]: crate::policy!
pub enum Either<A, B> {
    First(A),
    Second(B),
}

impl<A: ValidationPolicy, B: ValidationPolicy> ValidationPolicy for Either<A, B> {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        match self {
            Self::First(a) => a.verifying_critical_extensions(),
            Self::Second(b) => b.verifying_critical_extensions(),
        }
    }

    fn chain_meets_policy_requirements(
        &self,
        chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        match self {
            Self::First(a) => a.chain_meets_policy_requirements(chain),
            Self::Second(b) => b.chain_meets_policy_requirements(chain),
        }
    }
}

/// Wraps an optional [`ValidationPolicy`]; a `None` policy always meets the requirements. Built by the
/// [`policy!`] macro when composing a bare `if` block (no `else`).
///
/// [`policy!`]: crate::policy!
pub struct WrappedOptional<P> {
    wrapped: Option<P>,
}

impl<P> WrappedOptional<P> {
    pub fn new(wrapped: Option<P>) -> Self {
        Self { wrapped }
    }
}

impl<P: ValidationPolicy> ValidationPolicy for WrappedOptional<P> {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        self.wrapped
            .as_ref()
            .map(|p| p.verifying_critical_extensions())
            .unwrap_or_default()
    }

    fn chain_meets_policy_requirements(
        &self,
        chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        match &self.wrapped {
            Some(p) => p.chain_meets_policy_requirements(chain),
            None => Ok(()),
        }
    }
}

/// A DSL for constructing a [`ValidationPolicy`] out of other [`ValidationPolicy`] values, without type
/// erasure.
///
/// A flat, semicolon-separated sequence of policy expressions builds an AND-chain (every listed policy
/// must be met), using nested [`Tuple2`] values:
///
/// ```
/// use x509_validator::policy;
/// use x509_validator::rfc5280::{RFC5280Policy, VersionPolicy};
/// # let validation_time: x509_validator::rfc5280::Timestamp = 0;
///
/// let built = policy! {
///     RFC5280Policy::new(validation_time);
///     VersionPolicy
/// };
/// ```
///
/// [`ValidationPolicy`]: crate::policy::ValidationPolicy
#[macro_export]
macro_rules! policy {
    // `if`/`else`, followed by more items. Must come before the bare-`if` multi-item arm below,
    // since `macro_rules!` tries arms top-to-bottom and a bare-`if` pattern would otherwise
    // greedily match the `if (cond) { .. }` prefix of an `if`/`else` item and leave a dangling
    // `else { .. }` in `$rest`, which then fails to parse recursively.
    (if ($cond:expr) { $then:expr } else { $else_:expr }; $($rest:tt)+) => {
        $crate::policy_builder::Tuple2::new(
            if $cond {
                $crate::policy_builder::Either::First($then)
            } else {
                $crate::policy_builder::Either::Second($else_)
            },
            $crate::policy!($($rest)+),
        )
    };
    // `if`/`else`, sole item.
    (if ($cond:expr) { $then:expr } else { $else_:expr }) => {
        if $cond {
            $crate::policy_builder::Either::First($then)
        } else {
            $crate::policy_builder::Either::Second($else_)
        }
    };
    // Bare `if`, followed by more items.
    (if ($cond:expr) { $body:expr }; $($rest:tt)+) => {
        $crate::policy_builder::Tuple2::new(
            $crate::policy_builder::WrappedOptional::new(if $cond { Some($body) } else { None }),
            $crate::policy!($($rest)+),
        )
    };
    // Bare `if`, sole item.
    (if ($cond:expr) { $body:expr }) => {
        $crate::policy_builder::WrappedOptional::new(if $cond { Some($body) } else { None })
    };
    // Plain expression, followed by more items.
    ($first:expr; $($rest:tt)+) => {
        $crate::policy_builder::Tuple2::new($first, $crate::policy!($($rest)+))
    };
    // Plain expression, sole item.
    ($only:expr) => {
        $only
    };
}

/// Tries `first`; only if it fails, tries `second`. The overall extensions claimed
/// are the intersection of both sub-policies' claims (a critical extension is only
/// "handled" here if BOTH sub-policies would have handled it), deliberately
/// asymmetric with [`Tuple2`], which unions its extensions. Intersection is required
/// here because an extension is only safely ignorable if every alternative would
/// have handled it.
pub struct OneOfTuple2<A, B> {
    first: A,
    second: B,
}

impl<A, B> OneOfTuple2<A, B> {
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

impl<A: ValidationPolicy, B: ValidationPolicy> ValidationPolicy for OneOfTuple2<A, B> {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        let first = self
            .first
            .verifying_critical_extensions();
        let second = self
            .second
            .verifying_critical_extensions();
        first
            .into_iter()
            .filter(|oid| second.contains(oid))
            .collect()
    }

    fn chain_meets_policy_requirements(
        &self,
        chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        match self
            .first
            .chain_meets_policy_requirements(chain)
        {
            Ok(()) => Ok(()),
            Err(first_reason) => match self
                .second
                .chain_meets_policy_requirements(chain)
            {
                Ok(()) => Ok(()),
                Err(second_reason) => Err(PolicyFailureReason::new(format!(
                    "{first_reason} and {second_reason}"
                ))),
            },
        }
    }
}

/// Like [`WrappedOptional`], but a `None` policy FAILS instead of auto-passing:
/// a disabled alternative inside a `one_of!` block should not count as "the one
/// that succeeded."
pub struct OneOfWrappedOptional<P> {
    wrapped: Option<P>,
}

impl<P> OneOfWrappedOptional<P> {
    pub fn new(wrapped: Option<P>) -> Self {
        Self { wrapped }
    }
}

impl<P: ValidationPolicy> ValidationPolicy for OneOfWrappedOptional<P> {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        self.wrapped
            .as_ref()
            .map(|p| p.verifying_critical_extensions())
            .unwrap_or_default()
    }

    fn chain_meets_policy_requirements(
        &self,
        chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        match &self.wrapped {
            Some(p) => p.chain_meets_policy_requirements(chain),
            None => Err(PolicyFailureReason::new("alternative is disabled")),
        }
    }
}

/// A DSL for constructing a [`ValidationPolicy`] out of alternatives, without type erasure.
///
/// A flat, semicolon-separated sequence of policy expressions builds a try-each-until-one-succeeds
/// chain (the first alternative that meets the requirements wins; if every alternative fails, the
/// reported failure reason joins every alternative's reason), using nested [`OneOfTuple2`] values —
/// this is the `one_of!` counterpart to [`policy!`]'s AND-chain.
///
/// ```
/// use x509_validator::one_of;
/// use x509_validator::rfc5280::{RFC5280Policy, VersionPolicy};
/// # let validation_time: x509_validator::rfc5280::Timestamp = 0;
///
/// let built = one_of! {
///     RFC5280Policy::new(validation_time);
///     VersionPolicy
/// };
/// ```
///
/// [`ValidationPolicy`]: crate::policy::ValidationPolicy
#[macro_export]
macro_rules! one_of {
    // `if`/`else`, followed by more items. Must come before the bare-`if` multi-item arm below,
    // since `macro_rules!` tries arms top-to-bottom and a bare-`if` pattern would otherwise
    // greedily match the `if (cond) { .. }` prefix of an `if`/`else` item and leave a dangling
    // `else { .. }` in `$rest`, which then fails to parse recursively.
    (if ($cond:expr) { $then:expr } else { $else_:expr }; $($rest:tt)+) => {
        $crate::policy_builder::OneOfTuple2::new(
            if $cond {
                $crate::policy_builder::Either::First($then)
            } else {
                $crate::policy_builder::Either::Second($else_)
            },
            $crate::one_of!($($rest)+),
        )
    };
    // `if`/`else`, sole item.
    (if ($cond:expr) { $then:expr } else { $else_:expr }) => {
        if $cond {
            $crate::policy_builder::Either::First($then)
        } else {
            $crate::policy_builder::Either::Second($else_)
        }
    };
    // Bare `if`, followed by more items.
    (if ($cond:expr) { $body:expr }; $($rest:tt)+) => {
        $crate::policy_builder::OneOfTuple2::new(
            $crate::policy_builder::OneOfWrappedOptional::new(if $cond { Some($body) } else { None }),
            $crate::one_of!($($rest)+),
        )
    };
    // Bare `if`, sole item.
    (if ($cond:expr) { $body:expr }) => {
        $crate::policy_builder::OneOfWrappedOptional::new(if $cond { Some($body) } else { None })
    };
    // Plain expression, followed by more items.
    ($first:expr; $($rest:tt)+) => {
        $crate::policy_builder::OneOfTuple2::new($first, $crate::one_of!($($rest)+))
    };
    // Plain expression, sole item.
    ($only:expr) => {
        $only
    };
}
