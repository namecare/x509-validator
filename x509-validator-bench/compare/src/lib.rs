//! Types the comparison benchmarks need but cannot declare themselves.

pub mod signatures;

use x509_validator::crypto::SignatureVerifier;
use x509_validator::der_parser::Oid;
use x509_validator::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS;
use x509_validator::policy::{PolicyEvaluationResult, PolicyFailureReason, ValidationPolicy};
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::unverified_chain::UnverifiedCertificateChain;
/// The generated parity set, the vendored real chain, and the Mozilla CA
/// bundle roots all live in `x509-validator-testkit`, which is where their
/// provenance is recorded; both benchmark crates and the fuzz corpus draw
/// from that one copy.
pub use x509_validator_testkit::bench_fixtures::{
    p256_chain, parity, CurveChain, Parity, REFERENCE_TIME,
};
pub use x509_validator_testkit::real_chain::apple;
pub use x509_validator_testkit::roots::ROOTS;

/// One crypto backend, paired with the name it appears under in the report.
#[derive(Clone, Copy)]
pub struct Backend {
    pub name: &'static str,
    pub provider: &'static dyn SignatureVerifier,
}

impl core::fmt::Debug for Backend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name)
    }
}

/// Every backend compiled into this build, in a stable order so report rows
/// stay comparable between runs.
pub const BACKENDS: &[Backend] = &[
    #[cfg(feature = "aws_lc")]
    Backend {
        name: "aws_lc",
        provider: &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER,
    },
    #[cfg(feature = "ring")]
    Backend {
        name: "ring",
        provider: &x509_validator::crypto::ring::DEFAULT_PROVIDER,
    },
    #[cfg(feature = "rust_crypto")]
    Backend {
        name: "rust_crypto",
        provider: &x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER,
    },
];

/// The backend used by benchmarks that have no backend axis, preferring
/// aws-lc-rs when it is compiled in. Mirrors the selection the integration
/// tests use.
#[cfg(feature = "aws_lc")]
pub const DEFAULT_BACKEND: Backend = Backend {
    name: "aws_lc",
    provider: &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER,
};
#[cfg(all(feature = "ring", not(feature = "aws_lc")))]
pub const DEFAULT_BACKEND: Backend = Backend {
    name: "ring",
    provider: &x509_validator::crypto::ring::DEFAULT_PROVIDER,
};
#[cfg(all(
    feature = "rust_crypto",
    not(feature = "aws_lc"),
    not(feature = "ring")
))]
pub const DEFAULT_BACKEND: Backend = Backend {
    name: "rust_crypto",
    provider: &x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER,
};
#[cfg(not(any(feature = "aws_lc", feature = "ring", feature = "rust_crypto")))]
compile_error!("x509-validator-bench-compare requires at least one crypto backend feature: aws_lc, ring, or rust_crypto");

/// Rejects any chain containing a specific certificate, so that a scenario
/// can force the search past the shortest path onto a longer one.
///
/// A benchmark cannot declare this itself: `ValidationPolicy` is implemented
/// on a named type, and the same mock is needed by more than one target.
pub struct FailIfCertInChain {
    pub forbidden: Vec<u8>,
    pub inner: RFC5280Policy,
}

impl FailIfCertInChain {
    pub fn new(forbidden: Vec<u8>, at: i64) -> Self {
        Self {
            forbidden,
            inner: RFC5280Policy::new(at),
        }
    }
}

impl ValidationPolicy for FailIfCertInChain {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![OID_X509_EXT_BASIC_CONSTRAINTS]
    }

    fn chain_meets_policy_requirements(
        &self,
        chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        if chain
            .iter()
            .any(|cert| cert.as_ref() == self.forbidden.as_slice())
        {
            return Err(PolicyFailureReason::new(
                "chain contains forbidden certificate",
            ));
        }
        self.inner
            .chain_meets_policy_requirements(chain)
    }
}

/// Accepts every chain, so an outcome is decided purely by chain building.
pub struct IgnoreBasicConstraints;

impl ValidationPolicy for IgnoreBasicConstraints {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![OID_X509_EXT_BASIC_CONSTRAINTS]
    }

    fn chain_meets_policy_requirements(
        &self,
        _chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        Ok(())
    }
}
