//! Shared fixtures and the backend registry for the benchmark suite.
//!
//! Certificate generation is expensive and must never land inside a timed
//! region, so everything here is built once and reused across benchmarks.

pub mod fixtures;
pub mod signatures;

use x509_validator::crypto::CryptoProvider;

/// One crypto backend, paired with the name it appears under in the report.
///
/// divan's `args` values must be `Copy` and either `ToString` or `Debug`.
/// `CryptoProvider` holds `&dyn` trait objects and cannot derive `Debug`, so
/// the impl below is written by hand and prints just the name — which is
/// what labels the row.
#[derive(Clone, Copy)]
pub struct Backend {
    pub name: &'static str,
    pub provider: &'static CryptoProvider,
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

/// Every backend compiled into this build, in a stable order so report rows
/// stay comparable between runs.
pub const BACKENDS: &[Backend] = &[
    #[cfg(feature = "aws_lc")]
    Backend { name: "aws_lc", provider: &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER },
    #[cfg(feature = "ring")]
    Backend { name: "ring", provider: &x509_validator::crypto::ring::DEFAULT_PROVIDER },
    #[cfg(feature = "rust_crypto")]
    Backend { name: "rust_crypto", provider: &x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER },
];

/// The backend used by benchmarks that have no backend axis, preferring
/// aws-lc-rs when it is compiled in. Mirrors the selection the integration
/// tests use.
#[cfg(feature = "aws_lc")]
pub const DEFAULT_BACKEND: Backend = Backend { name: "aws_lc", provider: &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER };
#[cfg(all(feature = "ring", not(feature = "aws_lc")))]
pub const DEFAULT_BACKEND: Backend = Backend { name: "ring", provider: &x509_validator::crypto::ring::DEFAULT_PROVIDER };
#[cfg(all(feature = "rust_crypto", not(feature = "aws_lc"), not(feature = "ring")))]
pub const DEFAULT_BACKEND: Backend = Backend { name: "rust_crypto", provider: &x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER };
