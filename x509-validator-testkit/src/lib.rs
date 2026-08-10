//! Helpers for building real DER-encoded certificates in tests.

pub mod bench_fixtures;
pub mod ca;
pub mod constraints;
pub mod leaf;
pub mod parse;
pub mod raw;
pub mod real_chain;
pub mod roots;

pub use ca::*;
pub use constraints::*;
pub use leaf::*;
pub use parse::*;
pub use raw::*;
/// Re-exported so test call sites can name `CertificateParams`, `KeyPair`,
/// `DistinguishedName` and friends without declaring their own dependency
/// on the generator — keeping one source of truth for its version.
pub use rcgen;
/// Re-exported for test modules that construct certificate validity windows.
pub use time;
