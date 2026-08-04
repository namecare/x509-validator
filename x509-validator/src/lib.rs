pub mod crypto;
pub use crypto::*;
pub mod verifier;

pub use x509_validator_core::*;

// `verifier::Verifier` (this crate's concrete, DFS chain-building struct)
// and `x509_validator_core::Verifier` (core's backend-agnostic trait) share
// a name, so re-exporting `verifier`'s contents via glob would be ambiguous
// with the glob above for that one name. Re-exporting the concrete struct
// explicitly here avoids the clash and makes `x509_validator::Verifier`
// resolve to it unambiguously; callers who need the trait use
// `x509_validator_core::Verifier` (or `x509_validator::x509_validator_core::Verifier`)
// directly.

pub mod policy;
pub mod diagnostic;
pub mod rfc5280;
pub mod server_identity_policy;
pub mod all_of_policies;
pub mod any_policy;
pub mod one_of_policies;

pub use policy::*;
pub use diagnostic::*;
pub use rfc5280::*;
pub use server_identity_policy::ServerIdentityPolicy;
pub use all_of_policies::AllOfPolicies;
pub use any_policy::AnyPolicy;
pub use one_of_policies::OneOfPolicies;
pub use verifier::Verifier;
