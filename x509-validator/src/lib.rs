pub mod crypto;
pub use crypto::*;
pub mod verifier;

pub use x509_validator_core::*;

// `verifier::BaseVerifier` (this crate's concrete, DFS chain-building
// struct) and `x509_validator_core::Verifier` (core's backend-agnostic
// trait) share a name only via the trait; `BaseVerifier` itself is
// unambiguous, so it's re-exported directly here. When the `aws_lc` feature
// is enabled, `crypto::aws_lc` also exposes a `Verifier` type alias binding
// `BaseVerifier`'s certificate type parameter to the aws-lc-backed
// certificate, so callers of that backend don't need to name the
// certificate type themselves.
pub use verifier::BaseVerifier;

pub mod policy;
pub mod diagnostic;
pub mod rfc5280;
pub mod server_identity_policy;
pub mod all_of_policies;
pub mod any_policy;
pub mod one_of_policies;
pub mod store;
pub mod view;

pub use policy::*;
pub use diagnostic::*;
pub use rfc5280::*;
pub use server_identity_policy::ServerIdentityPolicy;
pub use all_of_policies::AllOfPolicies;
pub use any_policy::AnyPolicy;
pub use one_of_policies::OneOfPolicies;
