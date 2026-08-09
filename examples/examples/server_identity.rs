//! Validating a server's certificate the way a TLS client does: chain
//! validity *and* the leaf being authoritative for the hostname you dialled.
//!
//!     cargo run -p x509-validator-examples --example server_identity
//!
//! `RFC5280Policy` alone says nothing about hostnames — a perfectly valid
//! chain for `example.com` is still the wrong certificate if you asked for
//! `attacker.test`. `ServerIdentityPolicy` adds the RFC 6125 check.
//!
//! Both must hold, which is the other thing this example shows: a policy
//! that runs two sub-policies in sequence. Combining policies is just
//! implementing `ValidationPolicy` over the ones you want — the trait is two
//! methods, and the union of their handled critical extensions is what makes
//! the pair accept certificates neither would accept alone.

use x509_validator::policy::{PolicyEvaluationResult, ValidationPolicy};
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::validator::ChainValidationResult;
use x509_validator::{BaseValidator, ServerIdentityPolicy};
use x509_validator_core::der_parser::Oid;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use x509_validator_examples::{demo_chain, validation_time, BACKEND};

/// RFC 5280 chain rules plus RFC 6125 server identity — the pair a TLS
/// client wants. Both must pass; the first failure is the reported reason.
struct WebPkiPolicy {
    rfc5280: RFC5280Policy,
    identity: ServerIdentityPolicy,
}

impl WebPkiPolicy {
    fn new(now: i64, hostname: &str) -> Self {
        Self {
            rfc5280: RFC5280Policy::new(now),
            identity: ServerIdentityPolicy::new(Some(hostname), None),
        }
    }
}

impl ValidationPolicy for WebPkiPolicy {
    /// The union: a critical extension is handled if either sub-policy
    /// handles it.
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        let mut oids = self.rfc5280.verifying_critical_extensions();
        oids.extend(self.identity.verifying_critical_extensions());
        oids
    }

    fn chain_meets_policy_requirements(&self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        self.rfc5280.chain_meets_policy_requirements(chain)?;
        self.identity.chain_meets_policy_requirements(chain)
    }
}

fn main() {
    // A leaf carrying two SAN entries, one of them a wildcard.
    let chain = demo_chain(&["example.com", "*.example.com"]);

    // The wildcard matches one label deep and no further, and a hostname the
    // certificate never claimed is rejected however valid the chain is.
    for hostname in ["example.com", "api.example.com", "deep.api.example.com", "attacker.test"] {
        let roots = CertificateStore::from_iter([chain.root.clone()]);
        let intermediates = CertificateStore::from_iter([chain.intermediate.clone()]);

        let policy = WebPkiPolicy::new(validation_time(), hostname);
        let validator = BaseValidator::with_policy_and_backend(roots, policy, BACKEND);

        let verdict = match validator.validate_with_diagnostics(&chain.leaf, &intermediates, &mut |_| {}) {
            ChainValidationResult::ValidCertificate(_) => "accepted".to_string(),
            ChainValidationResult::CouldNotValidate(reasons) => {
                let first = reasons.first().map(ToString::to_string).unwrap_or_else(|| "no reason given".into());
                format!("rejected — {first}")
            }
        };

        println!("{hostname:<24} {verdict}");
    }
}