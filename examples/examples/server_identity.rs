//! Validating a server's certificate the way a TLS client does.
//!
//!     cargo run -p x509-validator-examples --example server_identity

use x509_validator::der_parser::Oid;
use x509_validator::policy::{PolicyEvaluationResult, ValidationPolicy};
use x509_validator::rfc5280::{EkuPolicy, RFC5280Policy};
use x509_validator::store::CertificateStore;
use x509_validator::unverified_chain::UnverifiedCertificateChain;
use x509_validator::{ServerIdentityPolicy, Validator};
use x509_validator_examples::{demo_chain, validation_time, BACKEND};

/// RFC 5280 chain rules, the serverAuth key purpose, and RFC 6125 server
/// identity — the set a TLS client wants. All three must pass; the first
/// failure is the reported reason.
struct WebPkiPolicy {
    rfc5280: RFC5280Policy,
    eku: EkuPolicy,
    identity: ServerIdentityPolicy,
}

impl WebPkiPolicy {
    fn new(now: i64, hostname: &str) -> Self {
        Self {
            rfc5280: RFC5280Policy::new(now),
            eku: EkuPolicy::server_auth(),
            identity: ServerIdentityPolicy::new(Some(hostname), None),
        }
    }
}

impl ValidationPolicy for WebPkiPolicy {
    /// The union: a critical extension is handled if any sub-policy
    /// handles it.
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        let mut oids = self
            .rfc5280
            .verifying_critical_extensions();
        oids.extend(self.eku.verifying_critical_extensions());
        oids.extend(
            self.identity
                .verifying_critical_extensions(),
        );
        oids
    }

    fn chain_meets_policy_requirements(
        &self,
        chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        self.rfc5280
            .chain_meets_policy_requirements(chain)?;
        self.eku
            .chain_meets_policy_requirements(chain)?;
        self.identity
            .chain_meets_policy_requirements(chain)
    }
}

fn main() {
    let chain = demo_chain(&["example.com", "*.example.com"]);

    for hostname in [
        "example.com",
        "api.example.com",
        "deep.api.example.com",
        "attacker.test",
    ] {
        let roots = CertificateStore::from_iter([chain.root.clone()]);
        let intermediates = CertificateStore::from_iter([chain.intermediate.clone()]);

        let policy = WebPkiPolicy::new(validation_time(), hostname);
        let validator = Validator::with_policy_and_backend(roots, policy, BACKEND);

        let verdict =
            match validator.validate_with_diagnostics(&chain.leaf, &intermediates, &mut |_| {}) {
                Ok(_) => "accepted".to_string(),
                Err(reasons) => {
                    let first = reasons
                        .first()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "no reason given".into());
                    format!("rejected — {first}")
                }
            };

        println!("{hostname:<24} {verdict}");
    }
}
