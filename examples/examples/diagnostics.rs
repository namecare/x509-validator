//! Finding out *why* a chain was rejected.
//!
//!     cargo run -p x509-validator-examples --example diagnostics
//!
//! A failed validation returns a list of policy failure reasons, which tells
//! you what went wrong but not where in the search it happened. The
//! diagnostic callback is the verbose channel: the verifier reports every
//! step of chain building through it — issuers considered, signatures that
//! did not check out, chains that reached a root but failed policy.
//!
//! The callback fires on successful validations too, which makes it just as
//! useful for understanding which of several candidate paths was chosen.

use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::verifier::ChainValidationResultOwned;
use x509_validator::BaseVerifier;
use x509_validator_examples::{demo_chain, validation_time, BACKEND};

fn main() {
    let chain = demo_chain(&["example.com"]);

    // A root the leaf has nothing to do with: chain building will search,
    // find no issuer it trusts, and give up.
    let unrelated = demo_chain(&["unrelated.test"]);

    let roots = CertificateStore::from_iter([unrelated.root.clone()]);
    let intermediates = CertificateStore::from_iter([chain.intermediate.clone()]);

    let mut verifier = BaseVerifier::with_policy_and_backend(roots, RFC5280Policy::new(validation_time()), BACKEND);

    let mut trace = Vec::new();
    let result = verifier.validate_with_diagnostics(&chain.leaf, &intermediates, &mut |diagnostic| {
        trace.push(diagnostic.to_string());
    });

    println!("chain building trace ({} events):", trace.len());
    for (step, event) in trace.iter().enumerate() {
        println!("  {}. {event}", step + 1);
    }

    match result {
        ChainValidationResultOwned::ValidCertificate(valid) => {
            println!("\nunexpectedly valid — chain of {}", valid.iter().count());
        }
        ChainValidationResultOwned::CouldNotValidate(reasons) => {
            println!("\nverdict: rejected");
            if reasons.is_empty() {
                println!("  no policy failures recorded — no chain reached a trusted root");
            }
            for reason in reasons {
                println!("  reason: {reason}");
            }
        }
    }

    // `multiline_description()` carries the same information as `Display`,
    // laid out over several lines.
    let roots = CertificateStore::from_iter([unrelated.root.clone()]);
    let mut verifier = BaseVerifier::with_policy_and_backend(roots, RFC5280Policy::new(validation_time()), BACKEND);

    let mut last = None;
    verifier.validate_with_diagnostics(&chain.leaf, &intermediates, &mut |diagnostic| {
        last = Some(diagnostic.multiline_description());
    });

    if let Some(description) = last {
        println!("\n--- final event, in full ---\n{description}");
    }
}