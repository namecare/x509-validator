//! Finding out *why* a chain was rejected.
//!
//!     cargo run -p x509-validator-examples --example diagnostics

use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::Validator;
use x509_validator_examples::{demo_chain, validation_time, BACKEND};

fn main() {
    let chain = demo_chain(&["example.com"]);
    let unrelated = demo_chain(&["unrelated.test"]);

    let roots = CertificateStore::from_iter([unrelated.root.clone()]);
    let intermediates = CertificateStore::from_iter([chain.intermediate.clone()]);

    let validator =
        Validator::with_policy_and_backend(roots, RFC5280Policy::new(validation_time()), BACKEND);

    let mut trace = Vec::new();
    let result =
        validator.validate_with_diagnostics(&chain.leaf, &intermediates, &mut |diagnostic| {
            trace.push(diagnostic.to_string());
        });

    println!("chain building trace ({} events):", trace.len());
    for (step, event) in trace.iter().enumerate() {
        println!("  {}. {event}", step + 1);
    }

    match result {
        Ok(valid) => {
            println!("\nunexpectedly valid — chain of {}", valid.iter().count());
        }
        Err(reasons) => {
            println!("\nverdict: rejected");
            if reasons.is_empty() {
                println!("  no policy failures recorded — no chain reached a trusted root");
            }
            for reason in reasons {
                println!("  reason: {reason}");
            }
        }
    }

    let roots = CertificateStore::from_iter([unrelated.root.clone()]);
    let validator =
        Validator::with_policy_and_backend(roots, RFC5280Policy::new(validation_time()), BACKEND);

    let mut last = None;
    let _ = validator.validate_with_diagnostics(&chain.leaf, &intermediates, &mut |diagnostic| {
        last = Some(diagnostic.multiline_description());
    });

    if let Some(description) = last {
        println!("\n--- final event, in full ---\n{description}");
    }
}
