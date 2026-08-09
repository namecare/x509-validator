//! The smallest useful thing this crate does: check that a leaf certificate
//! chains to a trusted root, under RFC 5280's rules.
//!
//!     cargo run -p x509-validator-examples --example validate_chain
//!
//! The three moving parts are a trust store of roots, a store of untrusted
//! intermediates the validator may build through, and a policy that decides
//! whether a candidate chain is acceptable. `RFC5280Policy` is the baseline:
//! validity windows, basic constraints, name constraints, version.

use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::validator::ChainValidationResult;
use x509_validator::Validator;
use x509_validator_examples::{demo_chain, validation_time, BACKEND};

fn main() {
    let chain = demo_chain(&["example.com"]);

    // Roots are trusted a priori. Intermediates are not: they are merely
    // available for the validator to build a path through, and each one still
    // has to be signed by something that leads back to a root.
    let roots = CertificateStore::from_iter([chain.root.clone()]);
    let intermediates = CertificateStore::from_iter([chain.intermediate.clone()]);

    let policy = RFC5280Policy::new(validation_time());
    let validator = Validator::with_policy_and_backend(roots, policy, BACKEND);

    match validator.validate_with_diagnostics(&chain.leaf, &intermediates, &mut |_| {}) {
        ChainValidationResult::ValidCertificate(valid) => {
            println!("valid — chain of {} certificates:", valid.iter().count());
            // Leaf first, root last.
            for cert in valid.iter() {
                println!("  {}", cert.tbs_certificate.subject);
            }
        }
        ChainValidationResult::CouldNotValidate(reasons) => {
            println!("rejected — {} policy failure(s):", reasons.len());
            for reason in reasons {
                println!("  {reason}");
            }
        }
    }

    // The same leaf without its intermediate available: there is no path to
    // the root, so chain building fails even though the leaf itself is fine.
    let roots = CertificateStore::from_iter([chain.root.clone()]);
    let validator = Validator::with_policy_and_backend(roots, RFC5280Policy::new(validation_time()), BACKEND);

    let result = validator.validate_with_diagnostics(&chain.leaf, &CertificateStore::new(), &mut |_| {});
    println!(
        "\nwithout the intermediate: {}",
        match result {
            ChainValidationResult::ValidCertificate(_) => "valid".to_string(),
            // An empty reason list means no candidate chain reached a root,
            // so the policy was never asked.
            ChainValidationResult::CouldNotValidate(reasons) if reasons.is_empty() =>
                "rejected — no chain to a trusted root could be built".to_string(),
            ChainValidationResult::CouldNotValidate(reasons) => {
                let listed = reasons.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ");
                format!("rejected — {listed}")
            }
        }
    );
}
