//! Validating the `x5c` certificate chain from an Apple App Store JWS.
//!
//! App Store Server Notifications and signed transactions arrive as a JWS
//! whose header carries the signing chain in `x5c`: leaf, then intermediate,
//! then root, each base64-encoded DER. Before trusting the payload you check
//! that this chain reaches a root you already hold — the certificates
//! travelling with the message cannot vouch for themselves.
//!
//! The chain is what this crate checks. Verifying the payload signature is
//! the step after: it uses the public key from the leaf, which is only worth
//! anything once the chain behind it has been accepted.
//!
//!     cargo run -p x509-validator-examples --example apple_x5c

use base64::Engine;
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::store::CertificateStore;
use x509_validator::{Certificate, CertificateExt, Validator};

/// A signed transaction, and the root its chain is expected to reach.
const SIGNED_TRANSACTION: &str = include_str!("mocks/signed_transaction.jws");
const TRUSTED_ROOT: &[u8] = include_bytes!("mocks/apple_test_root_ca.der");

/// Expiry is checked against the instant the payload was signed, taken from
/// its `signedDate`. A transaction signed last year was signed by
/// certificates that were valid then, and may since have expired.
const SIGNED_DATE: i64 = 1_672_956_154;

fn parse(der: &[u8]) -> Certificate<'_> {
    Certificate::parse(der).expect("certificate parses")
}

/// The `x5c` chain from a JWS header, as DER, leaf first.
fn x5c_chain(jws: &str) -> Vec<Vec<u8>> {
    let header = jws
        .split('.')
        .next()
        .expect("JWS has a header");
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header.trim())
        .expect("header is base64url");
    let header = String::from_utf8(header).expect("header is UTF-8");

    // The certificates are standard base64, not the base64url the JWS itself
    // is encoded with.
    let entries = header
        .split("\"x5c\":[")
        .nth(1)
        .expect("header has an x5c claim")
        .split(']')
        .next()
        .expect("x5c is an array");

    entries
        .split(',')
        .map(|entry| {
            base64::engine::general_purpose::STANDARD
                .decode(entry.trim().trim_matches('"'))
                .expect("x5c entry is base64")
        })
        .collect()
}

fn main() {
    let x5c = x5c_chain(SIGNED_TRANSACTION);
    println!("x5c carries {} certificates", x5c.len());

    let leaf = parse(&x5c[0]);

    // Everything the message brought along except the leaf is a candidate to
    // build through. The root it offers is among them, and is still not
    // trusted: it has to match the root held below to be of any use.
    let intermediates = CertificateStore::from_iter(x5c[1..].iter().map(|der| parse(der)));

    let roots = CertificateStore::from_iter([parse(TRUSTED_ROOT)]);
    let validator = Validator::with_policy(roots, RFC5280Policy::new(SIGNED_DATE));

    match validator.validate(&leaf, &intermediates) {
        Ok(chain) => {
            println!("accepted:");
            for certificate in chain.iter() {
                println!("  {}", certificate.tbs_certificate.subject);
            }

            // The key the payload signature is checked against, now that the
            // chain vouching for it has been accepted. Handing it to a JWS
            // library is the next step, and is outside this crate.
            let public_key = chain
                .leaf()
                .tbs_certificate
                .subject_pki
                .raw;
            println!("\nleaf public key: {} bytes of DER", public_key.len());
        }
        Err(failures) if failures.is_empty() => {
            println!("rejected: no chain reached the trusted root");
        }
        Err(failures) => {
            println!("rejected:");
            for failure in failures {
                println!("  {failure}");
            }
        }
    }
}
