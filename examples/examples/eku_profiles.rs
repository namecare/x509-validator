//! Extended key usage policies, and how the choices in one change its verdicts.
//!
//! RFC 5280 §4.2.1.12 leaves two questions open: whether a certificate that
//! omits extendedKeyUsage is thereby unrestricted, and whether an issuer's
//! extendedKeyUsage restricts what it may issue for. Answering them
//! differently produces materially different verifiers, all defensible. The
//! matrix below runs four such answers against five certificate shapes.
//!
//!     cargo run -p x509-validator-examples --example eku_profiles

use x509_validator::rfc5280::{eku_oids, CertificateRole, EkuPolicy, RFC5280Policy};
use x509_validator::store::CertificateStore;
use x509_validator::{policy, AnyPolicy, Validator};
use x509_validator_examples::{demo_chain_with_ekus, validation_time, BACKEND};
use x509_validator_testkit::rcgen::ExtendedKeyUsagePurpose::{self, Any, ClientAuth, ServerAuth};

/// serverAuth, or anyExtendedKeyUsage standing in for it.
fn server_auth_or_any() -> EkuPolicy {
    EkuPolicy::key_purposes([eku_oids::server_auth(), eku_oids::any_extended_key_usage()])
}

/// A named extendedKeyUsage policy. The policy is built on demand and erased
/// to one type, so profiles of unrelated shapes can share a list.
struct Profile {
    name: &'static str,
    build: fn() -> AnyPolicy,
}

/// The extendedKeyUsage policies compared.
fn profiles() -> Vec<Profile> {
    vec![
        // Every certificate must name serverAuth, or else omit the extension
        // and so claim no restriction. anyExtendedKeyUsage is not read as a
        // wildcard: it is simply a purpose that is not the one required.
        Profile {
            name: "strict purpose",
            build: || AnyPolicy::new(EkuPolicy::server_auth()),
        },
        // As above, but anyExtendedKeyUsage is accepted anywhere it appears.
        Profile {
            name: "any accepted",
            build: || AnyPolicy::new(server_auth_or_any()),
        },
        // The end entity must name serverAuth outright — omitting the
        // extension no longer excuses it — while issuers may fall back on
        // anyExtendedKeyUsage, and the trust anchor is not consulted.
        Profile {
            name: "strict end entity",
            build: || {
                AnyPolicy::new(policy! {
                    EkuPolicy::server_auth()
                        .applies_to(CertificateRole::EndEntity)
                        .require_extension();
                    server_auth_or_any().applies_to(CertificateRole::IssuersExcludingAnchor)
                })
            },
        },
        // Only the end entity is policed; whatever the issuers claim about
        // their own keys is left alone.
        Profile {
            name: "end entity only",
            build: || {
                AnyPolicy::new(EkuPolicy::server_auth().applies_to(CertificateRole::EndEntity))
            },
        },
    ]
}

/// A named chain shape: the key purposes its leaf and its intermediate carry.
struct Shape {
    name: &'static str,
    leaf_ekus: Vec<ExtendedKeyUsagePurpose>,
    intermediate_ekus: Vec<ExtendedKeyUsagePurpose>,
}

/// The certificate shapes the profiles are run against.
fn shapes() -> Vec<Shape> {
    vec![
        Shape {
            name: "leaf serverAuth",
            leaf_ekus: vec![ServerAuth],
            intermediate_ekus: vec![ServerAuth],
        },
        Shape {
            name: "leaf no extension",
            leaf_ekus: vec![],
            intermediate_ekus: vec![ServerAuth],
        },
        Shape {
            name: "leaf anyEKU only",
            leaf_ekus: vec![Any],
            intermediate_ekus: vec![ServerAuth],
        },
        Shape {
            name: "issuer no extension",
            leaf_ekus: vec![ServerAuth],
            intermediate_ekus: vec![],
        },
        Shape {
            name: "issuer clientAuth",
            leaf_ekus: vec![ServerAuth],
            intermediate_ekus: vec![ClientAuth],
        },
    ]
}

fn main() {
    let profiles = profiles();
    let shapes = shapes();

    print!("{:<22}", "");
    for profile in &profiles {
        print!("{:<20}", profile.name);
    }
    println!();

    for shape in &shapes {
        print!("{:<22}", shape.name);

        for profile in &profiles {
            let chain =
                demo_chain_with_ekus(&["example.com"], &shape.leaf_ekus, &shape.intermediate_ekus);
            let roots = CertificateStore::from_iter([chain.root.clone()]);
            let intermediates = CertificateStore::from_iter([chain.intermediate.clone()]);

            // The chain rules are the same throughout; only the key purpose
            // policy differs between columns.
            let policy = policy! {
                RFC5280Policy::new(validation_time());
                (profile.build)()
            };
            let validator = Validator::with_policy_and_backend(roots, policy, BACKEND);

            let verdict =
                match validator.validate_with_diagnostics(&chain.leaf, &intermediates, &mut |_| {})
                {
                    Ok(_) => "accepted",
                    Err(_) => "rejected",
                };
            print!("{verdict:<20}");
        }
        println!();
    }

    println!(
        "\n\
         A certificate that omits extendedKeyUsage claims no restriction, so it\n\
         satisfies any purpose asked of it — `require_extension` withdraws that.\n\
         Requiring it chain-wide would reject most real chains, since issuers\n\
         throughout the deployed web PKI leave the extension off, which is why\n\
         the strict profile above narrows that requirement to the end entity."
    );
}
