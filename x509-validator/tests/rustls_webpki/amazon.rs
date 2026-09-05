//! Ports the upstream `amazon` file: real-world chains to the four Amazon
//! roots and the legacy Starfield root.
//!
//! Upstream also drives certificate revocation through `RevocationOptions`
//! and a committed CRL per issuer. This library has no revocation support,
//! so the CRL arms are dropped and only upstream's `crls: None` assertions
//! are ported; the CRL fixtures are not vendored. See README.md.

use x509_validator::rfc5280::{EkuPolicy, RFC5280Policy, Timestamp, eku_oids};
use x509_validator::server_identity_policy::ServerIdentityPolicy;
use x509_validator::{Validator, policy};

use super::common::{DEFAULT_PROVIDER, assert_reason, parse, reason, reasons, store};

/// Sun Feb 23 02:02:16 PST 2025, as upstream validates at.
const NOW: Timestamp = 1_740_304_936;

/// The four Amazon roots.
const ROOTS: &[&[u8]] = &[
    // https://www.amazontrust.com/repository/AmazonRootCA1.cer
    // https://crt.sh/?id=12745009
    include_bytes!("fixtures/amazon/AmazonRootCA1.cer"),
    // https://www.amazontrust.com/repository/AmazonRootCA2.cer
    // https://crt.sh/?id=12744983
    include_bytes!("fixtures/amazon/AmazonRootCA2.cer"),
    // https://www.amazontrust.com/repository/AmazonRootCA3.cer
    // https://crt.sh/?id=12744938
    include_bytes!("fixtures/amazon/AmazonRootCA3.cer"),
    // https://www.amazontrust.com/repository/AmazonRootCA4.cer
    // https://crt.sh/?id=12745024
    include_bytes!("fixtures/amazon/AmazonRootCA4.cer"),
];

// https://aws.amazon.com/blogs/security/acm-will-no-longer-cross-sign-certificates-with-starfield-class-2-starting-august-2024/
// https://crt.sh/?id=793888
// https://crt.sh/?id=10739077
const LEGACY_ROOT: &[u8] = include_bytes!("fixtures/amazon/SFSRootCAG2.cer");

const ROOTS_AS_INTERMEDIATES: &[&[u8]] = &[
    include_bytes!("fixtures/amazon/rootca1.cer"),
    include_bytes!("fixtures/amazon/rootca2.cer"),
    include_bytes!("fixtures/amazon/rootca3.cer"),
    include_bytes!("fixtures/amazon/rootca4.cer"),
];

const INTERMEDIATES: &[&[u8]] = &[
    include_bytes!("fixtures/amazon/r2m01.cer"),
    include_bytes!("fixtures/amazon/r2m02.cer"),
    include_bytes!("fixtures/amazon/r2m03.cer"),
    include_bytes!("fixtures/amazon/r2m04.cer"),
    include_bytes!("fixtures/amazon/r4m01.cer"),
    include_bytes!("fixtures/amazon/r4m02.cer"),
    include_bytes!("fixtures/amazon/r4m03.cer"),
    include_bytes!("fixtures/amazon/r4m04.cer"),
    include_bytes!("fixtures/amazon/e2m01.cer"),
    include_bytes!("fixtures/amazon/e2m02.cer"),
    include_bytes!("fixtures/amazon/e2m03.cer"),
    include_bytes!("fixtures/amazon/e2m04.cer"),
    include_bytes!("fixtures/amazon/e3m01.cer"),
    include_bytes!("fixtures/amazon/e3m02.cer"),
    include_bytes!("fixtures/amazon/e3m03.cer"),
    include_bytes!("fixtures/amazon/e3m04.cer"),
];

const VALID_CERTS: &[(&[u8], &str)] = &[
    (
        include_bytes!("fixtures/amazon/valid.rootca1.demo.amazontrust.com.cer"),
        "valid.rootca1.demo.amazontrust.com",
    ),
    (
        include_bytes!("fixtures/amazon/valid.rootca2.demo.amazontrust.com.cer"),
        "valid.rootca2.demo.amazontrust.com",
    ),
    (
        include_bytes!("fixtures/amazon/valid.rootca3.demo.amazontrust.com.cer"),
        "valid.rootca3.demo.amazontrust.com",
    ),
    (
        include_bytes!("fixtures/amazon/valid.rootca4.demo.amazontrust.com.cer"),
        "valid.rootca4.demo.amazontrust.com",
    ),
];

const REVOKED_CERTS: &[(&[u8], &str)] = &[
    (
        include_bytes!("fixtures/amazon/revoked.rootca1.demo.amazontrust.com.cer"),
        "revoked.rootca1.demo.amazontrust.com",
    ),
    (
        include_bytes!("fixtures/amazon/revoked.rootca2.demo.amazontrust.com.cer"),
        "revoked.rootca2.demo.amazontrust.com",
    ),
    (
        include_bytes!("fixtures/amazon/revoked.rootca3.demo.amazontrust.com.cer"),
        "revoked.rootca3.demo.amazontrust.com",
    ),
    (
        include_bytes!("fixtures/amazon/revoked.rootca4.demo.amazontrust.com.cer"),
        "revoked.rootca4.demo.amazontrust.com",
    ),
];

const EXPIRED_CERTS: &[(&[u8], &str)] = &[
    (
        include_bytes!("fixtures/amazon/expired.rootca1.demo.amazontrust.com.cer"),
        "expired.rootca1.demo.amazontrust.com",
    ),
    (
        include_bytes!("fixtures/amazon/expired.rootca2.demo.amazontrust.com.cer"),
        "expired.rootca2.demo.amazontrust.com",
    ),
    (
        include_bytes!("fixtures/amazon/expired.rootca3.demo.amazontrust.com.cer"),
        "expired.rootca3.demo.amazontrust.com",
    ),
    (
        include_bytes!("fixtures/amazon/expired.rootca4.demo.amazontrust.com.cer"),
        "expired.rootca4.demo.amazontrust.com",
    ),
];

/// Builds a chain to `roots`, requiring server auth, optionally checking a
/// subject name. Upstream builds a path and checks names in two separate
/// calls; a `Validator` runs one composed policy with the identity check
/// inside it.
fn build(
    ee: &[u8],
    intermediates: &[&[u8]],
    roots: &[&[u8]],
    now: Timestamp,
    name: Option<&str>,
) -> Result<(), String> {
    let leaf = parse(ee);
    let roots = store(roots);
    let intermediates = store(intermediates);

    let validator = Validator::with_policy_and_backend(
        roots,
        policy! {
            RFC5280Policy::new(now);
            EkuPolicy::key_purposes(vec![eku_oids::server_auth()]);
            if (name.is_some()) { ServerIdentityPolicy::new(name, None) }
        },
        &DEFAULT_PROVIDER,
    );

    match validator.validate(&leaf, &intermediates) {
        Ok(_) => Ok(()),
        Err(collected) => Err(reasons(&collected)),
    }
}

#[test]
fn amazon() {
    let all_roots = [ROOTS, &[LEGACY_ROOT]].concat();
    let intermediates_legacy = [INTERMEDIATES, ROOTS_AS_INTERMEDIATES].concat();

    // Upstream checks the subject name on the leaf alone, with no chain
    // build and no validation time, so its expired leaves pass this loop
    // too. Subject-name matching here is only reachable through a full
    // validation, which the expired leaves fail on expiry first; they are
    // covered by the expiry assertion below instead.
    for &(cert, dns_name) in [VALID_CERTS, REVOKED_CERTS]
        .concat()
        .iter()
    {
        assert_eq!(
            build(cert, &intermediates_legacy, &all_roots, NOW, Some(dns_name)),
            Ok(()),
            "expected {dns_name:?} to be a valid name"
        );
    }

    for &(cert, _dns_name) in VALID_CERTS {
        assert_eq!(build(cert, INTERMEDIATES, ROOTS, NOW, None), Ok(()));
        assert_eq!(
            build(cert, &intermediates_legacy, &[LEGACY_ROOT], NOW, None),
            Ok(())
        );
        assert_eq!(
            build(cert, &intermediates_legacy, &all_roots, NOW, None),
            Ok(())
        );
    }

    // Without revocation checking a revoked certificate still builds a
    // path; upstream asserts the same for its `crls: None` arm.
    for &(cert, _dns_name) in REVOKED_CERTS {
        assert_eq!(build(cert, INTERMEDIATES, ROOTS, NOW, None), Ok(()));
    }

    for &(cert, _dns_name) in EXPIRED_CERTS {
        assert_reason(
            build(cert, INTERMEDIATES, ROOTS, NOW, None),
            reason::EXPIRED,
        );
    }
}
