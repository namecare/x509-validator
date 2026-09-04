//! Ports upstream's `tests/integration.rs`.
//!
//! Upstream builds a path and then checks subject names against the leaf in a
//! separate call; a `Validator` runs one composed policy, so a name check is
//! another build with `ServerIdentityPolicy` in the policy.

use x509_validator::der_parser::Oid;
use x509_validator::extensions::GeneralName;
use x509_validator::rfc5280::{EkuPolicy, RFC5280Policy, Timestamp, eku_oids};
use x509_validator::server_identity_policy::ServerIdentityPolicy;
use x509_validator::{Certificate, CertificateExt, Validator, policy};

use super::common::{self, DEFAULT_PROVIDER, assert_reason, parse, reason, store};

#[allow(dead_code)]
pub enum Eku {
    ServerAuth,
    ClientAuth,
    Custom(Vec<Oid<'static>>),
    None,
}

impl Eku {
    fn purposes(&self) -> Option<Vec<Oid<'static>>> {
        match self {
            Self::ServerAuth => Some(vec![eku_oids::server_auth()]),
            Self::ClientAuth => Some(vec![eku_oids::client_auth()]),
            Self::Custom(oids) => Some(oids.clone()),
            Self::None => None,
        }
    }
}

fn run(
    ee: &[u8],
    intermediates: &[&[u8]],
    roots: &[&[u8]],
    eku: Eku,
    now: Timestamp,
    name: Option<&str>,
    ip: Option<&str>,
) -> Result<(), String> {
    let leaf = parse(ee);
    let roots = store(roots);
    let intermediates = store(intermediates);

    let purposes = eku.purposes();
    let validator = Validator::with_policy_and_backend(
        roots,
        policy! {
            RFC5280Policy::new(now);
            if (purposes.is_some()) {
                EkuPolicy::key_purposes(purposes.unwrap_or_default())
            };
            if (name.is_some() || ip.is_some()) { ServerIdentityPolicy::new(name, ip) }
        },
        &DEFAULT_PROVIDER,
    );

    match validator.validate(&leaf, &intermediates) {
        Ok(_) => Ok(()),
        Err(reasons) => Err(common::reasons(&reasons)),
    }
}

fn build(
    ee: &[u8],
    intermediates: &[&[u8]],
    roots: &[&[u8]],
    eku: Eku,
    now: Timestamp,
) -> Result<(), String> {
    run(ee, intermediates, roots, eku, now, None, None)
}

fn build_for_name(
    ee: &[u8],
    intermediates: &[&[u8]],
    roots: &[&[u8]],
    eku: Eku,
    now: Timestamp,
    name: &str,
) -> Result<(), String> {
    run(ee, intermediates, roots, eku, now, Some(name), None)
}

fn build_for_ip(
    ee: &[u8],
    intermediates: &[&[u8]],
    roots: &[&[u8]],
    eku: Eku,
    now: Timestamp,
    ip: &str,
) -> Result<(), String> {
    run(ee, intermediates, roots, eku, now, None, Some(ip))
}

/* Checks we can verify netflix's cert chain.  This is notable
 * because they're rooted at a Verisign v1 root. */
#[test]
fn netflix() {
    const EE: &[u8] = include_bytes!("fixtures/netflix/ee.der");
    const INTER: &[u8] = include_bytes!("fixtures/netflix/inter.der");
    const CA: &[u8] = include_bytes!("fixtures/netflix/ca.der");

    assert_eq!(
        build(EE, &[INTER], &[CA], Eku::ServerAuth, 1_492_441_716),
        Ok(())
    );
}

/// See also https://github.com/rustls/rustls/issues/2448
#[test]
fn sanofi_rsa_signature_with_absent_algorithm_params() {
    const EE: &[u8] = include_bytes!("fixtures/sanofi/ee.der");
    const INTER: &[u8] = include_bytes!("fixtures/sanofi/inter.der");
    const CA: &[u8] = include_bytes!("fixtures/sanofi/ca.der");

    assert_eq!(
        build(EE, &[INTER], &[CA], Eku::ServerAuth, 1_746_549_566),
        Ok(())
    );
}

/* This is notable because it is a popular use of IP address subjectAltNames. */
#[test]
fn cloudflare_dns() {
    const EE: &[u8] = include_bytes!("fixtures/cloudflare_dns/ee.der");
    const INTER: &[u8] = include_bytes!("fixtures/cloudflare_dns/inter.der");
    const CA: &[u8] = include_bytes!("fixtures/cloudflare_dns/ca.der");

    assert_eq!(
        build(EE, &[INTER], &[CA], Eku::ServerAuth, 1_663_495_771),
        Ok(())
    );

    for name in [
        "cloudflare-dns.com",
        "wildcard.cloudflare-dns.com",
        "one.one.one.one",
    ] {
        assert_eq!(
            build_for_name(EE, &[INTER], &[CA], Eku::ServerAuth, 1_663_495_771, name),
            Ok(()),
            "expected {name:?} to be a valid name"
        );
    }

    for addr in [
        "1.1.1.1",
        "1.0.0.1",
        "162.159.36.1",
        "162.159.46.1",
        "2606:4700:4700:0000:0000:0000:0000:1111",
        "2606:4700:4700:0000:0000:0000:0000:1001",
        "2606:4700:4700:0000:0000:0000:0000:0064",
        "2606:4700:4700:0000:0000:0000:0000:6400",
    ] {
        assert_eq!(
            build_for_ip(EE, &[INTER], &[CA], Eku::ServerAuth, 1_663_495_771, addr),
            Ok(()),
            "expected {addr:?} to be a valid address"
        );
    }
}

#[test]
fn wpt() {
    const EE: &[u8] = include_bytes!("fixtures/wpt/ee.der");
    const CA: &[u8] = include_bytes!("fixtures/wpt/ca.der");

    assert_eq!(
        build(EE, &[], &[CA], Eku::ServerAuth, 1_619_256_684),
        Ok(())
    );
}

#[test]
fn ed25519() {
    const EE: &[u8] = include_bytes!("fixtures/ed25519/ee.der");
    const CA: &[u8] = include_bytes!("fixtures/ed25519/ca.der");

    assert_eq!(
        build(EE, &[], &[CA], Eku::ServerAuth, 1_547_363_522),
        Ok(())
    );
}

#[test]
fn critical_extensions() {
    const ROOT: &[u8] = include_bytes!("fixtures/critical_extensions/root-cert.der");
    const CA: &[u8] = include_bytes!("fixtures/critical_extensions/ca-cert.der");
    const EE_NONCRIT: &[u8] =
        include_bytes!("fixtures/critical_extensions/ee-cert-noncrit-unknown-ext.der");
    const EE_CRIT: &[u8] =
        include_bytes!("fixtures/critical_extensions/ee-cert-crit-unknown-ext.der");

    const NOW: i64 = 1_670_779_098;

    assert_eq!(
        build(EE_NONCRIT, &[CA], &[ROOT], Eku::ServerAuth, NOW),
        Ok(()),
        "accept non-critical unknown extension"
    );

    assert_reason(
        build(EE_CRIT, &[CA], &[ROOT], Eku::ServerAuth, NOW),
        reason::UNHANDLED_CRITICAL,
    );
}

#[test]
fn read_root_with_zero_serial() {
    const CA: &[u8] = include_bytes!("fixtures/misc/serial_zero.der");
    Certificate::parse(CA).expect("godaddy cert should parse as anchor");
}

#[test]
fn read_root_with_neg_serial() {
    const CA: &[u8] = include_bytes!("fixtures/misc/serial_neg.der");
    Certificate::parse(CA).expect("idcat cert should parse as anchor");
}

#[test]
fn read_ee_with_neg_serial() {
    const CA: &[u8] = include_bytes!("fixtures/misc/serial_neg_ca.der");
    const EE: &[u8] = include_bytes!("fixtures/misc/serial_neg_ee.der");

    assert_eq!(
        build(EE, &[], &[CA], Eku::ServerAuth, 1_667_401_500),
        Ok(())
    );
}

#[test]
fn read_ee_with_large_pos_serial() {
    const EE: &[u8] = include_bytes!("fixtures/misc/serial_large_positive.der");
    Certificate::parse(EE).expect("should parse 20-octet positive serial number");
}

#[test]
fn read_ee_with_issuer_and_subject_unique_ids() {
    const EE: &[u8] = include_bytes!("fixtures/misc/issuer_and_subject_unique_id.der");
    Certificate::parse(EE).expect("should skip over issuerUniqueID and subjectUniqueID");
}

#[test]
fn list_netflix_names() {
    expect_cert_dns_names(
        include_bytes!("fixtures/netflix/ee.der"),
        &[
            "account.netflix.com",
            "ca.netflix.com",
            "netflix.ca",
            "netflix.com",
            "signup.netflix.com",
            "www.netflix.ca",
            "www1.netflix.com",
            "www2.netflix.com",
            "www3.netflix.com",
            "develop-stage.netflix.com",
            "release-stage.netflix.com",
            "www.netflix.com",
        ],
    );
}

#[test]
fn invalid_subject_alt_names() {
    expect_cert_dns_names(
        // same as netflix ee certificate, but with the last name in the list
        // changed to 'www.netflix:com'
        include_bytes!("fixtures/misc/invalid_subject_alternative_name.der"),
        &[
            "account.netflix.com",
            "ca.netflix.com",
            "netflix.ca",
            "netflix.com",
            "signup.netflix.com",
            "www.netflix.ca",
            "www1.netflix.com",
            "www2.netflix.com",
            "www3.netflix.com",
            "develop-stage.netflix.com",
            "release-stage.netflix.com",
            // upstream's filtered accessor drops this one; the raw accessor
            // used here keeps it
            "www.netflix:com",
        ],
    );
}

#[test]
fn wildcard_subject_alternative_names() {
    expect_cert_dns_names(
        // same as netflix ee certificate, but with the last name in the list
        // changed to 'ww*.netflix:com'
        include_bytes!("fixtures/misc/dns_names_and_wildcards.der"),
        &[
            "account.netflix.com",
            "*.netflix.com",
            "netflix.ca",
            "netflix.com",
            "signup.netflix.com",
            "www.netflix.ca",
            "www1.netflix.com",
            "www2.netflix.com",
            "www3.netflix.com",
            "develop-stage.netflix.com",
            "release-stage.netflix.com",
            "www.netflix.com",
        ],
    );
}

#[test]
fn no_subject_alt_names() {
    expect_cert_dns_names(
        include_bytes!("fixtures/misc/no_subject_alternative_name.der"),
        &[],
    );
}

#[test]
fn list_uri_names() {
    expect_cert_uri_names(
        include_bytes!("fixtures/misc/uri_san_ee.der"),
        &[
            "https://example.com",
            "https://www.example.com/path",
            "spiffe://example.org/service",
        ],
    );
}

#[test]
fn no_uri_names() {
    expect_cert_uri_names(
        include_bytes!("fixtures/misc/no_subject_alternative_name.der"),
        &[],
    );
}

#[test]
fn mixed_san_types() {
    // The uri_san_ee.der certificate has both DNS and URI SANs
    const DER: &[u8] = include_bytes!("fixtures/misc/uri_san_ee.der");
    let cert = Certificate::parse(DER).expect("should parse end entity certificate correctly");

    let dns_names: Vec<&str> = cert
        .subject_alternative_names()
        .into_iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(value) => Some(value),
            _ => None,
        })
        .collect();
    assert_eq!(dns_names, ["example.com"]);

    let uri_names: Vec<&str> = cert
        .subject_alternative_names()
        .into_iter()
        .filter_map(|name| match name {
            GeneralName::URI(value) => Some(value),
            _ => None,
        })
        .collect();
    assert_eq!(
        uri_names,
        [
            "https://example.com",
            "https://www.example.com/path",
            "spiffe://example.org/service",
        ]
    );
}

fn expect_cert_dns_names(cert_der: &[u8], expected_names: &[&str]) {
    let cert = Certificate::parse(cert_der).expect("should parse end entity certificate correctly");

    let dns_names: Vec<&str> = cert
        .subject_alternative_names()
        .into_iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(value) => Some(value),
            _ => None,
        })
        .collect();

    assert_eq!(dns_names, expected_names);
}

fn expect_cert_uri_names(cert_der: &[u8], expected_uris: &[&str]) {
    let cert = Certificate::parse(cert_der).expect("should parse end entity certificate correctly");

    let uri_names: Vec<&str> = cert
        .subject_alternative_names()
        .into_iter()
        .filter_map(|name| match name {
            GeneralName::URI(value) => Some(value),
            _ => None,
        })
        .collect();

    assert_eq!(uri_names, expected_uris);
}

#[test]
fn cert_time_validity() {
    const EE: &[u8] = include_bytes!("fixtures/netflix/ee.der");
    const INTER: &[u8] = include_bytes!("fixtures/netflix/inter.der");
    const CA: &[u8] = include_bytes!("fixtures/netflix/ca.der");

    let not_before: i64 = 1_478_563_200;
    let not_after: i64 = 1_541_203_199;

    assert_reason(
        build(EE, &[INTER], &[CA], Eku::ServerAuth, not_before - 1),
        reason::NOT_YET_VALID,
    );

    assert_reason(
        build(EE, &[INTER], &[CA], Eku::ServerAuth, not_after + 1),
        reason::EXPIRED,
    );
}

#[test]
fn anchor_spki() {
    const CA: &[u8] = include_bytes!("fixtures/netflix/ca.der");
    let cert = Certificate::parse(CA).expect("fixture parses");

    let spki = cert.public_key().raw;
    assert_eq!(Some(&0x30u8), spki.first()); // starts with SEQUENCE
}
