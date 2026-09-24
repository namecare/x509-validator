#![cfg(any(feature = "aws_lc", feature = "ring", feature = "rust_crypto"))]

use core::net::IpAddr;

#[cfg(feature = "aws_lc")]
use x509_validator::crypto::aws_lc::DEFAULT_PROVIDER;
#[cfg(all(feature = "ring", not(feature = "aws_lc")))]
use x509_validator::crypto::ring::DEFAULT_PROVIDER;
#[cfg(all(
    feature = "rust_crypto",
    not(feature = "aws_lc"),
    not(feature = "ring")
))]
use x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER;
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator::server_identity_policy::ServerIdentityPolicy;
use x509_validator::store::CertificateStore;
use x509_validator::{Certificate, CertificateExt, Validator, policy};
use x509_validator_testkit::leaf::LeafSpec;
use x509_validator_testkit::rcgen::{
    CertificateParams, CidrSubnet, DistinguishedName, DnType, GeneralSubtree, Issuer, KeyPair,
    SigningKey,
};
use x509_validator_testkit::time::{Duration, OffsetDateTime};
use x509_validator_testkit::{Ca, issue_leaf_with_ip_sans, self_signed_ca_with};

const NOW: i64 = 1_500;

enum Query {
    Dns(&'static str),
    Ip(&'static str),
}

fn validate(leaf: &[u8], intermediates: &[&[u8]], root: &[u8], query: Query) -> Result<(), String> {
    let (hostname, ip) = match query {
        Query::Dns(name) => (Some(name), None),
        Query::Ip(ip) => (None, Some(ip)),
    };
    let validator = Validator::with_policy_and_backend(
        store(&[root]),
        policy! {
            RFC5280Policy::new(NOW);
            ServerIdentityPolicy::new(hostname, ip)
        },
        &DEFAULT_PROVIDER,
    );
    let leaf = Certificate::parse(leaf).expect("leaf parses");
    match validator.validate(&leaf, &store(intermediates)) {
        Ok(_) => Ok(()),
        Err(reasons) => Err(reasons
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")),
    }
}

fn store<'a>(ders: &[&'a [u8]]) -> CertificateStore<'a> {
    CertificateStore::from_iter(
        ders.iter()
            .map(|der| Certificate::parse(der).expect("certificate parses")),
    )
}

#[track_caller]
fn assert_rejected(result: Result<(), String>) {
    assert!(result.is_err(), "FAIL-OPEN: the chain was accepted");
}

fn issuer(permitted: Vec<GeneralSubtree>, excluded: Vec<GeneralSubtree>) -> Ca {
    self_signed_ca_with("issuer.example.com", |params: &mut CertificateParams| {
        if !permitted.is_empty() || !excluded.is_empty() {
            params.name_constraints = Some(x509_validator_testkit::rcgen::NameConstraints {
                permitted_subtrees: permitted,
                excluded_subtrees: excluded,
            });
        }
    })
}

fn no_ip_issuer() -> Ca {
    issuer(
        vec![dns("example.com")],
        vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
        ],
    )
}

fn dns(name: &str) -> GeneralSubtree {
    GeneralSubtree::DnsName(name.to_string())
}

fn dns_leaf(ca: &Ca, subject_cn: &str, sans: &[&str]) -> Vec<u8> {
    LeafSpec::new(subject_cn)
        .dns_sans(sans)
        .signed_by(ca)
}

fn ip_leaf(ca: &Ca, ip: &str) -> Vec<u8> {
    let addr: IpAddr = ip.parse().expect("valid ip");
    issue_leaf_with_ip_sans("", vec![addr], ca)
}

#[test]
fn sanity_valid_chain_is_accepted() {
    let ca = issuer(vec![], vec![]);
    let leaf = dns_leaf(&ca, "", &["www.example.com"]);
    assert_eq!(
        validate(&leaf, &[], &ca.der, Query::Dns("www.example.com")),
        Ok(())
    );
}

#[test]
fn issue_1_wildcard_san_matching_excluded_name_is_rejected() {
    let ca = issuer(vec![], vec![dns("evil.example.com")]);
    let leaf = dns_leaf(&ca, "", &["*.example.com"]);
    assert_rejected(validate(
        &leaf,
        &[],
        &ca.der,
        Query::Dns("evil.example.com"),
    ));
}

#[test]
fn issue_2_v1_end_entity_certificate_is_rejected_as_intermediate() {
    let root = self_signed_ca_with("legacy-root", |_| {});

    let device_key = KeyPair::generate().expect("generate key pair");
    let device_key_again =
        KeyPair::try_from(device_key.serialize_der().as_slice()).expect("reload key");
    let device_cert = v1_certificate_signed_by(&root, "legacy-device", device_key);

    let parsed = Certificate::parse(&device_cert).expect("v1 cert parses");
    assert_eq!(parsed.version().0, 0, "expected a v1 certificate");
    assert!(parsed.extensions().is_empty());

    let mut device_params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "legacy-device");
    device_params.distinguished_name = dn;
    let device_as_issuer = Issuer::from_params(&device_params, &device_key_again);

    let mut leaf_params =
        CertificateParams::new(vec!["www.victim.com".to_string()]).expect("leaf params");
    leaf_params.not_before = OffsetDateTime::UNIX_EPOCH + Duration::seconds(1000);
    leaf_params.not_after = OffsetDateTime::UNIX_EPOCH + Duration::seconds(2000);
    let leaf = leaf_params
        .signed_by(
            &KeyPair::generate().expect("generate key pair"),
            &device_as_issuer,
        )
        .expect("sign leaf")
        .der()
        .to_vec();

    assert_rejected(validate(
        &leaf,
        &[&device_cert],
        &root.der,
        Query::Dns("www.victim.com"),
    ));
}

#[test]
fn issue_3_wildcard_san_matching_excluded_name_is_rejected() {
    let ca = issuer(vec![], vec![dns("evil.example.com")]);
    let leaf = dns_leaf(&ca, "", &["*.example.com"]);
    assert_rejected(validate(
        &leaf,
        &[],
        &ca.der,
        Query::Dns("evil.example.com"),
    ));
}

#[test]
fn issue_3_absolute_form_san_matching_excluded_name_is_rejected() {
    let ca = issuer(vec![], vec![dns("evil.example.com")]);
    let leaf = dns_leaf(&ca, "", &["evil.example.com."]);
    assert_rejected(validate(
        &leaf,
        &[],
        &ca.der,
        Query::Dns("evil.example.com"),
    ));
}

#[test]
fn issue_3_ipv4_san_under_excluded_all_zero_mask_is_rejected() {
    let ca = no_ip_issuer();
    let leaf = ip_leaf(&ca, "203.0.113.10");
    assert_rejected(validate(&leaf, &[], &ca.der, Query::Ip("203.0.113.10")));
}

#[test]
fn issue_3_ipv6_san_under_excluded_all_zero_mask_is_rejected() {
    let ca = no_ip_issuer();
    let leaf = ip_leaf(&ca, "2001:db8::10");
    assert_rejected(validate(&leaf, &[], &ca.der, Query::Ip("2001:db8::10")));
}

#[test]
fn issue_4_san_less_cn_outside_permitted_subtree_is_rejected() {
    let ca = issuer(vec![dns("example.com")], vec![]);
    let leaf = dns_leaf(&ca, "www.victim.com", &[]);
    assert_rejected(validate(&leaf, &[], &ca.der, Query::Dns("www.victim.com")));
}

#[test]
fn issue_4_san_less_cn_inside_excluded_subtree_is_rejected() {
    let ca = issuer(vec![], vec![dns("victim.com")]);
    let leaf = dns_leaf(&ca, "www.victim.com", &[]);
    assert_rejected(validate(&leaf, &[], &ca.der, Query::Dns("www.victim.com")));
}

#[test]
fn issue_5_ipv4_san_under_excluded_all_zero_mask_is_rejected() {
    let ca = no_ip_issuer();
    let leaf = ip_leaf(&ca, "203.0.113.10");
    assert_rejected(validate(&leaf, &[], &ca.der, Query::Ip("203.0.113.10")));
}

#[test]
fn issue_5_ipv6_san_under_excluded_all_zero_mask_is_rejected() {
    let ca = no_ip_issuer();
    let leaf = ip_leaf(&ca, "2001:db8::10");
    assert_rejected(validate(&leaf, &[], &ca.der, Query::Ip("2001:db8::10")));
}

fn v1_certificate_signed_by(ca: &Ca, subject_cn: &str, key_pair: KeyPair) -> Vec<u8> {
    let v3 = LeafSpec::new(subject_cn)
        .key_pair(key_pair)
        .signed_by(ca);

    let certificate = der::contents_of(&v3, 0x30);
    let (tbs, rest) = der::split_first(certificate);
    let (signature_algorithm, _) = der::split_first(rest);

    let tbs_contents = der::contents_of(tbs, 0x30);
    let mut fields: Vec<&[u8]> = der::elements(tbs_contents);
    if fields
        .first()
        .is_some_and(|f| f[0] == 0xa0)
    {
        fields.remove(0);
    }
    if fields
        .last()
        .is_some_and(|f| f[0] == 0xa3)
    {
        fields.pop();
    }
    let v1_tbs = der::tlv(0x30, &fields.concat());

    let signature = ca
        .copy_of_key_pair()
        .sign(&v1_tbs)
        .expect("sign v1 tbs");
    let mut bit_string = vec![0u8];
    bit_string.extend_from_slice(&signature);

    der::tlv(
        0x30,
        &[
            v1_tbs.as_slice(),
            signature_algorithm,
            der::tlv(0x03, &bit_string).as_slice(),
        ]
        .concat(),
    )
}

mod der {
    pub(super) fn split_first(bytes: &[u8]) -> (&[u8], &[u8]) {
        let (header_len, content_len) = header(bytes);
        bytes.split_at(header_len + content_len)
    }

    pub(super) fn contents_of(bytes: &[u8], expected_tag: u8) -> &[u8] {
        assert_eq!(bytes[0], expected_tag, "unexpected DER tag");
        let (header_len, content_len) = header(bytes);
        &bytes[header_len..header_len + content_len]
    }

    pub(super) fn elements(mut bytes: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let (element, rest) = split_first(bytes);
            out.push(element);
            bytes = rest;
        }
        out
    }

    fn header(bytes: &[u8]) -> (usize, usize) {
        let first = bytes[1] as usize;
        if first < 0x80 {
            return (2, first);
        }
        let n = first & 0x7f;
        let len = bytes[2..2 + n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | *b as usize);
        (2 + n, len)
    }

    pub(super) fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = contents.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.extend_from_slice(&[0x81, len as u8]);
        } else {
            out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xff) as u8]);
        }
        out.extend_from_slice(contents);
        out
    }
}
