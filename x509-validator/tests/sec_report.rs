//! Reproductions for the September 2026 security review of the main crate.
//!
//! Every test here encodes a chain that RFC 5280 (or the trust boundary a
//! name constraint draws) says must be rejected, and asserts rejection.
//! They are expected to FAIL against the current code: each failure is a
//! confirmed fail-open. Once the corresponding fix lands, the test passes
//! and stays as the regression guard. Do not mark these `#[ignore]`.
//!
//! Each finding also has a `_control` sibling that exercises the adjacent
//! path the library already gets right, so the fix can be checked for
//! staying inside its intended blast radius.
//!
//! Run with any single backend, for example:
//!
//!     cargo test --features aws_lc --test sec_report
//!
//! Every scenario is built by a function returning a [`Scenario`], so the
//! identical certificates can be handed to other verifiers. The ignored
//! `dump_fixtures` test writes them out; see `sec-report-compare/README.md`
//! at the repository root.

#![cfg(any(feature = "aws_lc", feature = "ring", feature = "rust_crypto"))]

use core::net::IpAddr;
use std::path::Path;

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

/// Inside the validity window the testkit gives certificates by default,
/// which is epoch seconds 1000 to 2000.
const NOW: i64 = 1_500;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// What the leaf is being validated for.
enum Query {
    Dns(&'static str),
    Ip(&'static str),
}

/// One chain plus the identity it is presented for, and whether a correct
/// verifier accepts it.
struct Scenario {
    /// Stable identifier, used as the fixture directory name.
    name: &'static str,
    leaf: Vec<u8>,
    intermediates: Vec<Vec<u8>>,
    root: Vec<u8>,
    query: Query,
    /// `true` for the one sanity scenario every verifier must accept.
    expect_accept: bool,
}

impl Scenario {
    /// Runs the full recommended composition (RFC 5280 + server identity)
    /// over the chain, with intermediates supplied the way a TLS peer would
    /// supply them and the root as the trust store.
    ///
    /// Takes `&self` so the scenario keeps owning its DER: the certificates
    /// parsed below borrow those bytes.
    fn validate(&self) -> Result<(), String> {
        let leaf = Certificate::parse(&self.leaf).expect("leaf parses");
        let intermediates: Vec<&[u8]> = self
            .intermediates
            .iter()
            .map(Vec::as_slice)
            .collect();
        let root: &[u8] = &self.root;
        let (hostname, ip) = match self.query {
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
        match validator.validate(&leaf, &store(&intermediates)) {
            Ok(_) => Ok(()),
            Err(reasons) => Err(reasons
                .iter()
                .map(|reason| reason.to_string())
                .collect::<Vec<_>>()
                .join("; ")),
        }
    }
}

fn store<'a>(ders: &[&'a [u8]]) -> CertificateStore<'a> {
    CertificateStore::from_iter(
        ders.iter()
            .map(|der| Certificate::parse(der).expect("fixture parses")),
    )
}

/// A CA carrying the given name constraints, or none.
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

/// A two-certificate chain: leaf directly under `ca`.
fn direct(name: &'static str, ca: Ca, leaf: Vec<u8>, query: Query) -> Scenario {
    Scenario {
        name,
        leaf,
        intermediates: vec![],
        root: ca.der,
        query,
        expect_accept: false,
    }
}

#[track_caller]
fn assert_rejected(scenario: Scenario, what: &str) {
    assert!(
        !scenario.expect_accept,
        "assert_rejected called on a scenario expected to be accepted"
    );
    assert!(
        scenario.validate().is_err(),
        "FAIL-OPEN: {what} was accepted, but must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Sanity: an ordinary valid chain, which every verifier must accept
// ---------------------------------------------------------------------------

fn sanity_valid_chain() -> Scenario {
    let ca = issuer(vec![], vec![]);
    let leaf = dns_leaf(&ca, "", &["www.example.com"]);
    Scenario {
        expect_accept: true,
        ..direct(
            "sanity_valid_chain",
            ca,
            leaf,
            Query::Dns("www.example.com"),
        )
    }
}

#[test]
fn sanity_valid_chain_is_accepted() {
    assert_eq!(sanity_valid_chain().validate(), Ok(()));
}

// ---------------------------------------------------------------------------
// Finding 1: wildcard SAN evades an excluded dNSName subtree
// (rfc5280/dns_names.rs, dns_name_matches_constraint; CVE-2025-61727 class)
// ---------------------------------------------------------------------------

/// A sub-CA excluded from `evil.example.com` issues `*.example.com`. The
/// wildcard expands to the excluded name, so the chain must be rejected
/// for `evil.example.com`. The label walk compares `*` to `evil` literally,
/// finds no match, and concludes the SAN is not excluded.
fn wildcard_san_matching_excluded_name() -> Scenario {
    let ca = issuer(vec![], vec![dns("evil.example.com")]);
    let leaf = dns_leaf(&ca, "", &["*.example.com"]);
    direct(
        "wildcard_san_matching_excluded_name",
        ca,
        leaf,
        Query::Dns("evil.example.com"),
    )
}

#[test]
fn wildcard_san_matching_excluded_name_is_rejected() {
    assert_rejected(
        wildcard_san_matching_excluded_name(),
        "wildcard *.example.com under excluded evil.example.com",
    );
}

/// Control: the literal excluded name is rejected by the same issuer, so
/// only the wildcard form slips through.
fn literal_excluded_name() -> Scenario {
    let ca = issuer(vec![], vec![dns("evil.example.com")]);
    let leaf = dns_leaf(&ca, "", &["evil.example.com"]);
    direct(
        "control_literal_excluded_name",
        ca,
        leaf,
        Query::Dns("evil.example.com"),
    )
}

#[test]
fn literal_excluded_name_is_rejected_control() {
    assert_rejected(
        literal_excluded_name(),
        "literal evil.example.com under excluded evil.example.com",
    );
}

// ---------------------------------------------------------------------------
// Finding 2: trailing-dot SAN evades an excluded dNSName subtree
// (rfc5280/dns_names.rs, is_valid_dns_name / ReverseDnsLabels, versus
// server_identity_policy.rs, AnalysedCertificateHostname::new)
// ---------------------------------------------------------------------------

/// A sub-CA excluded from `evil.example.com` issues a SAN of the absolute
/// form `evil.example.com.`. The constraint matcher yields an empty first
/// label and says "no match"; the identity matcher strips the trailing
/// period and says "this is evil.example.com". The two layers disagree,
/// and the disagreement is in the attacker's favour.
fn trailing_dot_san_matching_excluded_name() -> Scenario {
    let ca = issuer(vec![], vec![dns("evil.example.com")]);
    let leaf = dns_leaf(&ca, "", &["evil.example.com."]);
    direct(
        "trailing_dot_san_matching_excluded_name",
        ca,
        leaf,
        Query::Dns("evil.example.com"),
    )
}

#[test]
fn trailing_dot_san_matching_excluded_name_is_rejected() {
    assert_rejected(
        trailing_dot_san_matching_excluded_name(),
        "absolute SAN evil.example.com. under excluded evil.example.com",
    );
}

/// Control: with a *permitted* subtree instead, the same absolute SAN is
/// rejected, because a non-match in the permitted direction fails closed.
fn trailing_dot_san_outside_permitted_subtree() -> Scenario {
    let ca = issuer(vec![dns("example.com")], vec![]);
    let leaf = dns_leaf(&ca, "", &["www.example.com."]);
    direct(
        "control_trailing_dot_san_under_permitted_subtree",
        ca,
        leaf,
        Query::Dns("www.example.com"),
    )
}

#[test]
fn trailing_dot_san_outside_permitted_subtree_is_rejected_control() {
    assert_rejected(
        trailing_dot_san_outside_permitted_subtree(),
        "absolute SAN www.example.com. under permitted example.com",
    );
}

// ---------------------------------------------------------------------------
// Finding 3: excluded iPAddress 0.0.0.0/0 and ::/0 match nothing
// (rfc5280/ip_constraints.rs, is_valid_cidr_mask)
// ---------------------------------------------------------------------------

/// The CA/Browser Forum shape of a technically-constrained sub-CA: a
/// permitted dNSName subtree, plus `excludedSubtrees` of `0.0.0.0/0` and
/// `::/0` so it can issue for no IP address at all.
fn no_ip_issuer() -> Ca {
    issuer(
        vec![dns("example.com")],
        vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
        ],
    )
}

/// An all-zero mask is treated as "matches nothing", so the exclusion is a
/// no-op and a leaf with any IP SAN validates for that address.
fn ip_san_under_all_zero_exclusion() -> Scenario {
    let ca = no_ip_issuer();
    let leaf = ip_leaf(&ca, "203.0.113.10");
    direct(
        "ip_san_under_all_zero_exclusion",
        ca,
        leaf,
        Query::Ip("203.0.113.10"),
    )
}

#[test]
fn ip_san_under_all_zero_exclusion_is_rejected() {
    assert_rejected(
        ip_san_under_all_zero_exclusion(),
        "IPv4 SAN under excluded 0.0.0.0/0",
    );
}

/// As above, for an IPv6 SAN against the `::/0` exclusion.
fn ipv6_san_under_all_zero_exclusion() -> Scenario {
    let ca = no_ip_issuer();
    let leaf = ip_leaf(&ca, "2001:db8::10");
    direct(
        "ipv6_san_under_all_zero_exclusion",
        ca,
        leaf,
        Query::Ip("2001:db8::10"),
    )
}

#[test]
fn ipv6_san_under_all_zero_exclusion_is_rejected() {
    assert_rejected(
        ipv6_san_under_all_zero_exclusion(),
        "IPv6 SAN under excluded ::/0",
    );
}

/// Control: a conventional excluded /8 is honoured, so the defect is
/// specific to the all-zero mask.
fn ip_san_under_conventional_exclusion() -> Scenario {
    let ca = issuer(
        vec![dns("example.com")],
        vec![GeneralSubtree::IpAddress(CidrSubnet::V4(
            [203, 0, 0, 0],
            [255, 0, 0, 0],
        ))],
    );
    let leaf = ip_leaf(&ca, "203.0.113.10");
    direct(
        "control_ip_san_under_conventional_exclusion",
        ca,
        leaf,
        Query::Ip("203.0.113.10"),
    )
}

#[test]
fn ip_san_under_conventional_exclusion_is_rejected_control() {
    assert_rejected(
        ip_san_under_conventional_exclusion(),
        "IPv4 SAN under excluded 203.0.0.0/8",
    );
}

// ---------------------------------------------------------------------------
// Finding 4: SAN-less leaf with a hostname in the subject CN escapes
// dNSName constraints
// (rfc5280/name_constraints_policy.rs, names(); server_identity_policy.rs,
// has_valid_identity_for_service CN fallback)
// ---------------------------------------------------------------------------

/// A sub-CA permitted only `example.com` issues a leaf with no SAN and
/// `CN=www.victim.com`. The constraint check never sees the CN as a DNS
/// name, and the identity check falls back to the CN because there is no
/// SAN. The constrained CA impersonates any host.
fn san_less_cn_outside_permitted_subtree() -> Scenario {
    let ca = issuer(vec![dns("example.com")], vec![]);
    let leaf = dns_leaf(&ca, "www.victim.com", &[]);
    direct(
        "san_less_cn_outside_permitted_subtree",
        ca,
        leaf,
        Query::Dns("www.victim.com"),
    )
}

#[test]
fn san_less_cn_outside_permitted_subtree_is_rejected() {
    assert_rejected(
        san_less_cn_outside_permitted_subtree(),
        "SAN-less CN=www.victim.com under permitted example.com",
    );
}

/// The excluded direction has the same hole.
fn san_less_cn_inside_excluded_subtree() -> Scenario {
    let ca = issuer(vec![], vec![dns("victim.com")]);
    let leaf = dns_leaf(&ca, "www.victim.com", &[]);
    direct(
        "san_less_cn_inside_excluded_subtree",
        ca,
        leaf,
        Query::Dns("www.victim.com"),
    )
}

#[test]
fn san_less_cn_inside_excluded_subtree_is_rejected() {
    assert_rejected(
        san_less_cn_inside_excluded_subtree(),
        "SAN-less CN=www.victim.com under excluded victim.com",
    );
}

/// Control: the same name presented as a SAN is caught by the constraint.
fn san_outside_permitted_subtree() -> Scenario {
    let ca = issuer(vec![dns("example.com")], vec![]);
    let leaf = dns_leaf(&ca, "www.victim.com", &["www.victim.com"]);
    direct(
        "control_san_outside_permitted_subtree",
        ca,
        leaf,
        Query::Dns("www.victim.com"),
    )
}

#[test]
fn san_outside_permitted_subtree_is_rejected_control() {
    assert_rejected(
        san_outside_permitted_subtree(),
        "SAN www.victim.com under permitted example.com",
    );
}

// ---------------------------------------------------------------------------
// Finding 5: a v1 end-entity certificate acts as an intermediate
// (rfc5280/basic_constraints_policy.rs, the `if !is_v1` exemption)
// ---------------------------------------------------------------------------

/// The one certificate shape the generator cannot emit: a v1 certificate
/// signed by `ca`, carrying `key_pair`'s public key and `subject_cn`. Built
/// by issuing an ordinary v3 leaf, removing its version field and its
/// extensions, and re-signing the result with the CA key. Everything else
/// (serial, algorithm identifiers, issuer, validity, subject, SPKI) is
/// kept verbatim.
fn v1_certificate_signed_by(ca: &Ca, subject_cn: &str, key_pair: KeyPair) -> Vec<u8> {
    let v3 = LeafSpec::new(subject_cn)
        .key_pair(key_pair)
        .signed_by(ca);

    let certificate = der::contents_of(&v3, 0x30);
    let (tbs, rest) = der::split_first(certificate);
    let (signature_algorithm, _) = der::split_first(rest);

    let tbs_contents = der::contents_of(tbs, 0x30);
    let mut fields: Vec<&[u8]> = der::elements(tbs_contents);
    // Drop `version [0] EXPLICIT` at the front, if present, and
    // `extensions [3] EXPLICIT` at the back, if present: a v1 certificate
    // has neither.
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

/// Minimal DER reading and writing for `v1_certificate_signed_by`.
mod der {
    /// Splits the first TLV off `bytes`, returning it and the remainder.
    pub(super) fn split_first(bytes: &[u8]) -> (&[u8], &[u8]) {
        let (header_len, content_len) = header(bytes);
        bytes.split_at(header_len + content_len)
    }

    /// The contents of the TLV at the start of `bytes`, which must carry
    /// `expected_tag`.
    pub(super) fn contents_of(bytes: &[u8], expected_tag: u8) -> &[u8] {
        assert_eq!(bytes[0], expected_tag, "unexpected DER tag");
        let (header_len, content_len) = header(bytes);
        &bytes[header_len..header_len + content_len]
    }

    /// Every top-level TLV in `bytes`, in order.
    pub(super) fn elements(mut bytes: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let (element, rest) = split_first(bytes);
            out.push(element);
            bytes = rest;
        }
        out
    }

    /// `(header length, content length)` of the TLV at the start of `bytes`.
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

    /// A DER TLV: `tag`, a definite-form length, then `contents`.
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

/// `leaf -> device certificate -> root`, where the device certificate is a
/// root-signed end-entity certificate (v1 or v3 per `v1`) whose key the
/// attacker holds, used to sign a leaf for `www.victim.com`.
fn chain_through_end_entity(name: &'static str, v1: bool) -> Scenario {
    let root = self_signed_ca_with("legacy-root", |_| {});

    // The attacker's key, in two copies: one is consumed building the
    // device certificate that carries it, the other signs the leaf.
    let device_key = KeyPair::generate().expect("generate key pair");
    let device_key_der = device_key.serialize_der();
    let device_key_again = KeyPair::try_from(device_key_der.as_slice()).expect("reload key");

    let device_cert = if v1 {
        v1_certificate_signed_by(&root, "legacy-device", device_key)
    } else {
        LeafSpec::new("legacy-device")
            .key_pair(device_key)
            .signed_by(&root)
    };

    let mut device_params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "legacy-device");
    device_params.distinguished_name = dn;
    let device_as_issuer = Issuer::from_params(&device_params, &device_key_again);

    let leaf_key = KeyPair::generate().expect("generate key pair");
    let mut leaf_params =
        CertificateParams::new(vec!["www.victim.com".to_string()]).expect("leaf params");
    leaf_params.not_before = OffsetDateTime::UNIX_EPOCH + Duration::seconds(1000);
    leaf_params.not_after = OffsetDateTime::UNIX_EPOCH + Duration::seconds(2000);
    let leaf = leaf_params
        .signed_by(&leaf_key, &device_as_issuer)
        .expect("sign leaf")
        .der()
        .to_vec();

    Scenario {
        name,
        leaf,
        intermediates: vec![device_cert],
        root: root.der,
        query: Query::Dns("www.victim.com"),
        expect_accept: false,
    }
}

/// A trusted root once issued a v1 end-entity certificate to a key the
/// attacker now holds (a legacy device certificate, say). The v1
/// certificate carries no CA marking, and cannot, but the basic-constraints
/// check exempts v1 certificates from the cA requirement, so the chain
/// validates. RFC 5280 §6.1.4 (k) says a v1 intermediate must be verified
/// as a CA out of band or rejected.
fn v1_end_entity_as_intermediate() -> Scenario {
    let scenario = chain_through_end_entity("v1_end_entity_as_intermediate", true);

    // Certificate::parse must see a v1 certificate with no extensions, or
    // the scenario is not exercising the exemption.
    let parsed = Certificate::parse(&scenario.intermediates[0]).expect("v1 cert parses");
    assert_eq!(parsed.version().0, 0, "expected a v1 certificate");
    assert!(
        parsed.extensions().is_empty(),
        "expected a v1 certificate with no extensions"
    );

    scenario
}

#[test]
fn v1_end_entity_certificate_is_not_accepted_as_intermediate() {
    assert_rejected(
        v1_end_entity_as_intermediate(),
        "leaf -> v1 end-entity certificate -> root",
    );
}

/// Control: the identical chain with a v3 end-entity certificate in the
/// middle is rejected, because that certificate lacks `cA=TRUE`. The v1
/// exemption is the only difference.
fn v3_end_entity_as_intermediate() -> Scenario {
    chain_through_end_entity("control_v3_end_entity_as_intermediate", false)
}

#[test]
fn v3_end_entity_certificate_is_not_accepted_as_intermediate_control() {
    assert_rejected(
        v3_end_entity_as_intermediate(),
        "leaf -> v3 end-entity certificate -> root",
    );
}

// ---------------------------------------------------------------------------
// Fixture export for other verifiers
// ---------------------------------------------------------------------------

/// Every scenario above, in report order.
fn all_scenarios() -> Vec<Scenario> {
    vec![
        sanity_valid_chain(),
        wildcard_san_matching_excluded_name(),
        literal_excluded_name(),
        trailing_dot_san_matching_excluded_name(),
        trailing_dot_san_outside_permitted_subtree(),
        ip_san_under_all_zero_exclusion(),
        ipv6_san_under_all_zero_exclusion(),
        ip_san_under_conventional_exclusion(),
        san_less_cn_outside_permitted_subtree(),
        san_less_cn_inside_excluded_subtree(),
        san_outside_permitted_subtree(),
        v1_end_entity_as_intermediate(),
        v3_end_entity_as_intermediate(),
    ]
}

/// Writes one directory per scenario under `$SEC_REPORT_FIXTURES_DIR`:
/// `leaf.der`, `root.der`, `inter-N.der` for each intermediate, and
/// `query.txt` holding `dns <name>` or `ip <address>` on the first line and
/// `accept` or `reject` on the second. Run with:
///
///     SEC_REPORT_FIXTURES_DIR=sec-report-compare/fixtures \
///       cargo test --features aws_lc --test sec_report -- --ignored dump_fixtures
#[test]
#[ignore = "writes fixtures for the cross-verifier comparison; run on demand"]
fn dump_fixtures() {
    let dir = std::env::var("SEC_REPORT_FIXTURES_DIR")
        .expect("set SEC_REPORT_FIXTURES_DIR to the output directory");
    let dir = Path::new(&dir);

    for scenario in all_scenarios() {
        let out = dir.join(scenario.name);
        std::fs::create_dir_all(&out).expect("create scenario dir");
        std::fs::write(out.join("leaf.der"), &scenario.leaf).expect("write leaf");
        std::fs::write(out.join("root.der"), &scenario.root).expect("write root");
        for (i, inter) in scenario
            .intermediates
            .iter()
            .enumerate()
        {
            std::fs::write(out.join(format!("inter-{i}.der")), inter).expect("write inter");
        }
        let query = match scenario.query {
            Query::Dns(name) => format!("dns {name}"),
            Query::Ip(ip) => format!("ip {ip}"),
        };
        let expect = if scenario.expect_accept {
            "accept"
        } else {
            "reject"
        };
        std::fs::write(out.join("query.txt"), format!("{query}\n{expect}\n")).expect("write query");
    }
}
