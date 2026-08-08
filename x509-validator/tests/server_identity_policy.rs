//! Server identity matching: DNS names, IP addresses, and common-name
//! fallback.

use x509_validator::{ServerIdentityPolicy, ValidationPolicy};
use x509_validator_core::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME;
use x509_validator_testkit::rcgen::string::Ia5String;
use x509_validator_testkit::rcgen::{DistinguishedName, DnType, SanType};
use x509_validator_testkit::{
    chain_of, issue_leaf, issue_leaf_with, issue_leaf_with_dn, issue_leaf_with_email_sans,
    issue_leaf_with_ip_sans, self_signed_ca_with,
};

fn cert_with_sans(sans: &[&str]) -> Vec<u8> {
    let root = self_signed_ca_with("root", |_| {});
    issue_leaf("leaf", sans, &root)
}

fn cert_with_ip_sans(ips: Vec<std::net::IpAddr>) -> Vec<u8> {
    let root = self_signed_ca_with("root", |_| {});
    issue_leaf_with_ip_sans("leaf", ips, &root)
}

fn cert_with_common_name(cn: &str) -> Vec<u8> {
    let root = self_signed_ca_with("root", |_| {});
    issue_leaf(cn, &[], &root)
}

#[test]
fn exact_dns_name_match_is_accepted() {
    let chain = chain_of(vec![cert_with_sans(&["www.example.com"])]);
    let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn dns_name_match_is_case_insensitive() {
    let chain = chain_of(vec![cert_with_sans(&["WWW.EXAMPLE.COM"])]);
    let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn non_matching_dns_name_is_rejected() {
    let chain = chain_of(vec![cert_with_sans(&["www.example.com"])]);
    let mut policy = ServerIdentityPolicy::new(Some("evil.com"), None);
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn wildcard_matches_single_label() {
    let chain = chain_of(vec![cert_with_sans(&["*.example.com"])]);
    let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn wildcard_does_not_match_multiple_labels() {
    let chain = chain_of(vec![cert_with_sans(&["*.example.com"])]);
    let mut policy = ServerIdentityPolicy::new(Some("foo.bar.example.com"), None);
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn wildcard_must_match_at_least_one_character() {
    let chain = chain_of(vec![cert_with_sans(&["*.example.com"])]);
    let mut policy = ServerIdentityPolicy::new(Some(".example.com"), None);
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn hostname_of_only_periods_does_not_match_a_wildcard() {
    // Stripping the trailing period can empty the hostname while it still records the offset of a
    // period, and matching a wildcard is what splits the hostname around that offset. Each of
    // these must come back as an ordinary mismatch.
    for hostname in [".", "..", "..."] {
        let chain = chain_of(vec![cert_with_sans(&["*.example.com"])]);
        let mut policy = ServerIdentityPolicy::new(Some(hostname), None);
        assert!(
            policy.chain_meets_policy_requirements(&chain).is_err(),
            "hostname {hostname:?} must not match"
        );
    }
}

#[test]
fn partial_wildcard_matches_prefix_and_suffix() {
    let chain = chain_of(vec![cert_with_sans(&["f*o.example.com"])]);
    let mut policy = ServerIdentityPolicy::new(Some("foo.example.com"), None);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn wildcard_after_first_label_is_rejected() {
    // "www.*.com" has the asterisk after the first period — invalid.
    let chain = chain_of(vec![cert_with_sans(&["www.*.com"])]);
    let mut policy = ServerIdentityPolicy::new(Some("www.anything.com"), None);
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn ipv4_san_matches_server_ip() {
    let chain = chain_of(vec![cert_with_ip_sans(vec!["127.0.0.1".parse().unwrap()])]);
    let mut policy = ServerIdentityPolicy::new(None, Some("127.0.0.1"));
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn ipv4_san_does_not_match_different_server_ip() {
    let chain = chain_of(vec![cert_with_ip_sans(vec!["127.0.0.1".parse().unwrap()])]);
    let mut policy = ServerIdentityPolicy::new(None, Some("127.0.0.2"));
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn ipv6_san_matches_server_ip() {
    let chain = chain_of(vec![cert_with_ip_sans(vec!["2001:db8::1".parse().unwrap()])]);
    let mut policy = ServerIdentityPolicy::new(None, Some("2001:db8::1"));
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn common_name_is_never_matched_against_an_ip_address() {
    let chain = chain_of(vec![cert_with_common_name("127.0.0.1")]);
    let mut policy = ServerIdentityPolicy::new(None, Some("127.0.0.1"));
    // No hostname supplied, only an IP — the CN path only ever compares
    // against a hostname, never an IP, so this must fail even though
    // the CN textually equals the target IP.
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn no_san_and_no_common_name_is_rejected() {
    let root = self_signed_ca_with("root", |_| {});
    let der = issue_leaf_with_ip_sans("", vec![], &root);
    let chain = chain_of(vec![der]);
    let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn san_present_but_no_match_never_falls_back_to_common_name() {
    // Even though the common name would match, having a (non-matching)
    // SAN extension present must suppress the CN fallback entirely.
    let root = self_signed_ca_with("root", |_| {});
    let der = issue_leaf("www.example.com", &["other.example.com"], &root);
    let chain = chain_of(vec![der]);
    let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn non_matchable_san_entry_still_suppresses_common_name_fallback() {
    // The SAN extension holds only an rfc822Name, which can never match
    // a service identity. RFC 6125 §6 nevertheless forbids falling back
    // to the common name once any SAN entry is present, so the matching
    // common name must not rescue this certificate.
    let root = self_signed_ca_with("root", |_| {});
    let der = issue_leaf_with_email_sans("www.example.com", &["admin@example.com"], &root);
    let chain = chain_of(vec![der]);
    let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn non_matchable_san_entry_alongside_matching_dns_name_still_matches() {
    // An unmatchable entry must not prevent a sibling dNSName entry from
    // satisfying the policy.
    let root = self_signed_ca_with("root", |_| {});
    let der = issue_leaf_with("leaf", &["www.example.com"], &root, |params| {
        params
            .subject_alt_names
            .push(SanType::Rfc822Name(Ia5String::try_from("admin@example.com").unwrap()));
    });
    let chain = chain_of(vec![der]);
    let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn no_san_falls_back_to_common_name() {
    let chain = chain_of(vec![cert_with_common_name("www.example.com")]);
    let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn wildcard_combined_with_idna_a_label_is_rejected() {
    // "xn--*.example.com" pairs a wildcard with a punycode-looking
    // first label; this must never validate, closing the homograph
    // attack the IDNA check exists to prevent.
    let chain = chain_of(vec![cert_with_sans(&["xn--*.example.com"])]);
    let mut policy = ServerIdentityPolicy::new(Some("xn--anything.example.com"), None);
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn no_server_hostname_never_matches_dns_san() {
    let chain = chain_of(vec![cert_with_sans(&["www.example.com"])]);
    let mut policy = ServerIdentityPolicy::new(None, None);
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn verifying_critical_extensions_includes_subject_alt_name_oid() {
    let policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
    let oids = policy.verifying_critical_extensions();
    assert!(oids.contains(&OID_X509_EXT_SUBJECT_ALT_NAME));
}

/// The commonName OID (2.5.4.3) spelled out as a custom attribute type.
///
/// `rcgen`'s `DistinguishedName` is keyed by attribute type, so the same
/// well-known `DnType` can only appear once. Naming the OID explicitly
/// yields a second, distinct key that still encodes as commonName, which
/// is how the multi-commonName fixture below gets built.
fn custom_common_name() -> DnType {
    DnType::CustomDnType(vec![2, 5, 4, 3])
}

/// A certificate whose subjectAltName extension collects every awkward
/// dNSName shape worth exercising, in the order documented below. Its
/// subject also carries a commonName of `httpbin.org`, which must never
/// be consulted because the SAN extension is present.
fn weirdo_san_cert() -> Vec<u8> {
    let root = self_signed_ca_with("root", |_| {});
    issue_leaf_with("httpbin.org", &[], &root, |params| {
        let names = [
            // A plain wildcard, matchable.
            "*.WILDCARD.EXAMPLE.com",
            // A suffix wildcard, matchable.
            "FO*.EXAMPLE.com",
            // A prefix wildcard, matchable.
            "*AR.EXAMPLE.com",
            // An infix wildcard, matchable.
            "B*Z.EXAMPLE.com",
            // A trailing period, which is not significant.
            "TRAILING.PERIOD.EXAMPLE.com.",
            // An IDNA A-label, matchable in its encoded form only.
            "XN--STRAE-OQA.UNICODE.EXAMPLE.com.",
            // An IDNA A-label carrying a wildcard, which RFC 6125 §6.4.3
            // never permits to match.
            "XN--X*-GIA.UNICODE.EXAMPLE.com.",
            // A wildcard outside the leftmost label, never matchable.
            "WEIRDWILDCARD.*.EXAMPLE.com.",
            // Two wildcards, never matchable.
            "*.*.DOUBLE.EXAMPLE.com.",
            // A wildcard whose *following* label is an A-label; only the
            // wildcard label itself is restricted, so this is matchable.
            "*.XN--STRAE-OQA.EXAMPLE.com.",
            // An embedded NUL, which is not a legal DNS character.
            "\u{0}",
        ];
        params.subject_alt_names = names
            .iter()
            .map(|name| SanType::DnsName(Ia5String::try_from(*name).expect("valid IA5 san")))
            .collect();
    })
}

/// A certificate with a mixture of SAN entry kinds: two dNSNames, an
/// rfc822Name, and both an IPv4 and an IPv6 iPAddress.
fn multi_san_cert() -> Vec<u8> {
    let root = self_signed_ca_with("root", |_| {});
    issue_leaf_with("localhost", &["localhost", "example.com"], &root, |params| {
        params
            .subject_alt_names
            .push(SanType::Rfc822Name(Ia5String::try_from("user@example.com").unwrap()));
        params.subject_alt_names.push(SanType::IpAddress("192.168.0.1".parse().unwrap()));
        params.subject_alt_names.push(SanType::IpAddress("2001:db8::1".parse().unwrap()));
    })
}

/// A certificate with no SAN extension whose subject holds two
/// commonName attributes; only the last one counts.
fn multi_cn_cert() -> Vec<u8> {
    let root = self_signed_ca_with("root", |_| {});
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "US");
    dn.push(custom_common_name(), "Ignore me");
    dn.push(DnType::StateOrProvinceName, "Nebraska");
    dn.push(DnType::CommonName, "localhost");
    issue_leaf_with_dn(dn, &root, |_| {})
}

/// A certificate with no SAN extension and no commonName at all.
fn no_cn_cert() -> Vec<u8> {
    let root = self_signed_ca_with("root", |_| {});
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "US");
    dn.push(DnType::StateOrProvinceName, "Nebraska");
    issue_leaf_with_dn(dn, &root, |_| {})
}

/// A certificate with no SAN extension whose commonName is a non-ASCII
/// U-label.
fn unicode_cn_cert() -> Vec<u8> {
    let root = self_signed_ca_with("root", |_| {});
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "straße.org");
    issue_leaf_with_dn(dn, &root, |_| {})
}

fn assert_matches(der: Vec<u8>, hostname: Option<&str>, ip: Option<&str>) {
    let chain = chain_of(vec![der]);
    let mut policy = ServerIdentityPolicy::new(hostname, ip);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

fn assert_does_not_match(der: Vec<u8>, hostname: Option<&str>, ip: Option<&str>) {
    let chain = chain_of(vec![der]);
    let mut policy = ServerIdentityPolicy::new(hostname, ip);
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn can_validate_hostname_in_first_san() {
    assert_matches(multi_san_cert(), Some("localhost"), None);
}

#[test]
fn can_validate_hostname_in_second_san() {
    assert_matches(multi_san_cert(), Some("example.com"), None);
}

#[test]
fn ignores_trailing_period_in_requested_hostname() {
    assert_matches(multi_san_cert(), Some("example.com."), None);
}

#[test]
fn lowercases_requested_hostname_for_san() {
    assert_matches(multi_san_cert(), Some("LoCaLhOsT"), None);
}

#[test]
fn rejects_incorrect_hostname() {
    assert_does_not_match(multi_san_cert(), Some("httpbin.org"), None);
}

#[test]
fn accepts_ipv4_address() {
    assert_matches(multi_san_cert(), None, Some("192.168.0.1"));
}

#[test]
fn accepts_ipv6_address() {
    assert_matches(multi_san_cert(), None, Some("2001:db8::1"));
}

#[test]
fn rejects_incorrect_ipv4_address() {
    assert_does_not_match(multi_san_cert(), None, Some("192.168.0.2"));
}

#[test]
fn rejects_incorrect_ipv6_address() {
    assert_does_not_match(multi_san_cert(), None, Some("2001:db8::2"));
}

#[test]
fn accepts_plain_wildcard() {
    assert_matches(weirdo_san_cert(), Some("this.wildcard.example.com"), None);
}

#[test]
fn accepts_suffix_wildcard() {
    assert_matches(weirdo_san_cert(), Some("foo.example.com"), None);
}

#[test]
fn accepts_prefix_wildcard() {
    assert_matches(weirdo_san_cert(), Some("bar.example.com"), None);
}

#[test]
fn accepts_infix_wildcard() {
    assert_matches(weirdo_san_cert(), Some("baz.example.com"), None);
}

#[test]
fn ignores_trailing_period_in_certificate_san() {
    assert_matches(weirdo_san_cert(), Some("trailing.period.example.com"), None);
}

#[test]
fn rejects_encoded_idna_label() {
    // The requested hostname is a U-label; certificate names are always
    // A-labels, so this can never match and we do not transcode.
    assert_does_not_match(weirdo_san_cert(), Some("straße.unicode.example.com"), None);
}

#[test]
fn matches_unencoded_idna_label() {
    assert_matches(weirdo_san_cert(), Some("xn--strae-oqa.unicode.example.com"), None);
}

#[test]
fn does_not_match_idna_label_with_wildcard() {
    // RFC 6125 §6.4.3: a wildcard must not be combined with an A-label.
    assert_does_not_match(weirdo_san_cert(), Some("xn--xx-gia.unicode.example.com"), None);
}

#[test]
fn does_not_match_non_leftmost_wildcards() {
    assert_does_not_match(weirdo_san_cert(), Some("weirdwildcard.nomatch.example.com"), None);
}

#[test]
fn does_not_match_multiple_wildcards() {
    assert_does_not_match(weirdo_san_cert(), Some("one.two.double.example.com"), None);
}

#[test]
fn rejects_wildcard_before_unencoded_idna_label() {
    assert_does_not_match(weirdo_san_cert(), Some("foo.straße.example.com"), None);
}

#[test]
fn matches_wildcard_before_encoded_idna_label() {
    // The A-label restriction applies only to the wildcard label itself,
    // so an A-label in a later position is perfectly matchable.
    assert_matches(weirdo_san_cert(), Some("foo.xn--strae-oqa.example.com"), None);
}

#[test]
fn does_not_match_san_with_embedded_nul() {
    assert_does_not_match(weirdo_san_cert(), Some("nul\u{0}l.example.com"), None);
}

#[test]
fn falls_back_to_last_common_name() {
    assert_matches(multi_cn_cert(), Some("localhost"), None);
}

#[test]
fn lowercases_requested_hostname_for_common_name() {
    assert_matches(multi_cn_cert(), Some("LoCaLhOsT"), None);
}

#[test]
fn rejects_unicode_common_name_with_unencoded_idna_label() {
    assert_does_not_match(unicode_cn_cert(), Some("straße.org"), None);
}

#[test]
fn rejects_unicode_common_name_with_encoded_idna_label() {
    // The common name holds a U-label, so its A-label form must not match.
    assert_does_not_match(unicode_cn_cert(), Some("xn--strae-oqa.org"), None);
}

#[test]
fn handles_missing_common_name() {
    assert_does_not_match(no_cn_cert(), Some("localhost"), None);
}

#[test]
fn does_not_fall_back_to_common_name_when_sans_are_present() {
    // The subject's common name is `httpbin.org`, but the SAN extension
    // is present, so RFC 6125 §6 forbids consulting it.
    assert_does_not_match(weirdo_san_cert(), Some("httpbin.org"), None);
}
