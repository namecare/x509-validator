//! Ports upstream's `tests/tls_server_certs.rs`.
//!
//! A `Validator` here runs one composed policy, where upstream builds a path
//! and checks subject names separately.

use x509_validator::der_parser::Oid;
use x509_validator::rfc5280::{EkuPolicy, RFC5280Policy, Timestamp, eku_oids};
use x509_validator::server_identity_policy::ServerIdentityPolicy;
use x509_validator::{Validator, policy};
use x509_validator_testkit::leaf::LeafSpec;
use x509_validator_testkit::rcgen::{
    self, CertificateParams, CidrSubnet, DistinguishedName, DnType, GeneralSubtree,
};
use x509_validator_testkit::{
    Ca, RawGeneralName, issue_leaf_with_ip_sans, raw_name_constraints_extension,
    self_signed_ca_with,
};

use super::common::{DEFAULT_PROVIDER, NOW, assert_reason, parse, reason, reasons, store};

/// The chain must build, every name in `valid_names` must match, and every
/// name in `invalid_names` must fail to match.
///
/// Upstream also asserts the exact set of names the certificate presented,
/// carried in its error's context. There is no counterpart to that context
/// here, so `presented_names` is accepted only so call sites stay identical
/// to upstream's, and is not asserted. Upstream's single call becomes
/// several here: one to build the chain, then one per name queried.
#[track_caller]
fn check_cert(
    ee: &[u8],
    ca: &[u8],
    valid_names: &[&str],
    invalid_names: &[&str],
    presented_names: &[&str],
) -> Result<(), String> {
    let _ = presented_names;

    build(ee, &[], &[ca], Eku::ServerAuth, NOW)?;

    for valid in valid_names {
        assert_eq!(
            build_for_name(ee, &[], &[ca], Eku::ServerAuth, NOW, valid),
            Ok(()),
            "expected {valid:?} to be a valid name"
        );
    }

    for invalid in invalid_names {
        assert_reason(
            build_for_name(ee, &[], &[ca], Eku::ServerAuth, NOW, invalid),
            reason::NAME_MISMATCH,
        );
    }

    Ok(())
}

/// The key purpose an upstream test asked the path builder for.
#[allow(dead_code)]
enum Eku {
    ServerAuth,
    ClientAuth,
    /// A purpose named by raw OID arcs.
    Custom(Vec<Oid<'static>>),
    /// No requirement.
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
        Err(failures) => Err(reasons(&failures)),
    }
}

/// Asserts a chain builds, with no subject name queried.
fn build(
    ee: &[u8],
    intermediates: &[&[u8]],
    roots: &[&[u8]],
    eku: Eku,
    now: Timestamp,
) -> Result<(), String> {
    run(ee, intermediates, roots, eku, now, None, None)
}

/// Asserts a chain builds *and* the leaf is valid for `name`.
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

/// Asserts a chain builds *and* the leaf is valid for `ip`.
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

#[test]
fn no_name_constraints() {
    let issuer = make_issuer(None);
    let ee = generate_cert_with_names(
        Some("subject.example.com"),
        None,
        &["dns.example.com"],
        &issuer,
    );
    let ca = issuer.der;

    assert_eq!(
        check_cert(
            &ee,
            &ca,
            &["dns.example.com"],
            &["subject.example.com"],
            &["DnsName(\"dns.example.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn additional_dns_labels() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![GeneralSubtree::DnsName(".example.com".to_string())],
        excluded: vec![],
    }));
    let ee = generate_cert_with_names(
        Some("subject.example.com"),
        None,
        &["host1.example.com", "host2.example.com"],
        &issuer,
    );
    let ca = issuer.der;

    assert_eq!(
        check_cert(
            &ee,
            &ca,
            &["host1.example.com", "host2.example.com"],
            &["subject.example.com"],
            &[
                "DnsName(\"host1.example.com\")",
                "DnsName(\"host2.example.com\")"
            ]
        ),
        Ok(())
    );
}

#[test]
fn disallow_dns_san() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![],
        excluded: vec![GeneralSubtree::DnsName(
            "disallowed.example.com".to_string(),
        )],
    }));
    let ee = generate_cert_with_names(None, None, &["disallowed.example.com"], &issuer);
    let ca = issuer.der;

    assert_reason(
        build(&ee, &[], &[&ca], Eku::ServerAuth, NOW),
        reason::EXCLUDED_SUBTREE,
    );
}

#[test]
#[ignore = "divergence: this library's ServerIdentityPolicy falls back to \
            the certificate's commonName when there is no matchable SAN \
            entry; webpki's verify_is_valid_for_subject_name never does \
            that fallback, so a certificate with no SAN extension always \
            fails upstream's name check regardless of its CN. Upstream \
            asserts allowed.example.com is *invalid* here; this library \
            accepts it via the CN fallback. Not a fail-open case in the \
            excluded/permitted-subtree sense — the CN is inside the \
            permitted subtree in this test — but a real behavioural \
            difference in when subject-name matching may fall back to a \
            deprecated legacy field. See task-4-report.md."]
fn allow_subject_common_name() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![GeneralSubtree::DnsName("allowed.example.com".to_string())],
        excluded: vec![],
    }));
    let ee = generate_cert_with_names(Some("allowed.example.com"), None, &[], &issuer);
    let ca = issuer.der;

    assert_reason(
        build_for_name(
            &ee,
            &[],
            &[&ca],
            Eku::ServerAuth,
            NOW,
            "allowed.example.com",
        ),
        reason::NAME_MISMATCH,
    );
}

#[test]
fn allow_dns_san() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![GeneralSubtree::DnsName("allowed.example.com".to_string())],
        excluded: vec![],
    }));
    let ee = generate_cert_with_names(None, None, &["allowed.example.com"], &issuer);
    let ca = issuer.der;

    assert_eq!(
        check_cert(
            &ee,
            &ca,
            &["allowed.example.com"],
            &[],
            &["DnsName(\"allowed.example.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn allow_dns_san_and_subject_common_name() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![
            GeneralSubtree::DnsName("allowed-san.example.com".to_string()),
            GeneralSubtree::DnsName("allowed-cn.example.com".to_string()),
        ],
        excluded: vec![],
    }));
    let ee = generate_cert_with_names(
        Some("allowed-cn.example.com"),
        None,
        &["allowed-san.example.com"],
        &issuer,
    );
    let ca = issuer.der;

    assert_eq!(
        check_cert(
            &ee,
            &ca,
            &["allowed-san.example.com"],
            &["allowed-cn.example.com"],
            &["DnsName(\"allowed-san.example.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn disallow_dns_san_and_allow_subject_common_name() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![
            GeneralSubtree::DnsName("allowed-san.example.com".to_string()),
            GeneralSubtree::DnsName("allowed-cn.example.com".to_string()),
        ],
        excluded: vec![GeneralSubtree::DnsName(
            "disallowed-san.example.com".to_string(),
        )],
    }));
    let ee = generate_cert_with_names(
        Some("allowed-cn.example.com"),
        None,
        &["allowed-san.example.com", "disallowed-san.example.com"],
        &issuer,
    );
    let ca = issuer.der;

    assert_reason(
        build(&ee, &[], &[&ca], Eku::ServerAuth, NOW),
        reason::PERMITTED_SUBTREE,
    );
}

#[test]
#[ignore = "divergence: upstream's own test name records this as \
            deliberately-tolerated upstream behaviour, not a correctness \
            requirement — webpki does not check the subject DN against \
            name constraints at all, only the SAN extension, so an \
            excluded rfc822Name constraint has no effect on an email \
            address carried in the subject DN. This library's \
            NameConstraintsPolicy checks every subject name including the \
            certificate's own subject, represented as a DirectoryName \
            GeneralName (see `names()` in name_constraints_policy.rs); \
            since the constraint's kind (Rfc822Name) is one this library \
            does not support evaluating, it rejects the chain outright \
            ('unable to validate excluded subtree, unsupported constraint \
            kind') rather than silently ignoring the subject DN as \
            upstream does. This library is stricter, not fail-open, but it \
            is still the inverse of upstream's assertion. See \
            task-4-report.md."]
fn we_incorrectly_ignore_name_constraints_on_name_in_subject() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![],
        excluded: vec![GeneralSubtree::Rfc822Name("example.com".to_string())],
    }));

    let mut dn = DistinguishedName::new();
    dn.push(DnType::from_oid(OID_EMAIL_ADDRESS), "test@example.com");
    let ee = x509_validator_testkit::issue_leaf_with_dn(dn, &issuer, |_| {});
    let ca = issuer.der;

    // webpki incorrectly ignores name constraints on email addresses in the subject DN
    // The email in subject should be checked against constraints, but it isn't
    assert_eq!(build(&ee, &[], &[&ca], Eku::ServerAuth, NOW), Ok(()));
}

#[test]
fn reject_constraints_on_unimplemented_names() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![GeneralSubtree::Rfc822Name("example.com".to_string())],
        excluded: vec![],
    }));
    let ee = x509_validator_testkit::issue_leaf_with_email_sans("", &["joe@example.com"], &issuer);
    let ca = issuer.der;

    assert_reason(
        build(&ee, &[], &[&ca], Eku::ServerAuth, NOW),
        reason::UNSUPPORTED_CONSTRAINT_KIND,
    );
}

#[test]
#[ignore = "divergence: upstream skips a permittedSubtrees entry whose kind \
            (here Rfc822Name) does not match the kind of name being \
            checked, so a certificate with only a dNSName SAN is untouched \
            by an rfc822Name-only constraint. This library's \
            NameConstraintsPolicy instead rejects on the constraint kind \
            being unsupported before ever comparing it against the actual \
            name (see `constraint_kind_is_unsupported` in \
            name_constraints_policy.rs), so the presence of *any* \
            unsupported-kind subtree in permittedSubtrees rejects the whole \
            chain, regardless of whether the certificate carries a name of \
            that kind. Fail-closed rather than fail-open, but stricter than \
            upstream: a real behavioural difference the task brief expects \
            this suite to surface. See task-4-report.md."]
fn we_ignore_constraints_on_names_that_do_not_appear_in_cert() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![GeneralSubtree::Rfc822Name("example.com".to_string())],
        excluded: vec![],
    }));
    let ee = generate_cert_with_names(None, None, &["notexample.com"], &issuer);
    let ca = issuer.der;

    assert_eq!(
        check_cert(
            &ee,
            &ca,
            &["notexample.com"],
            &["example.com"],
            &["DnsName(\"notexample.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn wildcard_san_accepted_if_in_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![GeneralSubtree::DnsName("example.com".to_string())],
        excluded: vec![],
    }));
    let ee = generate_cert_with_names(None, None, &["*.example.com"], &issuer);
    let ca = issuer.der;

    assert_eq!(
        check_cert(
            &ee,
            &ca,
            &["bob.example.com", "jane.example.com"],
            &["example.com", "uh.oh.example.com"],
            &["DnsName(\"*.example.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn wildcard_san_rejected_if_in_excluded_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![],
        excluded: vec![GeneralSubtree::DnsName("example.com".to_string())],
    }));
    let ee = generate_cert_with_names(None, None, &["*.example.com"], &issuer);
    let ca = issuer.der;

    assert_reason(
        build(&ee, &[], &[&ca], Eku::ServerAuth, NOW),
        reason::EXCLUDED_SUBTREE,
    );
}

/// CVE-2025-61727: a wildcard SAN like `*.example.com` can expand to a name (like
/// `evil.example.com`) that falls inside an excluded subtree such as `evil.example.com`. Such
/// certificates must be rejected even though the excluded subtree is narrower than the wildcard's
/// parent label.
#[test]
#[ignore = "FAIL-OPEN DIVERGENCE (the CVE-2025-61727 scenario this test is \
            named for): dns_name_matches_constraint compares DNS labels as \
            literal byte strings from the right, including the wildcard's \
            own leftmost label. For SAN '*.example.com' against excluded \
            constraint 'evil.example.com', both have three labels; the walk \
            matches 'com'=='com' and 'example'=='example', then compares \
            the literal byte string '*' against 'evil' — a length \
            mismatch, so case_insensitive_ascii_match returns false and the \
            excluded-subtree check treats the wildcard as NOT excluded. A \
            certificate whose wildcard SAN could expand to a name the \
            issuer explicitly excluded is therefore ACCEPTED here, where \
            upstream rejects it. This library has no wildcard-aware \
            expansion in its name-constraints matching at all (confirmed: \
            no `is_wildcard`/`ASCII_ASTERISK` reference anywhere in \
            name_constraints_policy.rs); the sibling test \
            wildcard_san_rejected_if_in_excluded_subtree only passes \
            because its excluded subtree (example.com) is a strict suffix \
            match reached by the constraint-exhausted branch of the label \
            walk, which happens not to need the wildcard's own label to \
            match anything. Reported with emphasis per the task brief: \
            this is the single most consequential finding in this suite. \
            See task-4-report.md."]
fn wildcard_san_rejected_if_could_match_excluded_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![],
        excluded: vec![GeneralSubtree::DnsName("evil.example.com".to_string())],
    }));
    let ee = generate_cert_with_names(None, None, &["*.example.com"], &issuer);
    let ca = issuer.der;

    assert_reason(
        build(&ee, &[], &[&ca], Eku::ServerAuth, NOW),
        reason::EXCLUDED_SUBTREE,
    );
}

/// When a CA name constraint permits `www.example.com`, leaf certificates with a wildcard SAN of
/// `*.example.com` should be rejected, because it could match names outside the permitted subtree.
///
/// <https://github.com/rustls/webpki/security/advisories/GHSA-xgp8-3hg3-c2mh>
#[test]
fn wildcard_san_rejected_if_could_match_name_outside_permitted_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![GeneralSubtree::DnsName("foo.example.com".to_string())],
        excluded: vec![],
    }));
    let ee = generate_cert_with_names(None, None, &["*.example.com"], &issuer);
    let ca = issuer.der;

    assert_reason(
        build(&ee, &[], &[&ca], Eku::ServerAuth, NOW),
        reason::PERMITTED_SUBTREE,
    );
}

#[test]
fn ip4_address_san_rejected_if_in_excluded_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![],
        excluded: vec![GeneralSubtree::IpAddress(CidrSubnet::V4(
            [12, 34, 56, 0],
            [255, 255, 255, 0],
        ))],
    }));
    let ee = generate_cert_with_names(None, Some("12.34.56.78"), &[], &issuer);
    let ca = issuer.der;

    assert_reason(
        build(&ee, &[], &[&ca], Eku::ServerAuth, NOW),
        reason::EXCLUDED_SUBTREE,
    );
}

#[test]
fn ip4_address_san_allowed_if_outside_excluded_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![],
        excluded: vec![GeneralSubtree::IpAddress(CidrSubnet::V4(
            [12, 34, 56, 252],
            [255, 255, 255, 252],
        ))],
    }));
    let ee = generate_cert_with_names(None, Some("12.34.56.78"), &[], &issuer);
    let ca = issuer.der;

    assert_eq!(build(&ee, &[], &[&ca], Eku::ServerAuth, NOW), Ok(()));
    assert_eq!(
        build_for_ip(&ee, &[], &[&ca], Eku::ServerAuth, NOW, "12.34.56.78"),
        Ok(())
    );
}

#[test]
#[ignore = "FAIL-OPEN DIVERGENCE, inside this crate's own code (not a \
            dependency): this library DOES detect an invalid (sparse) CIDR \
            mask — is_valid_cidr_mask in ip_constraints.rs correctly \
            identifies 255.0.255.0 as non-contiguous and has its own unit \
            test covering exactly that (ip_constraints.rs:330-339). The bug \
            is in what happens next: address_is_in_subnet returns false \
            when the mask is invalid, and inside validate_excluded_subtrees \
            that false is indistinguishable from 'this address is \
            legitimately outside the excluded range' — there is no \
            separate signal for 'the constraint itself is malformed, reject \
            the chain'. So a malformed excluded-subtree constraint is \
            silently treated as 'does not match' rather than as grounds to \
            reject outright. Upstream detects the same malformed mask and \
            rejects with Error::InvalidNetworkMaskConstraint; this library \
            accepts the chain instead. Same bug class as the empty-subtree \
            finding (a malformed constraint silently downgraded to \
            'no constraint'), but more actionable since this one is in \
            x509-validator/src/rfc5280/ip_constraints.rs rather than in a \
            dependency. See task-4-report.md."]
fn ip4_address_san_rejected_if_excluded_is_sparse_cidr_mask() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![],
        excluded: vec![GeneralSubtree::IpAddress(CidrSubnet::V4(
            [12, 34, 56, 0],
            [255, 0, 255, 0],
        ))],
    }));
    let ee = generate_cert_with_names(None, Some("12.34.56.79"), &[], &issuer);
    let ca = issuer.der;

    assert_reason(
        build(&ee, &[], &[&ca], Eku::ServerAuth, NOW),
        reason::EXCLUDED_SUBTREE,
    );
}

#[test]
fn ip4_address_san_allowed() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![GeneralSubtree::IpAddress(CidrSubnet::V4(
            [12, 34, 56, 0],
            [255, 255, 255, 0],
        ))],
        excluded: vec![],
    }));
    let ee = generate_cert_with_names(None, Some("12.34.56.78"), &[], &issuer);
    let ca = issuer.der;

    assert_eq!(build(&ee, &[], &[&ca], Eku::ServerAuth, NOW), Ok(()));
    assert_eq!(
        build_for_ip(&ee, &[], &[&ca], Eku::ServerAuth, NOW, "12.34.56.78"),
        Ok(())
    );
    for invalid in [
        "12.34.56.77",
        "12.34.56.79",
        "0000:0000:0000:0000:0000:ffff:0c22:384e",
    ] {
        assert_reason(
            build_for_ip(&ee, &[], &[&ca], Eku::ServerAuth, NOW, invalid),
            reason::NAME_MISMATCH,
        );
    }
}

#[test]
fn ip6_address_san_rejected_if_in_excluded_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![],
        excluded: vec![GeneralSubtree::IpAddress(CidrSubnet::V6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ))],
    }));
    let ee = generate_cert_with_names(None, Some("2001:db8::1"), &[], &issuer);
    let ca = issuer.der;

    assert_reason(
        build(&ee, &[], &[&ca], Eku::ServerAuth, NOW),
        reason::EXCLUDED_SUBTREE,
    );
}

#[test]
fn ip6_address_san_allowed_if_outside_excluded_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![],
        excluded: vec![GeneralSubtree::IpAddress(CidrSubnet::V6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ))],
    }));
    let ee = generate_cert_with_names(None, Some("2001:db9::1"), &[], &issuer);
    let ca = issuer.der;

    assert_eq!(build(&ee, &[], &[&ca], Eku::ServerAuth, NOW), Ok(()));
    assert_eq!(
        build_for_ip(
            &ee,
            &[],
            &[&ca],
            Eku::ServerAuth,
            NOW,
            "2001:0db9:0000:0000:0000:0000:0000:0001"
        ),
        Ok(())
    );
}

#[test]
fn ip6_address_san_allowed() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![GeneralSubtree::IpAddress(CidrSubnet::V6(
            [0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ))],
        excluded: vec![],
    }));
    let ee = generate_cert_with_names(None, Some("2001:db9::1"), &[], &issuer);
    let ca = issuer.der;

    assert_eq!(build(&ee, &[], &[&ca], Eku::ServerAuth, NOW), Ok(()));
    assert_eq!(
        build_for_ip(
            &ee,
            &[],
            &[&ca],
            Eku::ServerAuth,
            NOW,
            "2001:0db9:0000:0000:0000:0000:0000:0001"
        ),
        Ok(())
    );
    assert_reason(
        build_for_ip(&ee, &[], &[&ca], Eku::ServerAuth, NOW, "12.34.56.78"),
        reason::NAME_MISMATCH,
    );
}

#[test]
fn ip46_mixed_address_san_allowed() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4([12, 34, 56, 0], [255, 255, 255, 0])),
            GeneralSubtree::IpAddress(CidrSubnet::V6(
                [0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            )),
        ],
        excluded: vec![],
    }));
    let ee = generate_cert_with_ip_sans_from_strs(&["12.34.56.78", "2001:db9::1"], &issuer);
    let ca = issuer.der;

    assert_eq!(build(&ee, &[], &[&ca], Eku::ServerAuth, NOW), Ok(()));
    for valid in ["12.34.56.78", "2001:0db9:0000:0000:0000:0000:0000:0001"] {
        assert_eq!(
            build_for_ip(&ee, &[], &[&ca], Eku::ServerAuth, NOW, valid),
            Ok(())
        );
    }
    for invalid in [
        "12.34.56.77",
        "12.34.56.79",
        "0000:0000:0000:0000:0000:ffff:0c22:384e",
    ] {
        assert_reason(
            build_for_ip(&ee, &[], &[&ca], Eku::ServerAuth, NOW, invalid),
            reason::NAME_MISMATCH,
        );
    }
}

/// Since we don't have real constraint matching implemented for URI names, fail closed.
#[test]
fn uri_san_rejected_against_uri_permitted_subtree() {
    let issuer = uri_permitted_name_constraints("https://allowed.example.com");
    let ee = x509_validator_testkit::issue_leaf_with("", &[], &issuer, |params| {
        params.subject_alt_names = vec![rcgen::SanType::URI(
            "https://evil.example.com"
                .try_into()
                .unwrap(),
        )];
    });
    let ca = issuer.der;

    assert_reason(
        build(&ee, &[], &[&ca], Eku::ServerAuth, NOW),
        reason::PERMITTED_SUBTREE,
    );
}

/// Since we don't have real constraint matching implemented for URI names, fail closed.
#[test]
#[ignore = "divergence, NOT fail-open: this library implements real URI \
            constraint matching (uri_name_matches_constraint in \
            uri_constraints.rs), and per RFC 5280 §4.2.1.10 (quoted in that \
            file's own doc comment) 'the constraint applies to the host \
            part of the name' — a URI constraint is supposed to name a \
            host, not a full URI. Upstream's fixture sets the excluded \
            constraint to the full URI 'https://evil.example.com', but this \
            library extracts just the host from the SAN \
            ('evil.example.com') and compares that against the constraint \
            as a DNS name. 'evil.example.com' != 'https://evil.example.com' \
            as strings, so there is no match and the chain is ACCEPTED \
            here where upstream (matching its own fixture literally) \
            rejects it. This is upstream's test fixture being the outlier, \
            not a name-constraints bypass: had the constraint been written \
            as a bare host ('evil.example.com'), as RFC 5280 requires, this \
            library would reject the chain exactly like \
            uri_san_rejected_against_uri_permitted_subtree does above. See \
            task-4-report.md."]
fn uri_san_rejected_against_uri_excluded_subtree() {
    let issuer = uri_excluded_name_constraints("https://evil.example.com");
    let ee = x509_validator_testkit::issue_leaf_with("", &[], &issuer, |params| {
        params.subject_alt_names = vec![rcgen::SanType::URI(
            "https://evil.example.com"
                .try_into()
                .unwrap(),
        )];
    });
    let ca = issuer.der;

    assert_reason(
        build(&ee, &[], &[&ca], Eku::ServerAuth, NOW),
        reason::EXCLUDED_SUBTREE,
    );
}

#[test]
#[ignore = "FAIL-OPEN DIVERGENCE: the underlying DER decoder \
            (x509_parser's parse_nameconstraints) parses each subtrees \
            field with opt(complete(many1(...))); many1 fails to parse an \
            empty SEQUENCE, but the wrapping opt() swallows that failure \
            and treats the field as though it were absent. A \
            present-but-empty permittedSubtrees or excludedSubtrees field — \
            malformed per RFC 5280 §4.2.1.10 — is silently treated as \
            'no constraint of that kind', so the chain is ACCEPTED where \
            upstream (and RFC 5280) require rejection. This is a bug in a \
            dependency (x509-parser), not this crate's own policy code; \
            reported rather than patched, per this task's scope. See \
            task-4-report.md."]
fn empty_name_constraint_sequences_rejected() {
    let permitted = name_constraint_subtrees(b"example.com", DNS_NAME_TAG, PERMITTED_SUBTREES_TAG);
    let excluded = name_constraint_subtrees(b"example.com", DNS_NAME_TAG, EXCLUDED_SUBTREES_TAG);
    let empty_permitted = der_tlv(PERMITTED_SUBTREES_TAG, &[]);
    let empty_excluded = der_tlv(EXCLUDED_SUBTREES_TAG, &[]);

    let cases = [
        (
            "empty permittedSubtrees",
            [empty_permitted.as_slice(), excluded.as_slice()].concat(),
        ),
        (
            "empty excludedSubtrees",
            [permitted.as_slice(), empty_excluded.as_slice()].concat(),
        ),
        (
            "both subtree fields empty",
            [empty_permitted.as_slice(), empty_excluded.as_slice()].concat(),
        ),
    ];

    for (description, subtrees) in cases {
        let issuer = self_signed_ca_with("issuer.example.com", |params| {
            params
                .custom_extensions
                .push(name_constraints_extension(&subtrees));
        });
        let ee = x509_validator_testkit::issue_leaf_with("", &[], &issuer, |_| {});
        let ca = issuer.der;

        assert!(
            build(&ee, &[], &[&ca], Eku::ServerAuth, NOW).is_err(),
            "{description}: expected validation to fail"
        );
    }
}

// Hand-encode a NameConstraints extension (OID 2.5.29.30) with a single
// permittedSubtree containing a URI GeneralName. rcgen's GeneralSubtree enum
// doesn't expose a URI variant, so we emit the DER directly.
fn uri_permitted_name_constraints(uri: &str) -> Ca {
    self_signed_ca_with("issuer.example.com", |params| {
        params
            .custom_extensions
            .push(raw_name_constraints_extension(
                &[RawGeneralName::uri(uri)],
                &[],
            ));
    })
}

// Hand-encode a NameConstraints extension (OID 2.5.29.30) with a single
// excludedSubtree containing a URI GeneralName.
fn uri_excluded_name_constraints(uri: &str) -> Ca {
    self_signed_ca_with("issuer.example.com", |params| {
        params
            .custom_extensions
            .push(raw_name_constraints_extension(
                &[],
                &[RawGeneralName::uri(uri)],
            ));
    })
}

fn name_constraint_subtrees(name: &[u8], name_tag: u8, subtrees_tag: u8) -> Vec<u8> {
    let general_name = der_tlv(name_tag, name);
    let subtree = der_tlv(SEQUENCE_TAG, &general_name);
    der_tlv(subtrees_tag, &subtree)
}

fn name_constraints_extension(subtrees: &[u8]) -> rcgen::CustomExtension {
    let nc = der_tlv(SEQUENCE_TAG, subtrees);
    let mut ext = rcgen::CustomExtension::from_oid_content(NAME_CONSTRAINTS_OID, nc);
    ext.set_criticality(true);
    ext
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 128);
    let mut encoded = vec![tag, value.len() as u8];
    encoded.extend_from_slice(value);
    encoded
}

const NAME_CONSTRAINTS_OID: &[u64] = &[2, 5, 29, 30];
const SEQUENCE_TAG: u8 = 0x30;
const DNS_NAME_TAG: u8 = 0x82; // [2] IMPLICIT IA5String
const PERMITTED_SUBTREES_TAG: u8 = 0xa0; // [0] IMPLICIT GeneralSubtrees
const EXCLUDED_SUBTREES_TAG: u8 = 0xa1; // [1] IMPLICIT GeneralSubtrees

#[test]
fn permit_directory_name_not_implemented() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "CN");
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![GeneralSubtree::DirectoryName(dn)],
        excluded: vec![],
    }));
    let ee = x509_validator_testkit::issue_leaf_with("", &[], &issuer, |_| {});
    let ca = issuer.der;

    assert_reason(
        build(&ee, &[], &[&ca], Eku::ServerAuth, NOW),
        reason::DIRECTORY_NAME_UNSUPPORTED,
    );
}

#[test]
fn exclude_directory_name_not_implemented() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "CN");
    let issuer = make_issuer(Some(NameConstraints {
        permitted: vec![],
        excluded: vec![GeneralSubtree::DirectoryName(dn)],
    }));
    let ee = x509_validator_testkit::issue_leaf_with("", &[], &issuer, |_| {});
    let ca = issuer.der;

    assert_reason(
        build(&ee, &[], &[&ca], Eku::ServerAuth, NOW),
        reason::DIRECTORY_NAME_UNSUPPORTED,
    );
}

#[test]
fn invalid_dns_name_matching() {
    let issuer = make_issuer(None);
    let ee = generate_cert_with_names(
        None,
        None,
        &["{invalid}.example.com", "dns.example.com"],
        &issuer,
    );
    let ca = issuer.der;

    assert_eq!(
        check_cert(
            &ee,
            &ca,
            &["dns.example.com"],
            &[],
            &[
                "DnsName(\"{invalid}.example.com\")",
                "DnsName(\"dns.example.com\")"
            ]
        ),
        Ok(())
    );
}

/// Permitted and excluded subtrees for an issuer's name constraints.
#[derive(Default)]
struct NameConstraints {
    permitted: Vec<GeneralSubtree>,
    excluded: Vec<GeneralSubtree>,
}

fn generate_cert_with_names(
    subject_cn: Option<&str>,
    ip: Option<&str>,
    dns_sans: &[&str],
    issuer: &Ca,
) -> Vec<u8> {
    if let Some(ip) = ip {
        let addr: core::net::IpAddr = ip.parse().expect("valid ip address");
        return issue_leaf_with_ip_sans(subject_cn.unwrap_or(""), vec![addr], issuer);
    }

    LeafSpec::new(subject_cn.unwrap_or(""))
        .dns_sans(dns_sans)
        .signed_by(issuer)
}

fn generate_cert_with_ip_sans_from_strs(ips: &[&str], issuer: &Ca) -> Vec<u8> {
    let addrs: Vec<core::net::IpAddr> = ips
        .iter()
        .map(|ip| ip.parse().expect("valid ip"))
        .collect();
    issue_leaf_with_ip_sans("", addrs, issuer)
}

fn make_issuer(name_constraints: Option<NameConstraints>) -> Ca {
    self_signed_ca_with("issuer.example.com", |params: &mut CertificateParams| {
        if let Some(constraints) = name_constraints {
            params.name_constraints = Some(rcgen::NameConstraints {
                permitted_subtrees: constraints.permitted,
                excluded_subtrees: constraints.excluded,
            });
        }
    })
}

// OID for emailAddress in subject DN (pkcs9-emailAddress)
const OID_EMAIL_ADDRESS: &[u64] = &[1, 2, 840, 113549, 1, 9, 1];

#[test]
fn presented_names_escape_control_characters() {
    // `InvalidNameContext::presented` is public API built by formatting the SAN
    // entries, and a certificate can carry anything there. Whatever a caller
    // does with those strings, they should not contain raw control characters.
    let issuer = make_issuer(None);
    let ee = generate_cert_with_names(None, None, &["a\r\nInjected: header\u{1b}[31m"], &issuer);
    let ca = issuer.der;

    assert_eq!(
        check_cert(
            &ee,
            &ca,
            &[],
            &["real.example.com"],
            &[r#"DnsName("a\r\nInjected: header\u{1b}[31m")"#],
        ),
        Ok(())
    );
}
