use x509_validator::{
    CertificateExt, NameConstraintsPolicy, PolicyFailureReason, ValidationPolicy,
};
use x509_validator_testkit::rcgen::CertificateParams;
use x509_validator_testkit::{
    RawGeneralName, chain_of, dns_subtree, issue_leaf, issue_leaf_with, name_constraints,
    raw_name_constraints_extension, self_signed_ca_with,
};

#[test]
fn chain_without_name_constraints_is_accepted() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf("leaf", &["www.example.com"], &root);
    let ders = chain_of(vec![leaf, root.der]);
    let chain = ders.chain();
    let policy = NameConstraintsPolicy;
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn leaf_name_in_permitted_subtree_is_accepted() {
    let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
        params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
    });
    let leaf = issue_leaf("leaf", &["www.example.com"], &root);
    let ders = chain_of(vec![leaf, root.der]);
    let chain = ders.chain();
    let policy = NameConstraintsPolicy;
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn leaf_name_outside_permitted_subtree_is_rejected() {
    let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
        params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
    });
    let leaf = issue_leaf("leaf", &["www.evil.com"], &root);
    let ders = chain_of(vec![leaf, root.der]);
    let chain = ders.chain();
    let policy = NameConstraintsPolicy;
    assert!(
        policy
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

#[test]
fn leaf_name_in_excluded_subtree_is_rejected() {
    let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
        params.name_constraints = Some(name_constraints(vec![], vec![dns_subtree("example.com")]));
    });
    let leaf = issue_leaf("leaf", &["www.example.com"], &root);
    let ders = chain_of(vec![leaf, root.der]);
    let chain = ders.chain();
    let policy = NameConstraintsPolicy;
    assert_eq!(
        policy
            .chain_meets_policy_requirements(&chain)
            .unwrap_err(),
        PolicyFailureReason::new("name is in an excluded subtree")
    );
}

#[test]
fn constraints_apply_transitively_through_intermediate() {
    let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
        params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
    });
    let intermediate = x509_validator_testkit::issue_ca("intermediate", &root, None, |_| {});
    let leaf = issue_leaf("leaf", &["www.evil.com"], &intermediate);
    let ders = chain_of(vec![leaf, intermediate.der, root.der]);
    let chain = ders.chain();
    let policy = NameConstraintsPolicy;
    assert!(
        policy
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

#[test]
fn self_signed_single_certificate_enforces_its_own_constraints() {
    let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
        params.subject_alt_names = vec![x509_validator_testkit::rcgen::SanType::DnsName(
            "www.evil.com".try_into().unwrap(),
        )];
        params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
    });
    let ders = chain_of(vec![root.der]);
    let chain = ders.chain();
    let policy = NameConstraintsPolicy;
    assert!(
        policy
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

#[test]
fn directory_name_constraint_is_rejected_outright() {
    let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
        let mut dn = x509_validator_testkit::rcgen::DistinguishedName::new();
        dn.push(x509_validator_testkit::rcgen::DnType::CommonName, "example");
        params.name_constraints = Some(name_constraints(
            vec![x509_validator_testkit::rcgen::GeneralSubtree::DirectoryName(dn)],
            vec![],
        ));
    });
    let leaf = issue_leaf("leaf", &["www.example.com"], &root);
    let ders = chain_of(vec![leaf, root.der]);
    let chain = ders.chain();
    let policy = NameConstraintsPolicy;
    assert_eq!(
        policy
            .chain_meets_policy_requirements(&chain)
            .unwrap_err(),
        PolicyFailureReason::new("directoryName name constraints are not supported")
    );
}

/// A subject alternative name whose sole entry is a `dNSName` carrying bytes that are not valid
/// IA5, which the parser surfaces as `GeneralName::Invalid` rather than failing the extension
/// parse. `raw_subject_alt_name_extension` cannot express this, as it builds names from `&str`.
fn undecodable_dns_san() -> x509_validator_testkit::rcgen::CustomExtension {
    let name = [0x82, 0x05, 0xff, b'e', b'v', b'i', b'l'];
    let mut contents = vec![0x30, name.len() as u8];
    contents.extend_from_slice(&name);

    let mut extension =
        x509_validator_testkit::rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 17], contents);
    extension.set_criticality(false);
    extension
}

#[test]
fn name_that_cannot_be_decoded_is_rejected_rather_than_skipped() {
    let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
        params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
    });
    let leaf = issue_leaf_with("leaf", &[], &root, |params: &mut CertificateParams| {
        params
            .custom_extensions
            .push(undecodable_dns_san());
    });
    let ders = chain_of(vec![leaf, root.der]);
    let chain = ders.chain();

    // Guard against a vacuous test: the name has to reach the policy as `Invalid`, because an
    // extension that failed to parse outright would be rejected by a different path.
    let names = chain.leaf().subject_alternative_names();
    assert!(
        matches!(names.as_slice(), [x509_validator::GeneralName::Invalid(..)]),
        "expected a single undecodable name, got {names:?}"
    );

    // An undecodable name can never be compared against the permitted subtree, so it must fail the
    // chain rather than slip past unexamined.
    let policy = NameConstraintsPolicy;
    assert!(
        policy
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

#[test]
fn unsupported_constraint_kind_is_rejected_even_with_no_name_of_that_kind() {
    // The leaf carries only a dNSName, so nothing it holds is comparable to an rfc822Name
    // constraint. The constraint is still one we cannot evaluate, and RFC 5280 requires rejecting
    // a chain we cannot fully check — the certificate's own names have no say in that.
    let rfc822 = || vec![RawGeneralName::rfc822("bar.com")];
    for (permitted, excluded, expected) in [
        (
            rfc822(),
            vec![],
            "unable to validate permitted subtree, unsupported constraint kind",
        ),
        (
            vec![],
            rfc822(),
            "unable to validate excluded subtree, unsupported constraint kind",
        ),
    ] {
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params
                .custom_extensions
                .push(raw_name_constraints_extension(&permitted, &excluded));
        });
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let ders = chain_of(vec![leaf, root.der]);
        let chain = ders.chain();

        let policy = NameConstraintsPolicy;
        assert_eq!(
            policy
                .chain_meets_policy_requirements(&chain)
                .unwrap_err(),
            PolicyFailureReason::new(expected)
        );
    }
}

#[test]
fn verifying_critical_extensions_includes_name_constraints_oid() {
    let policy = NameConstraintsPolicy;
    let oids = policy.verifying_critical_extensions();
    assert!(oids.contains(&x509_validator::oid_registry::OID_X509_EXT_NAME_CONSTRAINTS));
}
