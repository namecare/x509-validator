use x509_validator::{NameConstraintsPolicy, PolicyFailureReason, VerifierPolicy};
use x509_validator_testkit::rcgen::CertificateParams;
use x509_validator_testkit::{chain_of, dns_subtree, issue_leaf, name_constraints, self_signed_ca_with};

#[test]
fn chain_without_name_constraints_is_accepted() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf("leaf", &["www.example.com"], &root);
    let chain = chain_of(vec![leaf, root.der]);
    let mut policy = NameConstraintsPolicy;
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn leaf_name_in_permitted_subtree_is_accepted() {
    let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
        params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
    });
    let leaf = issue_leaf("leaf", &["www.example.com"], &root);
    let chain = chain_of(vec![leaf, root.der]);
    let mut policy = NameConstraintsPolicy;
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn leaf_name_outside_permitted_subtree_is_rejected() {
    let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
        params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
    });
    let leaf = issue_leaf("leaf", &["www.evil.com"], &root);
    let chain = chain_of(vec![leaf, root.der]);
    let mut policy = NameConstraintsPolicy;
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn leaf_name_in_excluded_subtree_is_rejected() {
    let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
        params.name_constraints = Some(name_constraints(vec![], vec![dns_subtree("example.com")]));
    });
    let leaf = issue_leaf("leaf", &["www.example.com"], &root);
    let chain = chain_of(vec![leaf, root.der]);
    let mut policy = NameConstraintsPolicy;
    assert_eq!(
        policy.chain_meets_policy_requirements(&chain).unwrap_err(),
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
    let chain = chain_of(vec![leaf, intermediate.der, root.der]);
    let mut policy = NameConstraintsPolicy;
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn self_signed_single_certificate_enforces_its_own_constraints() {
    let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
        params.subject_alt_names = vec![x509_validator_testkit::rcgen::SanType::DnsName("www.evil.com".try_into().unwrap())];
        params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
    });
    let chain = chain_of(vec![root.der]);
    let mut policy = NameConstraintsPolicy;
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn directory_name_constraint_is_rejected_outright() {
    let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
        let mut dn = x509_validator_testkit::rcgen::DistinguishedName::new();
        dn.push(x509_validator_testkit::rcgen::DnType::CommonName, "example");
        params.name_constraints = Some(name_constraints(vec![x509_validator_testkit::rcgen::GeneralSubtree::DirectoryName(dn)], vec![]));
    });
    let leaf = issue_leaf("leaf", &["www.example.com"], &root);
    let chain = chain_of(vec![leaf, root.der]);
    let mut policy = NameConstraintsPolicy;
    assert_eq!(
        policy.chain_meets_policy_requirements(&chain).unwrap_err(),
        PolicyFailureReason::new("directoryName name constraints are not supported")
    );
}

#[test]
fn verifying_critical_extensions_includes_name_constraints_oid() {
    let policy = NameConstraintsPolicy;
    let oids = policy.verifying_critical_extensions();
    assert!(oids.contains(&x509_validator_core::oid_registry::OID_X509_EXT_NAME_CONSTRAINTS));
}
