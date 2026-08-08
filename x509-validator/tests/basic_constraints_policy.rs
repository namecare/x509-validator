use x509_validator::{BasicConstraintsPolicy, VerifierPolicy};
use x509_validator_core::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use x509_validator_core::{Certificate, FromDer};
use x509_validator_testkit::rcgen::CertificateParams;
use x509_validator_testkit::{chain_of, issue_ca, issue_leaf, self_signed_ca_with};

#[test]
fn leaf_and_ca_chain_is_accepted() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf("leaf", &["www.example.com"], &root);
    let chain = chain_of(vec![leaf, root.der]);
    let mut policy = BasicConstraintsPolicy;
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn self_signed_leaf_used_as_trust_anchor_must_be_a_ca() {
    let root = self_signed_ca_with("root", |_| {});
    let chain = chain_of(vec![root.der]);
    let mut policy = BasicConstraintsPolicy;
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn self_signed_leaf_without_ca_bit_is_rejected() {
    // A self-signed cert that isn't marked as a CA at all: built the
    // same way `issue_leaf` builds ordinary leaves, but self-signed.
    let this = self_signed_ca_with("root", |params: &mut CertificateParams| {
        params.is_ca = x509_validator_testkit::rcgen::IsCa::NoCa;
    });
    let chain = chain_of(vec![this.der]);
    let mut policy = BasicConstraintsPolicy;
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn non_ca_intermediate_is_rejected() {
    let root = self_signed_ca_with("root", |_| {});
    // "intermediate" is issued as a non-CA leaf, then used to sign
    // another cert anyway — its basicConstraints has no CA bit set.
    let intermediate = issue_leaf("intermediate", &[], &root);
    let intermediate_der: &'static [u8] = Box::leak(intermediate.clone().into_boxed_slice());
    let intermediate_cert = Certificate::from_der(intermediate_der).unwrap().1;
    let leaf = issue_leaf("leaf", &["www.example.com"], &root);

    let chain = UnverifiedCertificateChain::new(vec![
        {
            let leaf_der: &'static [u8] = Box::leak(leaf.into_boxed_slice());
            Certificate::from_der(leaf_der).unwrap().1
        },
        intermediate_cert,
        {
            let root_der: &'static [u8] = Box::leak(root.der.into_boxed_slice());
            Certificate::from_der(root_der).unwrap().1
        },
    ]);
    let mut policy = BasicConstraintsPolicy;
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn path_length_constraint_satisfied_is_accepted() {
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &root, Some(1), |_| {});
    let leaf = issue_leaf("leaf", &["www.example.com"], &intermediate);
    let chain = chain_of(vec![leaf, intermediate.der, root.der]);
    let mut policy = BasicConstraintsPolicy;
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn path_length_constraint_violated_is_rejected() {
    let root = self_signed_ca_with("root", |_| {});
    let intermediate1 = issue_ca("intermediate1", &root, Some(0), |_| {});
    let intermediate2 = issue_ca("intermediate2", &intermediate1, None, |_| {});
    let leaf = issue_leaf("leaf", &["www.example.com"], &intermediate2);
    let chain = chain_of(vec![leaf, intermediate2.der, intermediate1.der, root.der]);
    let mut policy = BasicConstraintsPolicy;
    assert!(policy.chain_meets_policy_requirements(&chain).is_err());
}

#[test]
fn self_issued_intermediate_does_not_count_against_path_length() {
    // "intermediate" re-issues itself (same subject name, fresh key)
    // before signing the leaf; that self-issued hop must not consume
    // the path-length budget.
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &root, Some(0), |_| {});
    let self_issued = issue_ca("intermediate", &intermediate, Some(0), |_| {});
    let leaf = issue_leaf("leaf", &["www.example.com"], &self_issued);
    let chain = chain_of(vec![leaf, self_issued.der, intermediate.der, root.der]);
    let mut policy = BasicConstraintsPolicy;
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn verifying_critical_extensions_includes_basic_constraints_oid() {
    let policy = BasicConstraintsPolicy;
    let oids = policy.verifying_critical_extensions();
    assert!(oids.contains(&OID_X509_EXT_BASIC_CONSTRAINTS));
}
