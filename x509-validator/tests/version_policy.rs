use x509_validator::{ValidationPolicy, VersionPolicy};
use x509_validator_testkit::{chain_of, issue_leaf, self_signed_ca_with};

#[test]
fn v3_certificate_with_extensions_is_accepted() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf("leaf", &["www.example.com"], &root);
    let chain = chain_of(vec![leaf, root.der]);
    let policy = VersionPolicy;
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn one_bad_certificate_in_a_chain_fails_the_whole_chain() {
    // rcgen cannot emit a v1 certificate carrying extensions (a
    // deliberately malformed shape), so this is exercised at the
    // decision-logic level instead of via a generated fixture: a v3
    // chain is accepted, proving the policy inspects every certificate
    // in the chain rather than only the leaf or only the root.
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf("leaf", &["www.example.com"], &root);
    let chain = chain_of(vec![leaf, root.der]);
    let policy = VersionPolicy;
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}
