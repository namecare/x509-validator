use x509_validator::{ExpiryPolicy, PolicyFailureReason, Timestamp, ValidationPolicy};
use x509_validator_testkit::rcgen::CertificateParams;
use x509_validator_testkit::time::{Duration, OffsetDateTime};
use x509_validator_testkit::{chain_of, self_signed_ca_with};

fn cert_with_validity(not_before: Timestamp, not_after: Timestamp) -> Vec<u8> {
    self_signed_ca_with("root", |params: &mut CertificateParams| {
        params.not_before = OffsetDateTime::UNIX_EPOCH + Duration::seconds(not_before);
        params.not_after = OffsetDateTime::UNIX_EPOCH + Duration::seconds(not_after);
    })
    .der
}

#[test]
fn certificate_within_validity_window_is_accepted() {
    let chain = chain_of(vec![cert_with_validity(1000, 2000)]);
    let policy = ExpiryPolicy::new(1500);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn certificate_exactly_at_not_before_is_accepted() {
    let chain = chain_of(vec![cert_with_validity(1000, 2000)]);
    let policy = ExpiryPolicy::new(1000);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn certificate_exactly_at_not_after_is_accepted() {
    let chain = chain_of(vec![cert_with_validity(1000, 2000)]);
    let policy = ExpiryPolicy::new(2000);
    assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
}

#[test]
fn certificate_not_yet_valid_is_rejected() {
    let chain = chain_of(vec![cert_with_validity(1000, 2000)]);
    let policy = ExpiryPolicy::new(500);
    assert!(
        policy
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

#[test]
fn expired_certificate_is_rejected() {
    let chain = chain_of(vec![cert_with_validity(1000, 2000)]);
    let policy = ExpiryPolicy::new(2500);
    assert_eq!(
        policy
            .chain_meets_policy_requirements(&chain)
            .unwrap_err(),
        PolicyFailureReason::new("certificate has expired")
    );
}
