//! Ports the upstream `client_auth` file. Upstream builds a path with
//! `ExtendedKeyUsage::CLIENT_AUTH` and asserts a typed `webpki::Error`; a
//! `Validator` here composes an `EkuPolicy` and reports failures as strings.

use x509_validator::rfc5280::{EkuPolicy, RFC5280Policy, Timestamp, eku_oids};
use x509_validator::{Validator, policy};
use x509_validator_testkit::rcgen::ExtendedKeyUsagePurpose;
use x509_validator_testkit::{LeafSpec, self_signed_ca_with};

use super::common::{self, DEFAULT_PROVIDER, assert_reason, reason};

#[test]
fn cert_with_no_eku_accepted_for_client_auth() {
    let (ee, ca) = test_certs(&[], "cert_with_no_eku_accepted_for_client_auth");
    assert_eq!(check_cert(&ee, &ca), Ok(()));
}

#[test]
fn cert_with_clientauth_eku_accepted_for_client_auth() {
    let (ee, ca) = test_certs(
        &[ExtendedKeyUsagePurpose::ClientAuth],
        "cert_with_clientauth_eku_accepted_for_client_auth",
    );
    assert_eq!(check_cert(&ee, &ca), Ok(()));
}

#[test]
fn cert_with_both_ekus_accepted_for_client_auth() {
    let (ee, ca) = test_certs(
        &[
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ],
        "cert_with_both_ekus_accepted_for_client_auth",
    );
    assert_eq!(check_cert(&ee, &ca), Ok(()));
}

#[test]
fn cert_with_serverauth_eku_rejected_for_client_auth() {
    let (ee, ca) = test_certs(
        &[ExtendedKeyUsagePurpose::ServerAuth],
        "cert_with_serverauth_eku_rejected_for_client_auth",
    );

    assert_reason(check_cert(&ee, &ca), reason::EKU_MISMATCH);
}

fn check_cert(ee: &[u8], ca: &[u8]) -> Result<(), String> {
    validate_chain(ee, &[], &[ca], common::NOW)
}

fn validate_chain(
    ee: &[u8],
    intermediates: &[&[u8]],
    roots: &[&[u8]],
    now: Timestamp,
) -> Result<(), String> {
    let leaf = common::parse(ee);
    let roots = common::store(roots);
    let intermediates = common::store(intermediates);

    let validator = Validator::with_policy_and_backend(
        roots,
        policy! {
            RFC5280Policy::new(now);
            EkuPolicy::key_purposes(vec![eku_oids::client_auth()])
        },
        &DEFAULT_PROVIDER,
    );

    match validator.validate(&leaf, &intermediates) {
        Ok(_) => Ok(()),
        Err(reasons) => Err(common::reasons(&reasons)),
    }
}

fn test_certs(ekus: &[ExtendedKeyUsagePurpose], name: &str) -> (Vec<u8>, Vec<u8>) {
    let issuer = self_signed_ca_with(&format!("{name}-issuer"), |_| {});
    let end_entity = LeafSpec::new(name)
        .extended_key_usages(ekus)
        .signed_by(&issuer);
    (end_entity, issuer.der)
}
