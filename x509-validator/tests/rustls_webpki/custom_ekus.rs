//! Ports the upstream `custom_ekus` file. Upstream asserts an exact
//! `Result<(), webpki::Error>`; failures here are strings, so the expected
//! error is a reason substring instead.

use x509_validator::der_parser::Oid;
use x509_validator::rfc5280::{EkuPolicy, RFC5280Policy, Timestamp, eku_oids};
use x509_validator::{Validator, policy};

use super::common::{self, DEFAULT_PROVIDER, assert_reason, reason};

/// The key purpose an upstream test asked the path builder for.
enum Eku {
    ServerAuth,
    ClientAuth,
    /// A purpose named by raw OID arcs, as the custom-EKU tests use.
    Custom(Vec<Oid<'static>>),
}

impl Eku {
    fn purposes(&self) -> Vec<Oid<'static>> {
        match self {
            Self::ServerAuth => vec![eku_oids::server_auth()],
            Self::ClientAuth => vec![eku_oids::client_auth()],
            Self::Custom(oids) => oids.clone(),
        }
    }
}

#[track_caller]
fn check_cert(ee: &[u8], ca: &[u8], eku: Eku, time: Timestamp, result: Result<(), &str>) {
    let leaf = common::parse(ee);
    let roots = common::store(&[ca]);
    let intermediates = common::store(&[]);

    let validator = Validator::with_policy_and_backend(
        roots,
        policy! {
            RFC5280Policy::new(time);
            EkuPolicy::key_purposes(eku.purposes())
        },
        &DEFAULT_PROVIDER,
    );

    let outcome = match validator.validate(&leaf, &intermediates) {
        Ok(_) => Ok(()),
        Err(reasons) => Err(common::reasons(&reasons)),
    };

    match result {
        Ok(()) => assert_eq!(outcome, Ok(())),
        Err(expected) => assert_reason(outcome, expected),
    }
}

/// arcs 1.0.18013.5.1.2 — upstream's mdoc EKU, encoded `[40, 129, 140, 93, 5,
/// 1, 2]` in its source; built here from the arc form.
fn mdoc_eku() -> Oid<'static> {
    Oid::from(&[1, 0, 18013, 5, 1, 2]).expect("valid oid arcs")
}

#[test]
pub fn verify_custom_eku_mdoc() {
    let time: Timestamp = 1_609_459_200; //  Jan 1 01:00:00 CET 2021

    const EE: &[u8] = include_bytes!("fixtures/misc/mdoc_eku.ee.der");
    const CA: &[u8] = include_bytes!("fixtures/misc/mdoc_eku.ca.der");

    check_cert(EE, CA, Eku::Custom(vec![mdoc_eku()]), time, Ok(()));
    check_cert(EE, CA, Eku::ServerAuth, time, Err(reason::EKU_MISMATCH));
    check_cert(EE, CA, Eku::Custom(vec![mdoc_eku()]), time, Ok(()));
    check_cert(EE, CA, Eku::ServerAuth, time, Err(reason::EKU_MISMATCH));
}

#[test]
pub fn verify_custom_eku_client() {
    let time: Timestamp = 0x1fed_f00d;

    const NO_EKU_EE: &[u8] =
        include_bytes!("fixtures/custom_ekus/cert_with_no_eku_accepted_for_client_auth.ee.der");
    const NO_EKU_CA: &[u8] =
        include_bytes!("fixtures/custom_ekus/cert_with_no_eku_accepted_for_client_auth.ca.der");
    check_cert(NO_EKU_EE, NO_EKU_CA, Eku::ClientAuth, time, Ok(()));

    const BOTH_EE: &[u8] =
        include_bytes!("fixtures/custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    const BOTH_CA: &[u8] =
        include_bytes!("fixtures/custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    check_cert(BOTH_EE, BOTH_CA, Eku::ClientAuth, time, Ok(()));
    check_cert(BOTH_EE, BOTH_CA, Eku::ServerAuth, time, Ok(()));
}

#[test]
pub fn verify_custom_eku_required_if_present() {
    let time: Timestamp = 0x1fed_f00d;

    let eku = || {
        Eku::Custom(vec![
            Oid::from(&[1, 3, 6, 1, 5, 5, 7, 3, 2]).expect("valid oid arcs"),
        ])
    };

    const NO_EKU_EE: &[u8] =
        include_bytes!("fixtures/custom_ekus/cert_with_no_eku_accepted_for_client_auth.ee.der");
    const NO_EKU_CA: &[u8] =
        include_bytes!("fixtures/custom_ekus/cert_with_no_eku_accepted_for_client_auth.ca.der");
    check_cert(NO_EKU_EE, NO_EKU_CA, eku(), time, Ok(()));

    const BOTH_EE: &[u8] =
        include_bytes!("fixtures/custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    const BOTH_CA: &[u8] =
        include_bytes!("fixtures/custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    check_cert(BOTH_EE, BOTH_CA, eku(), time, Ok(()));
}
