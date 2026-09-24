use x509_validator::ValidationPolicy;
use x509_validator::rfc5280::RFC5280Policy;
use x509_validator_testkit::time::{Duration, OffsetDateTime};
use x509_validator_testkit::{CaSpec, chain_of};

const V1_NOT_BEFORE: i64 = 1_613_446_729;

#[test]
#[ignore = "divergence: RFC 5280 permits version 1 certificates and this library \
            only rejects a v1 certificate that carries extensions; upstream refuses \
            any v1 end-entity certificate outright"]
fn test_cert_v1_unsupported() {
    // Check with `openssl x509 -text -noout -in cert_v1.der -inform DER`
    // to verify this is a correct version 1 certificate.
    let ee = include_bytes!("fixtures/misc/cert_v1.der").to_vec();
    let now = V1_NOT_BEFORE + 3_600;
    let issued = OffsetDateTime::from_unix_timestamp(now).expect("timestamp");
    let root = CaSpec::new("my.ca")
        .validity(issued - Duration::days(365), issued + Duration::days(365))
        .self_signed();

    let ders = chain_of(vec![ee, root.der]);
    let result = RFC5280Policy::new(now).chain_meets_policy_requirements(&ders.chain());

    assert!(
        result.is_err(),
        "a version 1 end-entity certificate was accepted"
    );
}
