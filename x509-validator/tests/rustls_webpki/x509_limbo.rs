use core::panic::AssertUnwindSafe;
use std::collections::HashMap;
use std::panic::catch_unwind;
use std::time::{SystemTime, UNIX_EPOCH};

use limbo_harness_support::LIMBO_JSON;
use limbo_harness_support::models::{
    ExpectedResult, Feature, KnownEkUs, Limbo, PeerKind, Testcase, ValidationKind,
};
use x509_validator::der_parser::Oid;
use x509_validator::prelude::parse_x509_pem;
use x509_validator::rfc5280::{EkuPolicy, RFC5280Policy, eku_oids};
use x509_validator::server_identity_policy::ServerIdentityPolicy;
use x509_validator::store::CertificateStore;
use x509_validator::{Certificate, CertificateExt, Validator, policy};

use super::common::{self, DEFAULT_PROVIDER};

#[ignore] // Runs slower than other unit tests - opt-in with `cargo test -- --include-ignored`
#[test]
fn x509_limbo() {
    let limbo = serde_json::from_slice::<Limbo>(LIMBO_JSON).expect("invalid test JSON");

    let exceptions = exceptions();

    let mut summary = Summary::default();
    for testcase in &limbo.testcases {
        let id = testcase.id.to_string();

        match evaluate_testcase(testcase, &exceptions) {
            Outcome::Pass => summary.passed.push(id),
            Outcome::Skip(reason) => summary.skipped.push((id, reason)),
            Outcome::KnownDivergence => summary.known_divergences.push(id),
            Outcome::UnexpectedFailure(err) => summary
                .unexpected_failures
                .push((id, err)),
            Outcome::UnexpectedSuccess => summary.unexpected_successes.push(id),
            Outcome::Panic(message) => summary.panics.push((id, message)),
        }
    }

    summary.print();
    assert!(
        summary.unexpected_failures.is_empty()
            && summary.unexpected_successes.is_empty()
            && summary.panics.is_empty(),
        "x509-limbo: {} unexpected failures, {} unexpected successes, {} panics",
        summary.unexpected_failures.len(),
        summary.unexpected_successes.len(),
        summary.panics.len()
    );
}

fn evaluate_testcase(tc: &Testcase, exceptions: &HashMap<String, Exception>) -> Outcome {
    if tc
        .features
        .contains(&Feature::MaxChainDepth)
    {
        return Outcome::Skip("max-chain-depth testcases are not supported by this API".into());
    }

    if !tc.signature_algorithms.is_empty() {
        return Outcome::Skip("signature_algorithms not supported by this API".into());
    }

    if !tc.key_usage.is_empty() {
        return Outcome::Skip("key_usage not supported by this API".into());
    }

    if !tc.crls.is_empty() {
        return Outcome::Skip("CRL revocation not supported by this API".into());
    }

    let validation_result = match catch_unwind(AssertUnwindSafe(|| run_validation(tc))) {
        Ok(result) => result,
        Err(panic) => return Outcome::Panic(panic_message(panic.as_ref())),
    };

    if let Some(exception) = exceptions.get(tc.id.as_str())
        && validation_result.is_ok() == (exception.actual == "SUCCESS")
    {
        return Outcome::KnownDivergence;
    }

    match (&tc.expected_result, validation_result) {
        (ExpectedResult::Success, Ok(())) | (ExpectedResult::Failure, Err(_)) => Outcome::Pass,
        (ExpectedResult::Success, Err(err)) => Outcome::UnexpectedFailure(err),
        (ExpectedResult::Failure, Ok(())) => Outcome::UnexpectedSuccess,
    }
}

fn run_validation(tc: &Testcase) -> Result<(), String> {
    let trusted_ders = tc
        .trusted_certs
        .iter()
        .map(|pem| cert_der_from_pem(pem))
        .collect::<Vec<_>>();
    let trusted = trusted_ders
        .iter()
        .filter_map(|der| Certificate::parse(der).ok())
        .collect::<Vec<_>>();
    if trusted.is_empty() && !trusted_ders.is_empty() {
        return Err("trust anchor parse failed".into());
    }

    let intermediate_ders = tc
        .untrusted_intermediates
        .iter()
        .map(|pem| cert_der_from_pem(pem))
        .collect::<Vec<_>>();
    let intermediates = intermediate_ders
        .iter()
        .filter_map(|der| Certificate::parse(der).ok())
        .collect::<Vec<_>>();

    let leaf_der = cert_der_from_pem(&tc.peer_certificate);
    let leaf = Certificate::parse(&leaf_der).map_err(|e| format!("leaf cert parse failed: {e}"))?;

    let now = match &tc.validation_time {
        Some(time) => time.timestamp(),
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs() as i64,
    };

    let purposes = key_purposes(tc);

    let (name, ip) = match &tc.expected_peer_name {
        Some(peer) => match peer.kind {
            PeerKind::Dns => (Some(peer.value.as_str()), None),
            PeerKind::Ip => (None, Some(peer.value.as_str())),
            PeerKind::Rfc822 => return Err("RFC822 peer names not supported by this API".into()),
        },
        None => (None, None),
    };

    let validator = Validator::with_policy_and_backend(
        CertificateStore::from_iter(trusted),
        policy! {
            RFC5280Policy::new(now);
            EkuPolicy::key_purposes(purposes);
            if (name.is_some() || ip.is_some()) { ServerIdentityPolicy::new(name, ip) }
        },
        &DEFAULT_PROVIDER,
    );

    let intermediates = CertificateStore::from_iter(intermediates);
    match validator.validate(&leaf, &intermediates) {
        Ok(_) => Ok(()),
        Err(reasons) => Err(common::reasons(&reasons)),
    }
}

fn key_purposes(tc: &Testcase) -> Vec<Oid<'static>> {
    if tc.extended_key_usage.is_empty() {
        return match tc.validation_kind {
            ValidationKind::Server => vec![eku_oids::server_auth()],
            ValidationKind::Client => vec![eku_oids::client_auth()],
        };
    }

    tc.extended_key_usage
        .iter()
        .map(|eku| match eku {
            KnownEkUs::AnyExtendedKeyUsage => eku_oids::any_extended_key_usage(),
            KnownEkUs::ServerAuth => eku_oids::server_auth(),
            KnownEkUs::ClientAuth => eku_oids::client_auth(),
            KnownEkUs::CodeSigning => eku_oids::code_signing(),
            KnownEkUs::EmailProtection => eku_oids::email_protection(),
            KnownEkUs::TimeStamping => eku_oids::time_stamping(),
            KnownEkUs::OcspSigning => eku_oids::ocsp_signing(),
        })
        .collect()
}

struct Exception {
    actual: String,
}

fn exceptions() -> HashMap<String, Exception> {
    let json: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/x509_limbo/exceptions.json"))
            .expect("invalid exceptions JSON");
    json.as_object()
        .expect("exceptions JSON is an object")
        .iter()
        .map(|(id, exception)| {
            let actual = exception["actual"]
                .as_str()
                .expect("exception has an actual result")
                .to_string();
            (id.clone(), Exception { actual })
        })
        .collect()
}

fn cert_der_from_pem(pem: &str) -> Vec<u8> {
    let (_, pem) = parse_x509_pem(pem.as_bytes()).expect("cert PEM parse failed");
    pem.contents
}

fn panic_message(panic: &(dyn core::any::Any + Send)) -> String {
    if let Some(message) = panic.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".into()
    }
}

#[derive(Debug)]
enum Outcome {
    Pass,
    Skip(String),
    KnownDivergence,
    UnexpectedFailure(String),
    UnexpectedSuccess,
    Panic(String),
}

#[derive(Debug, Default)]
struct Summary {
    passed: Vec<String>,
    skipped: Vec<(String, String)>,
    known_divergences: Vec<String>,
    unexpected_failures: Vec<(String, String)>,
    unexpected_successes: Vec<String>,
    panics: Vec<(String, String)>,
}

impl Summary {
    fn print(&self) {
        println!("\nx509-limbo: {} tests", self.total());
        println!("  {} passed (match expected)", self.passed.len());
        println!("  {} skipped (unsupported features)", self.skipped.len());
        println!(
            "  {} known divergences (shared with rustls/webpki, see exceptions.json)",
            self.known_divergences.len()
        );

        if !self.panics.is_empty() {
            println!("\nPANICS ({}):", self.panics.len());
            for (id, message) in &self.panics {
                println!("  - {id}: {message}");
            }
        }

        if !self.unexpected_failures.is_empty() {
            println!(
                "\nUNEXPECTED FAILURES ({}):",
                self.unexpected_failures.len()
            );
            for (id, err) in &self.unexpected_failures {
                println!("  - {id}: {err}");
            }
        }

        if !self.unexpected_successes.is_empty() {
            println!(
                "\nUNEXPECTED SUCCESSES ({}):",
                self.unexpected_successes.len()
            );
            for id in &self.unexpected_successes {
                println!("  - {id}");
            }
        }
    }

    fn total(&self) -> usize {
        self.passed.len()
            + self.skipped.len()
            + self.known_divergences.len()
            + self.unexpected_failures.len()
            + self.unexpected_successes.len()
            + self.panics.len()
    }
}
