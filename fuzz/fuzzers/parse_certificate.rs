#![no_main]

use libfuzzer_sys::fuzz_target;
use x509_validator::{Certificate, CertificateExt};

fuzz_target!(|data: &[u8]| {
    let Ok(cert) = Certificate::parse(data) else {
        return;
    };

    let _ = cert.subject_key_identifier();
    let _ = cert.authority_key_identifier();
    let _ = cert.subject_key();
    let _ = cert.issuer_key();
    let _ = cert.subject_alternative_names();
    let _ = cert.public_key();

    for ext in cert.tbs_certificate.iter_extensions() {
        let _ = ext.parsed_extension();
    }

    let _ = x509_validator::certificate::format_certificate(&cert);

    // Re-parsing the same bytes must land in the same place.
    let again = Certificate::parse(data).expect("reparse of accepted DER");
    assert!(cert.has_same_identity_as(&again));
});
