use x509_validator::{Certificate, CertificateExt};

#[test]
fn cert_without_extensions_test() {
    // Check the certificate is valid with
    // `openssl x509 -in cert_without_extensions.der -inform DER -text -noout`
    let ca = include_bytes!("fixtures/misc/cert_without_extensions.der");
    assert!(Certificate::parse(ca).is_ok());
}

#[test]
fn cert_with_empty_extensions_test() {
    // Check the certificate is valid with
    // `openssl x509 -in cert_with_empty_extensions.der -inform DER -text -noout`
    let ca = include_bytes!("fixtures/misc/cert_with_empty_extensions.der");
    assert!(Certificate::parse(ca).is_ok());
}
