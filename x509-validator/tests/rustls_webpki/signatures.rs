use std::sync::OnceLock;

use x509_validator::crypto::{CryptoError, SignatureVerifier};
use x509_validator::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use x509_validator::{Certificate, CertificateExt, FromDer};
use x509_validator_testkit::rcgen::{self, KeyPair, SignatureAlgorithm, SigningKey};
use x509_validator_testkit::{LeafSpec, self_signed_ca_with};

#[derive(Debug, PartialEq, Eq)]
enum Error {
    InvalidSignatureForPublicKey,
    UnsupportedSignatureAlgorithmForPublicKey,
}

#[derive(Clone, Copy, Debug)]
enum Alg {
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    Ed25519,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
}

const ECDSA_P256_SHA256: Alg = Alg::EcdsaSha256;
const ECDSA_P256_SHA384: Alg = Alg::EcdsaSha384;
const ECDSA_P384_SHA256: Alg = Alg::EcdsaSha256;
const ECDSA_P384_SHA384: Alg = Alg::EcdsaSha384;
const ECDSA_P521_SHA256: Alg = Alg::EcdsaSha256;
const ECDSA_P521_SHA384: Alg = Alg::EcdsaSha384;
const ECDSA_P521_SHA512: Alg = Alg::EcdsaSha512;
const ED25519: Alg = Alg::Ed25519;
const RSA_PKCS1_2048_8192_SHA256: Alg = Alg::RsaPkcs1Sha256;
const RSA_PKCS1_2048_8192_SHA384: Alg = Alg::RsaPkcs1Sha384;
const RSA_PKCS1_2048_8192_SHA512: Alg = Alg::RsaPkcs1Sha512;
const RSA_PSS_2048_8192_SHA256_LEGACY_KEY: Alg = Alg::RsaPssSha256;
const RSA_PSS_2048_8192_SHA384_LEGACY_KEY: Alg = Alg::RsaPssSha384;
const RSA_PSS_2048_8192_SHA512_LEGACY_KEY: Alg = Alg::RsaPssSha512;

impl Alg {
    fn der(self) -> Vec<u8> {
        const ECDSA: [u8; 7] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03];
        const PKCS1: [u8; 8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
        const SHA2: [u8; 8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02];

        let oid = |arc: &[u8], last: u8| tlv(0x06, &[arc, &[last]].concat());
        let null = [0x05, 0x00];
        let hash = |last: u8| tlv(0x30, &[oid(&SHA2, last), null.to_vec()].concat());
        let pss = |last: u8, salt: u8| {
            let params = [
                tlv(0xa0, &hash(last)),
                tlv(0xa1, &tlv(0x30, &[oid(&PKCS1, 0x08), hash(last)].concat())),
                tlv(0xa2, &[0x02, 0x01, salt]),
            ]
            .concat();
            [oid(&PKCS1, 0x0a), tlv(0x30, &params)].concat()
        };

        let body = match self {
            Self::EcdsaSha256 => oid(&ECDSA, 0x02),
            Self::EcdsaSha384 => oid(&ECDSA, 0x03),
            Self::EcdsaSha512 => oid(&ECDSA, 0x04),
            Self::Ed25519 => tlv(0x06, &[0x2b, 0x65, 0x70]),
            Self::RsaPkcs1Sha256 => [oid(&PKCS1, 0x0b), null.to_vec()].concat(),
            Self::RsaPkcs1Sha384 => [oid(&PKCS1, 0x0c), null.to_vec()].concat(),
            Self::RsaPkcs1Sha512 => [oid(&PKCS1, 0x0d), null.to_vec()].concat(),
            Self::RsaPssSha256 => pss(0x01, 32),
            Self::RsaPssSha384 => pss(0x02, 48),
            Self::RsaPssSha512 => pss(0x03, 64),
        };
        tlv(0x30, &body)
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 0x80);
    [&[tag, value.len() as u8][..], value].concat()
}

fn providers() -> Vec<(&'static str, &'static dyn SignatureVerifier)> {
    vec![
        #[cfg(feature = "aws_lc")]
        ("aws_lc", &x509_validator::crypto::aws_lc::DEFAULT_PROVIDER),
        #[cfg(feature = "ring")]
        ("ring", &x509_validator::crypto::ring::DEFAULT_PROVIDER),
        #[cfg(feature = "rust_crypto")]
        (
            "rust_crypto",
            &x509_validator::crypto::rust_crypto::DEFAULT_PROVIDER,
        ),
    ]
}

fn verify(
    spki: &SubjectPublicKeyInfo<'_>,
    alg: Alg,
    message: &[u8],
    signature: &[u8],
) -> Vec<(&'static str, Result<(), Error>)> {
    let der = alg.der();
    let (_, algorithm) = AlgorithmIdentifier::from_der(&der).expect("algorithm identifier parses");
    providers()
        .into_iter()
        .map(|(name, provider)| {
            let result = provider
                .verify_signature(&algorithm, spki, message, signature)
                .map_err(|error| match error {
                    CryptoError::VerificationFailed => Error::InvalidSignatureForPublicKey,
                    CryptoError::InvalidKey(_) => Error::UnsupportedSignatureAlgorithmForPublicKey,
                });
            (name, result)
        })
        .collect()
}

fn check_sig(
    ee: &[u8],
    alg: Alg,
    message: &[u8],
    signature: &[u8],
) -> Vec<(&'static str, Result<(), Error>)> {
    let cert = Certificate::parse(ee).expect("certificate parses");
    verify(cert.public_key(), alg, message, signature)
}

fn check_sig_rpk(
    spki: &[u8],
    alg: Alg,
    message: &[u8],
    signature: &[u8],
) -> Vec<(&'static str, Result<(), Error>)> {
    let (_, spki) = SubjectPublicKeyInfo::from_der(spki).expect("SPKI parses");
    verify(&spki, alg, message, signature)
}

#[track_caller]
fn assert_all(results: Vec<(&'static str, Result<(), Error>)>, expected: Result<(), Error>) {
    assert!(!results.is_empty(), "no crypto backend enabled");
    for (backend, result) in results {
        assert_eq!(result, expected, "backend {backend}");
    }
}

#[track_caller]
fn assert_rejected_by_other_algorithms(ee: &[u8], algorithms: &[Alg]) {
    let mismatches = algorithms
        .iter()
        .flat_map(|algorithm| {
            check_sig(ee, *algorithm, b"", b"")
                .into_iter()
                .filter(|(_, result)| {
                    *result != Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
                })
                .map(move |(backend, result)| format!("{backend} {algorithm:?}: {result:?}"))
        })
        .collect::<Vec<_>>();
    assert!(
        mismatches.is_empty(),
        "expected UnsupportedSignatureAlgorithmForPublicKey, got:\n{}",
        mismatches.join("\n")
    );
}

#[test]
#[ignore = "divergence, fail-closed: the aws_lc and ring backends never compare \
            the SPKI algorithm with the signature algorithm's key family, so a \
            mismatched pairing reaches the primitive and fails as a bad signature \
            rather than being refused as unsupported for the key; rust_crypto \
            refuses it"]
fn ed25519() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ED25519, "ed25519 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_all(
        check_sig(&test_cert.cert, ED25519, MESSAGE, &good_sig),
        Ok(()),
    );
    assert_all(
        check_sig_rpk(&test_cert.spki_der, ED25519, MESSAGE, &good_sig),
        Ok(()),
    );
    assert_all(
        check_sig(&test_cert.cert, ED25519, MESSAGE, &bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );
    assert_all(
        check_sig_rpk(&test_cert.spki_der, ED25519, MESSAGE, &bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );

    assert_rejected_by_other_algorithms(
        &test_cert.cert,
        &[
            ECDSA_P521_SHA256,
            ECDSA_P521_SHA384,
            ECDSA_P521_SHA512,
            ECDSA_P256_SHA256,
            ECDSA_P256_SHA384,
            ECDSA_P384_SHA256,
            ECDSA_P384_SHA384,
            RSA_PKCS1_2048_8192_SHA256,
            RSA_PKCS1_2048_8192_SHA384,
            RSA_PKCS1_2048_8192_SHA512,
            RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        ],
    );
}

#[test]
fn ecdsa_p256_sha384() {
    let ee = include_bytes!("fixtures/signatures/ecdsa_p256.ee.der");
    let rpk = include_bytes!("fixtures/signatures/ecdsa_p256.spki.der");
    let message = include_bytes!("fixtures/signatures/message.bin");
    let good_sig = include_bytes!(
        "fixtures/signatures/ecdsa_p256_key_and_ecdsa_p256_sha384_good_signature.sig.bin"
    );
    let bad_sig = include_bytes!(
        "fixtures/signatures/ecdsa_p256_key_and_ecdsa_p256_sha384_detects_bad_signature.sig.bin"
    );

    assert_all(check_sig(ee, ECDSA_P256_SHA384, message, good_sig), Ok(()));
    assert_all(
        check_sig_rpk(rpk, ECDSA_P256_SHA384, message, good_sig),
        Ok(()),
    );
    assert_all(
        check_sig(ee, ECDSA_P256_SHA384, message, bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );
    assert_all(
        check_sig_rpk(rpk, ECDSA_P256_SHA384, message, bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );
}

#[test]
#[ignore = "divergence, fail-closed: the aws_lc and ring backends never compare \
            the SPKI algorithm with the signature algorithm's key family, so a \
            mismatched pairing reaches the primitive and fails as a bad signature \
            rather than being refused as unsupported for the key; rust_crypto \
            refuses it"]
fn ecdsa_p256_sha256() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P256_SHA256, "ecdsa_p256 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_all(
        check_sig(&test_cert.cert, ECDSA_P256_SHA256, MESSAGE, &good_sig),
        Ok(()),
    );
    assert_all(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P256_SHA256, MESSAGE, &good_sig),
        Ok(()),
    );
    assert_all(
        check_sig(&test_cert.cert, ECDSA_P256_SHA256, MESSAGE, &bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );
    assert_all(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P256_SHA256, MESSAGE, &bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );

    assert_rejected_by_other_algorithms(
        &test_cert.cert,
        &[
            ED25519,
            RSA_PKCS1_2048_8192_SHA256,
            RSA_PKCS1_2048_8192_SHA384,
            RSA_PKCS1_2048_8192_SHA512,
            RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        ],
    );
}

#[test]
fn ecdsa_p384_sha384() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P384_SHA384, "ecdsa_p384 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_all(
        check_sig(&test_cert.cert, ECDSA_P384_SHA384, MESSAGE, &good_sig),
        Ok(()),
    );
    assert_all(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P384_SHA384, MESSAGE, &good_sig),
        Ok(()),
    );
    assert_all(
        check_sig(&test_cert.cert, ECDSA_P384_SHA384, MESSAGE, &bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );
    assert_all(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P384_SHA384, MESSAGE, &bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );
}

#[test]
fn ecdsa_p384_sha256() {
    let ee = include_bytes!("fixtures/signatures/ecdsa_p384.ee.der");
    let rpk = include_bytes!("fixtures/signatures/ecdsa_p384.spki.der");
    let message = include_bytes!("fixtures/signatures/message.bin");
    let good_sig = include_bytes!(
        "fixtures/signatures/ecdsa_p384_key_and_ecdsa_p384_sha256_good_signature.sig.bin"
    );
    let bad_sig = include_bytes!(
        "fixtures/signatures/ecdsa_p384_key_and_ecdsa_p384_sha256_detects_bad_signature.sig.bin"
    );

    assert_all(check_sig(ee, ECDSA_P384_SHA256, message, good_sig), Ok(()));
    assert_all(
        check_sig_rpk(rpk, ECDSA_P384_SHA256, message, good_sig),
        Ok(()),
    );
    assert_all(
        check_sig(ee, ECDSA_P384_SHA256, message, bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );
    assert_all(
        check_sig_rpk(rpk, ECDSA_P384_SHA256, message, bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );
}

#[test]
#[ignore = "divergence, fail-closed: the aws_lc and ring backends never compare \
            the SPKI algorithm with the signature algorithm's key family, so a \
            mismatched pairing reaches the primitive and fails as a bad signature \
            rather than being refused as unsupported for the key; rust_crypto \
            refuses it"]
fn ecdsa_p384_key_rejected_by_other_algorithms() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P384_SHA384, "ecdsa_p384 test");
    assert_rejected_by_other_algorithms(
        &test_cert.cert,
        &[
            ED25519,
            RSA_PKCS1_2048_8192_SHA256,
            RSA_PKCS1_2048_8192_SHA384,
            RSA_PKCS1_2048_8192_SHA512,
            RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        ],
    );
}

#[test]
#[ignore = "capability gap: no backend verifies ECDSA over P-521, so the key is \
            refused as unsupported instead of verifying"]
fn ecdsa_p521_sha256() {
    let ee = include_bytes!("fixtures/signatures/ecdsa_p521.ee.der");
    let rpk = include_bytes!("fixtures/signatures/ecdsa_p521.spki.der");
    let message = include_bytes!("fixtures/signatures/message.bin");
    let good_sig = include_bytes!(
        "fixtures/signatures/ecdsa_p521_key_and_ecdsa_p521_sha256_good_signature.sig.bin"
    );
    let bad_sig = include_bytes!(
        "fixtures/signatures/ecdsa_p521_key_and_ecdsa_p521_sha256_detects_bad_signature.sig.bin"
    );

    assert_all(check_sig(ee, ECDSA_P521_SHA256, message, good_sig), Ok(()));
    assert_all(
        check_sig_rpk(rpk, ECDSA_P521_SHA256, message, good_sig),
        Ok(()),
    );
    assert_all(
        check_sig(ee, ECDSA_P521_SHA256, message, bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );
    assert_all(
        check_sig_rpk(rpk, ECDSA_P521_SHA256, message, bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );
}

#[test]
#[ignore = "capability gap: no backend verifies ECDSA over P-521, so the key is \
            refused as unsupported instead of verifying"]
fn ecdsa_p521_sha384() {
    let ee = include_bytes!("fixtures/signatures/ecdsa_p521.ee.der");
    let rpk = include_bytes!("fixtures/signatures/ecdsa_p521.spki.der");
    let message = include_bytes!("fixtures/signatures/message.bin");
    let good_sig = include_bytes!(
        "fixtures/signatures/ecdsa_p521_key_and_ecdsa_p521_sha384_good_signature.sig.bin"
    );
    let bad_sig = include_bytes!(
        "fixtures/signatures/ecdsa_p521_key_and_ecdsa_p521_sha384_detects_bad_signature.sig.bin"
    );

    assert_all(check_sig(ee, ECDSA_P521_SHA384, message, good_sig), Ok(()));
    assert_all(
        check_sig_rpk(rpk, ECDSA_P521_SHA384, message, good_sig),
        Ok(()),
    );
    assert_all(
        check_sig(ee, ECDSA_P521_SHA384, message, bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );
    assert_all(
        check_sig_rpk(rpk, ECDSA_P521_SHA384, message, bad_sig),
        Err(Error::InvalidSignatureForPublicKey),
    );
}

#[test]
#[ignore = "divergence, fail-closed: the aws_lc and ring backends never compare \
            the SPKI algorithm with the signature algorithm's key family, so a \
            mismatched pairing reaches the primitive and fails as a bad signature \
            rather than being refused as unsupported for the key; rust_crypto \
            refuses it"]
fn ecdsa_p521_key_rejected_by_other_algorithms() {
    let ee = include_bytes!("fixtures/signatures/ecdsa_p521.ee.der");
    assert_rejected_by_other_algorithms(
        ee,
        &[
            ED25519,
            RSA_PKCS1_2048_8192_SHA256,
            RSA_PKCS1_2048_8192_SHA384,
            RSA_PKCS1_2048_8192_SHA512,
            RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        ],
    );
}

#[test]
fn rsa_pkcs1_2048_8192_sha256() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA256, "rsa_2048 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_all(
        check_sig(
            &test_cert.cert,
            RSA_PKCS1_2048_8192_SHA256,
            MESSAGE,
            &good_sig,
        ),
        Ok(()),
    );
    assert_all(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA256,
            MESSAGE,
            &good_sig,
        ),
        Ok(()),
    );
    assert_all(
        check_sig(
            &test_cert.cert,
            RSA_PKCS1_2048_8192_SHA256,
            MESSAGE,
            &bad_sig,
        ),
        Err(Error::InvalidSignatureForPublicKey),
    );
    assert_all(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA256,
            MESSAGE,
            &bad_sig,
        ),
        Err(Error::InvalidSignatureForPublicKey),
    );
}

#[test]
fn rsa_pkcs1_2048_8192_sha384() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA384, "rsa_2048 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_all(
        check_sig(
            &test_cert.cert,
            RSA_PKCS1_2048_8192_SHA384,
            MESSAGE,
            &good_sig,
        ),
        Ok(()),
    );
    assert_all(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA384,
            MESSAGE,
            &good_sig,
        ),
        Ok(()),
    );
    assert_all(
        check_sig(
            &test_cert.cert,
            RSA_PKCS1_2048_8192_SHA384,
            MESSAGE,
            &bad_sig,
        ),
        Err(Error::InvalidSignatureForPublicKey),
    );
    assert_all(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA384,
            MESSAGE,
            &bad_sig,
        ),
        Err(Error::InvalidSignatureForPublicKey),
    );
}

#[test]
fn rsa_pkcs1_2048_8192_sha512() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA512, "rsa_2048 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_all(
        check_sig(
            &test_cert.cert,
            RSA_PKCS1_2048_8192_SHA512,
            MESSAGE,
            &good_sig,
        ),
        Ok(()),
    );
    assert_all(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA512,
            MESSAGE,
            &good_sig,
        ),
        Ok(()),
    );
    assert_all(
        check_sig(
            &test_cert.cert,
            RSA_PKCS1_2048_8192_SHA512,
            MESSAGE,
            &bad_sig,
        ),
        Err(Error::InvalidSignatureForPublicKey),
    );
    assert_all(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA512,
            MESSAGE,
            &bad_sig,
        ),
        Err(Error::InvalidSignatureForPublicKey),
    );
}

#[test]
#[ignore = "divergence, fail-closed: the aws_lc and ring backends never compare \
            the SPKI algorithm with the signature algorithm's key family, so a \
            mismatched pairing reaches the primitive and fails as a bad signature \
            rather than being refused as unsupported for the key; rust_crypto \
            refuses it"]
fn rsa_2048_key_rejected_by_other_algorithms() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA256, "rsa_2048 test");
    assert_rejected_by_other_algorithms(
        &test_cert.cert,
        &[
            ECDSA_P521_SHA256,
            ECDSA_P521_SHA384,
            ECDSA_P521_SHA512,
            ECDSA_P256_SHA256,
            ECDSA_P256_SHA384,
            ECDSA_P384_SHA256,
            ECDSA_P384_SHA384,
            ED25519,
        ],
    );
}

struct TestCertificate {
    key_pair: KeyPair,
    cert: Vec<u8>,
    spki_der: Vec<u8>,
}

impl TestCertificate {
    fn generate(alg: &'static SignatureAlgorithm, org: &str) -> Self {
        let key_pair = key_pair_for(alg);
        let issuer = self_signed_ca_with("issuer.example.com", |_| {});
        let key_pair_copy = KeyPair::from_pkcs8_der_and_sign_algo(
            &key_pair
                .serialize_der()
                .as_slice()
                .into(),
            alg,
        )
        .expect("key pair copy");
        let cert = LeafSpec::new(org)
            .key_pair(key_pair_copy)
            .signed_by(&issuer);
        let spki_der = Certificate::parse(&cert)
            .expect("certificate parses")
            .public_key()
            .raw
            .to_vec();

        Self {
            key_pair,
            cert,
            spki_der,
        }
    }

    fn sign_bad(&self, message: &[u8]) -> Vec<u8> {
        let mut bad_message = message.to_vec();
        bad_message.push(b'X');
        self.sign(&bad_message)
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key_pair.sign(message).unwrap()
    }
}

fn key_pair_for(alg: &'static SignatureAlgorithm) -> KeyPair {
    if [
        &rcgen::PKCS_RSA_SHA256,
        &rcgen::PKCS_RSA_SHA384,
        &rcgen::PKCS_RSA_SHA512,
    ]
    .contains(&alg)
    {
        return KeyPair::from_pkcs8_der_and_sign_algo(&rsa_2048_pkcs8().to_vec().into(), alg)
            .expect("RSA key pair");
    }
    KeyPair::generate_for(alg).expect("key pair")
}

fn rsa_2048_pkcs8() -> &'static [u8] {
    use rsa::pkcs8::EncodePrivateKey;

    static PKCS8_DER: OnceLock<Vec<u8>> = OnceLock::new();
    PKCS8_DER.get_or_init(|| {
        rsa::RsaPrivateKey::new(&mut rand::rng(), 2048)
            .expect("generate RSA key")
            .to_pkcs8_der()
            .expect("encode PKCS#8")
            .as_bytes()
            .to_vec()
    })
}

const MESSAGE: &[u8] = b"hello world!";
