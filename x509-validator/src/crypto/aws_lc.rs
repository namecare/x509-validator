//! aws-lc-rs backed crypto backend.

backend! {
    krate: aws_lc_rs,
    backend: AwsLc,
    ecdsa_p256: {
        256 => ECDSA_P256_SHA256_ASN1,
        384 => ECDSA_P256_SHA384_ASN1,
        512 => ECDSA_P256_SHA512_ASN1,
    },
    ecdsa_p384: {
        256 => ECDSA_P384_SHA256_ASN1,
        384 => ECDSA_P384_SHA384_ASN1,
        512 => ECDSA_P384_SHA512_ASN1,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_validator_testkit::rcgen::{CertificateParams, KeyPair};
    use x509_validator_core::CertificateExt;
    use x509_validator_core::Certificate;

    /// Builds a real self-signed certificate for `key_pair` and parses it
    /// back, giving tests a genuine `AlgorithmIdentifier`/`SubjectPublicKeyInfo`
    /// pair straight from a real DER encoding rather than hand-assembled
    /// ASN.1 structs.
    fn self_signed(key_pair: &KeyPair) -> Vec<u8> {
        let params = CertificateParams::default();
        params.self_signed(key_pair).expect("self-sign").der().to_vec()
    }

    #[test]
    fn ecdsa_p256_round_trip_verifies() {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

        let public_key = AwsLc
            .public_key(&cert.signature_algorithm, cert.public_key())
            .expect("build public key");

        let result = public_key.is_valid(cert.signature_value.as_ref(), cert.tbs_certificate.as_ref());
        assert!(result.is_ok(), "expected valid signature to verify, got {result:?}");
    }

    #[test]
    fn ecdsa_p256_tampered_message_fails() {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

        let public_key = AwsLc
            .public_key(&cert.signature_algorithm, cert.public_key())
            .expect("build public key");

        let result = public_key.is_valid(cert.signature_value.as_ref(), b"tampered message");
        assert!(matches!(result, Err(CryptoError::VerificationFailed)));
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let algorithm = AlgorithmIdentifier {
            algorithm: oid_registry::OID_SIG_ED448,
            parameters: None,
        };
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

        let result = AwsLc.public_key(&algorithm, cert.public_key());
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn digest_returns_32_bytes() {
        let hash = AwsLc.hash(b"some data");
        assert_eq!(hash.len(), 32);
    }
}