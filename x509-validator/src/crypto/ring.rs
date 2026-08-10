//! ring backed crypto backend.

use ::ring as ring_krate;

backend! {
    krate: ring_krate,
    backend: Ring,
    ecdsa_p256: {
        256 => ECDSA_P256_SHA256_ASN1,
        384 => ECDSA_P256_SHA384_ASN1,
    },
    ecdsa_p384: {
        256 => ECDSA_P384_SHA256_ASN1,
        384 => ECDSA_P384_SHA384_ASN1,
    },
}

#[cfg(test)]
mod tests {
    use x509_validator_testkit::rcgen::KeyPair;
    use x509_validator_testkit::self_signed;

    use super::*;
    use crate::{Certificate, CertificateExt, oid_registry};

    #[test]
    fn ecdsa_p256_round_trip_verifies() {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

        let result = Ring.verify_signature(
            &cert.signature_algorithm,
            cert.public_key(),
            cert.tbs_certificate.as_ref(),
            cert.signature_value.as_ref(),
        );
        assert!(
            result.is_ok(),
            "expected valid signature to verify, got {result:?}"
        );
    }

    #[test]
    fn ecdsa_p256_tampered_message_fails() {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

        let result = Ring.verify_signature(
            &cert.signature_algorithm,
            cert.public_key(),
            b"tampered message",
            cert.signature_value.as_ref(),
        );
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

        let result = Ring.verify_signature(&algorithm, cert.public_key(), b"message", b"signature");
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn ecdsa_sha512_is_unsupported() {
        let algorithm = AlgorithmIdentifier {
            algorithm: oid_registry::OID_SIG_ECDSA_WITH_SHA512,
            parameters: None,
        };
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

        let result = Ring.verify_signature(&algorithm, cert.public_key(), b"message", b"signature");
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }
}
