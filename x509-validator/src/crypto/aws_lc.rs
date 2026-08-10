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
    use x509_validator_testkit::rcgen::KeyPair;
    use x509_validator_core::oid_registry;
    use x509_validator_core::CertificateExt;
    use x509_validator_core::Certificate;
    use x509_validator_testkit::self_signed;

    #[test]
    fn ecdsa_p256_round_trip_verifies() {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

                let result = AwsLc.verify_signature(
            &cert.signature_algorithm,
            cert.public_key(),
            cert.tbs_certificate.as_ref(),
            cert.signature_value.as_ref(),
        );
        assert!(result.is_ok(), "expected valid signature to verify, got {result:?}");
    }

    #[test]
    fn ecdsa_p256_tampered_message_fails() {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = Certificate::parse(der).expect("parse certificate");

                let result = AwsLc.verify_signature(
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

        let result = AwsLc.verify_signature(&algorithm, cert.public_key(), b"message", b"signature");
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }
}