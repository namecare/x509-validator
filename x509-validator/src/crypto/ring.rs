//! ring backed crypto backend.

// This module is named `ring`, which shadows the external crate of the same
// name for paths written inside it, so the crate is aliased and the alias
// handed to the macro.
use ::ring as ring_krate;

// ring ships no ECDSA-with-SHA512 verification algorithm for either curve, so
// no 512 arm appears below and those pairings surface as
// `CryptoError::InvalidKey`.
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
    use super::*;
    use x509_validator_testkit::rcgen::{CertificateParams, KeyPair};
    use x509_validator_core::FromDer;
    use x509_validator_core::Certificate;

    /// Builds a real self-signed certificate for `key_pair` and parses it
    /// back, giving tests a genuine `AlgorithmIdentifier`/`SubjectPublicKeyInfo`
    /// pair straight from a real DER encoding rather than hand-assembled
    /// ASN.1 structs.
    fn self_signed(key_pair: &KeyPair) -> Vec<u8> {
        let params = CertificateParams::default();
        params.self_signed(key_pair).expect("self-sign").der().to_vec()
    }

    fn parse(der: &'static [u8]) -> Certificate<'static> {
        Certificate::from_der(der).unwrap().1
    }

    #[test]
    fn ecdsa_p256_round_trip_verifies() {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = parse(der);

        let public_key = Ring
            .public_key(&cert.signature_algorithm, cert.public_key())
            .expect("build public key");

        let result = public_key.is_valid(cert.signature_value.as_ref(), cert.tbs_certificate.as_ref());
        assert!(result.is_ok(), "expected valid signature to verify, got {result:?}");
    }

    #[test]
    fn ecdsa_p256_tampered_message_fails() {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = parse(der);

        let public_key = Ring
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
        let cert = parse(der);

        let result = Ring.public_key(&algorithm, cert.public_key());
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    /// Unlike the aws_lc backend, ring has no ECDSA-with-SHA512 verification
    /// algorithm, so this pairing is reported as unsupported rather than
    /// silently verified with a different digest.
    #[test]
    fn ecdsa_sha512_is_unsupported() {
        let algorithm = AlgorithmIdentifier {
            algorithm: oid_registry::OID_SIG_ECDSA_WITH_SHA512,
            parameters: None,
        };
        let key_pair = KeyPair::generate().expect("generate key pair");
        let der: &'static [u8] = Box::leak(self_signed(&key_pair).into_boxed_slice());
        let cert = parse(der);

        let result = Ring.public_key(&algorithm, cert.public_key());
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn digest_returns_32_bytes() {
        let hash = Ring.hash(b"some data");
        assert_eq!(hash.len(), 32);
    }
}