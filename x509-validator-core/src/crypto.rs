//! Backend-neutral helpers shared by crypto backends.

use crate::oid_registry;
use crate::{Any, RsaSsaPssParams};

/// The digest size, in bits, that an RSASSA-PSS `signatureAlgorithm` is
/// parameterised with.
///
/// RSA-PSS names its digest in the algorithm parameters rather than in the
/// signature OID, so selecting a verification algorithm means decoding those
/// parameters first. That decoding is identical across crypto backends; only
/// the mapping from a digest size to a backend's own algorithm handle differs.
///
/// Returns `None` when the parameters are absent, cannot be decoded as
/// `RSASSA-PSS-params`, or name a digest outside the SHA-2 family this crate
/// recognises. Note that RFC 4055 makes SHA-1 the default when the parameters
/// omit a hash algorithm; that case is reported as `None` here, since no
/// backend offers SHA-1 RSA-PSS verification.
pub fn rsa_pss_digest_bits(params: Option<&Any>) -> Option<usize> {
    let params = params?;
    let params = RsaSsaPssParams::try_from(params).ok()?;
    let hash_algorithm = params.hash_algorithm_oid();

    if *hash_algorithm == oid_registry::OID_NIST_HASH_SHA256 {
        Some(256)
    } else if *hash_algorithm == oid_registry::OID_NIST_HASH_SHA384 {
        Some(384)
    } else if *hash_algorithm == oid_registry::OID_NIST_HASH_SHA512 {
        Some(512)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FromDer;

    #[test]
    fn absent_parameters_yield_no_digest() {
        assert_eq!(rsa_pss_digest_bits(None), None);
    }

    #[test]
    fn undecodable_parameters_yield_no_digest() {
        // A NULL where `RSASSA-PSS-params` (a SEQUENCE) is expected.
        let params = Any::from_der(&[0x05, 0x00]).expect("parse NULL").1;

        assert_eq!(rsa_pss_digest_bits(Some(&params)), None);
    }

    /// DER for `RSASSA-PSS-params` carrying only a `hashAlgorithm` of `oid`.
    fn pss_params_der(oid_der: &[u8]) -> Vec<u8> {
        // AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER }
        let mut algorithm_identifier = vec![0x30, oid_der.len() as u8];
        algorithm_identifier.extend_from_slice(oid_der);

        // hashAlgorithm is context tag [0], explicit.
        let mut tagged = vec![0xa0, algorithm_identifier.len() as u8];
        tagged.extend_from_slice(&algorithm_identifier);

        // RSASSA-PSS-params ::= SEQUENCE { [0] hashAlgorithm ... }
        let mut params = vec![0x30, tagged.len() as u8];
        params.extend_from_slice(&tagged);
        params
    }

    #[test]
    fn sha2_hash_algorithms_yield_their_digest_size() {
        // OIDs 2.16.840.1.101.3.4.2.{1,2,3} = SHA-256 / SHA-384 / SHA-512.
        for (last_octet, expected) in [(0x01, 256), (0x02, 384), (0x03, 512)] {
            let oid_der = [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last_octet,
            ];
            let der = pss_params_der(&oid_der);
            let params = Any::from_der(&der).expect("parse PSS params").1;

            assert_eq!(rsa_pss_digest_bits(Some(&params)), Some(expected));
        }
    }

    #[test]
    fn non_sha2_hash_algorithm_yields_no_digest() {
        // OID 1.3.14.3.2.26 = SHA-1, which no backend supports for RSA-PSS.
        let oid_der = [0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];
        let der = pss_params_der(&oid_der);
        let params = Any::from_der(&der).expect("parse PSS params").1;

        assert_eq!(rsa_pss_digest_bits(Some(&params)), None);
    }
}