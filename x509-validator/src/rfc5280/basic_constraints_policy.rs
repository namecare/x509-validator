use crate::{ValidationPolicy, PolicyEvaluationResult, PolicyFailureReason};
use crate::der_parser::Oid;
use crate::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS;
use crate::unverified_chain::UnverifiedCertificateChain;

/// id-ce-basicConstraints, RFC 5280 §4.2.1.9: 2.5.29.19.
fn basic_constraints_oid() -> Oid<'static> {
    OID_X509_EXT_BASIC_CONSTRAINTS
}

/// A sub-policy of the [`RFC5280Policy`] that polices the basicConstraints extension.
///
/// [`RFC5280Policy`]: crate::rfc5280::RFC5280Policy
pub struct BasicConstraintsPolicy;

impl ValidationPolicy for BasicConstraintsPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![basic_constraints_oid()]
    }

    fn chain_meets_policy_requirements(&self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        // The rules for BasicConstraints come from https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9,
        // but roughly can be summarised as:
        //
        // 0. If the cert is a v1 cert then shrug our shoulders, it can do whatever.
        // 1. If basicConstraints is absent, the cert must not be used as an issuing certificate.
        // 2. If basicConstraints is present and does not assert that this is a CA, this must not be used
        //        as an issuing certificate.
        // 3. If basic constraints is present, and the CA bit is present, and there is a path length constraint,
        //        then this certificate may not have more sub CAs than the path length constraint allows.
        //
        // RFC 5280 also wants us to enforce key usage. Unfortunately, as a practical matter, browsers don't. That
        // means that other implementations, like Go and webpki, also don't. To maximise compatibility, we don't either.
        if chain.is_empty() {
            // This is conceptually impossible, but we'll tolerate it.
            return Err(PolicyFailureReason::new("empty certificate chain"));
        }

        let leaf = chain.leaf();
        let leaf_is_v1 = leaf.tbs_certificate.version == crate::x509::X509Version::V1;

        // We check for the special-case of a trust root being presented as the end entity cert. If that's what's
        // happening, we require that this cert be marked as a CA.
        if chain.len() == 1 && !leaf_is_v1 {
            let basic_constraints = leaf
                .tbs_certificate
                .basic_constraints()
                .map_err(|error| PolicyFailureReason::new(format!("error processing basic constraints for {:?}: {}", leaf, error)))?;

            return match basic_constraints {
                Some(bc) if bc.value.ca => Ok(()),
                _ => Err(PolicyFailureReason::new(format!("self-signed cert {:?} is not marked as a CA", leaf))),
            };
        }

        // Now we check the chain.
        let mut sub_ca_count: u32 = 0;

        for i in 1..chain.len() {
            let cert = &chain[i];
            let is_v1 = cert.tbs_certificate.version == crate::x509::X509Version::V1;

            if !is_v1 {
                let basic_constraints = cert
                    .tbs_certificate
                    .basic_constraints()
                    .map_err(|error| PolicyFailureReason::new(format!("error processing basic constraints for {:?}: {}", cert, error)))?;

                match basic_constraints {
                    Some(bc) if bc.value.ca => {
                        // Is a CA, but either the max path length is at least as large as our current set of sub CAs,
                        // or there isn't one. Continue to the next cert.
                        if let Some(max_path_length) = bc.value.path_len_constraint {
                            // Is a CA, but the max path length is smaller than the number of sub CAs we have.
                            if max_path_length < sub_ca_count {
                                return Err(PolicyFailureReason::new(format!(
                                    "CA {:?} has maximum path length {}, but chain has {} subCAs",
                                    cert, max_path_length, sub_ca_count
                                )));
                            }
                        }
                    }
                    _ => {
                        return Err(PolicyFailureReason::new(format!("certificate {:?} is not marked as a CA", cert)));
                    }
                }
            }
            // Is a v1 cert. Basic constraints don't apply here. Continue to the next cert.
            // Note that we _do_ include this in the path length, in case there are basic constraints further along
            // the path.

            if cert.issuer() != cert.subject() {
                // only non-self-issued certificates count against the maxPathLength limit
                //
                // RFC Section 4.2.1.9.  Basic Constraints
                // [...]
                // The pathLenConstraint field is meaningful only if the cA boolean is
                // asserted and the key usage extension, if present, asserts the
                // keyCertSign bit (Section 4.2.1.3).  In this case, it gives the
                // maximum number of non-self-issued intermediate certificates that may
                // follow this certificate in a valid certification path.  (Note: The
                // last certificate in the certification path is not an intermediate
                // certificate, and is not included in this limit.  Usually, the last
                // certificate is an end entity certificate, but it can be a CA
                // certificate.)  A pathLenConstraint of zero indicates that no non-
                // self-issued intermediate CA certificates may follow in a valid
                // certification path.  Where it appears, the pathLenConstraint field
                // MUST be greater than or equal to zero.  Where pathLenConstraint does
                // not appear, no limit is imposed.
                // [...]
                // https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9

                sub_ca_count += 1;
            }
        }

        Ok(())
    }
}