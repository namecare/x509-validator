use crate::{VerifierPolicy, PolicyEvaluationResult, PolicyFailureReason};
use x509_validator_core::der_parser::Oid;
use x509_validator_core::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

/// id-ce-basicConstraints, RFC 5280 §4.2.1.9: 2.5.29.19.
fn basic_constraints_oid() -> Oid<'static> {
    OID_X509_EXT_BASIC_CONSTRAINTS
}

/// A sub-policy of `RFC5280Policy` that polices the basicConstraints
/// extension.
///
/// The rules come from RFC 5280 §4.2.1.9, summarized:
///
/// 0. A v1 certificate may do whatever it likes; basicConstraints doesn't
///    apply.
/// 1. If basicConstraints is absent, the certificate must not be used as an
///    issuing certificate.
/// 2. If basicConstraints is present and does not assert the CA bit, the
///    certificate must not be used as an issuing certificate.
/// 3. If basicConstraints asserts the CA bit and carries a path length
///    constraint, the certificate may not have more non-self-issued sub-CAs
///    than that constraint allows.
///
/// RFC 5280 also wants us to enforce keyUsage. In practice, mainstream
/// implementations don't, to maximize interoperability — so this crate
/// doesn't either.
pub struct BasicConstraintsPolicy;

impl VerifierPolicy for BasicConstraintsPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![basic_constraints_oid()]
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        if chain.is_empty() {
            // Conceptually impossible (UnverifiedCertificateChain enforces
            // non-empty at construction), but tolerate it defensively.
            return Err(PolicyFailureReason::new("empty certificate chain"));
        }

        let leaf = chain.leaf();
        let leaf_is_v1 = leaf.tbs_certificate.version == x509_validator_core::x509::X509Version::V1;

        // Special case: the leaf is presented alone (i.e. a self-signed
        // trust anchor as the end-entity cert). We require that it be
        // marked as a CA.
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

        let mut sub_ca_count: u32 = 0;

        for i in 1..chain.len() {
            let cert = &chain[i];
            let is_v1 = cert.tbs_certificate.version == x509_validator_core::x509::X509Version::V1;

            if !is_v1 {
                let basic_constraints = cert
                    .tbs_certificate
                    .basic_constraints()
                    .map_err(|error| PolicyFailureReason::new(format!("error processing basic constraints for {:?}: {}", cert, error)))?;

                match basic_constraints {
                    Some(bc) if bc.value.ca => {
                        if let Some(max_path_length) = bc.value.path_len_constraint {
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
            // v1 certificates are exempt from basicConstraints checking, but
            // still count toward the path length below.

            if cert.issuer() != cert.subject() {
                // Only non-self-issued certificates count against
                // maxPathLength. RFC 5280 §4.2.1.9: pathLenConstraint gives
                // the maximum number of non-self-issued intermediate
                // certificates that may follow this certificate in a valid
                // certification path; the final certificate in the path is
                // not counted.
                sub_ca_count += 1;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{issue_ca, issue_leaf, self_signed_ca_with};
    use rcgen::CertificateParams;
    use x509_validator_core::FromDer;
    use x509_validator_core::Certificate;

    fn chain_of(ders: Vec<Vec<u8>>) -> UnverifiedCertificateChain<'static> {
        let certs = ders
            .into_iter()
            .map(|der| {
                let der: &'static [u8] = Box::leak(der.into_boxed_slice());
                Certificate::from_der(der).unwrap().1
            })
            .collect();
        UnverifiedCertificateChain::new(certs)
    }

    #[test]
    fn leaf_and_ca_chain_is_accepted() {
        let root = self_signed_ca_with("root", |_| {});
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let chain = chain_of(vec![leaf, root.der]);
        let mut policy = BasicConstraintsPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn self_signed_leaf_used_as_trust_anchor_must_be_a_ca() {
        let root = self_signed_ca_with("root", |_| {});
        let chain = chain_of(vec![root.der]);
        let mut policy = BasicConstraintsPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn self_signed_leaf_without_ca_bit_is_rejected() {
        // A self-signed cert that isn't marked as a CA at all: built the
        // same way `issue_leaf` builds ordinary leaves, but self-signed.
        let this = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.is_ca = rcgen::IsCa::NoCa;
        });
        let chain = chain_of(vec![this.der]);
        let mut policy = BasicConstraintsPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn non_ca_intermediate_is_rejected() {
        let root = self_signed_ca_with("root", |_| {});
        // "intermediate" is issued as a non-CA leaf, then used to sign
        // another cert anyway — its basicConstraints has no CA bit set.
        let intermediate = issue_leaf("intermediate", &[], &root);
        let intermediate_der: &'static [u8] = Box::leak(intermediate.clone().into_boxed_slice());
        let intermediate_cert = Certificate::from_der(intermediate_der).unwrap().1;
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);

        let chain = UnverifiedCertificateChain::new(vec![
            {
                let leaf_der: &'static [u8] = Box::leak(leaf.into_boxed_slice());
                Certificate::from_der(leaf_der).unwrap().1
            },
            intermediate_cert,
            {
                let root_der: &'static [u8] = Box::leak(root.der.into_boxed_slice());
                Certificate::from_der(root_der).unwrap().1
            },
        ]);
        let mut policy = BasicConstraintsPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn path_length_constraint_satisfied_is_accepted() {
        let root = self_signed_ca_with("root", |_| {});
        let intermediate = issue_ca("intermediate", &root, Some(1), |_| {});
        let leaf = issue_leaf("leaf", &["www.example.com"], &intermediate);
        let chain = chain_of(vec![leaf, intermediate.der, root.der]);
        let mut policy = BasicConstraintsPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn path_length_constraint_violated_is_rejected() {
        let root = self_signed_ca_with("root", |_| {});
        let intermediate1 = issue_ca("intermediate1", &root, Some(0), |_| {});
        let intermediate2 = issue_ca("intermediate2", &intermediate1, None, |_| {});
        let leaf = issue_leaf("leaf", &["www.example.com"], &intermediate2);
        let chain = chain_of(vec![leaf, intermediate2.der, intermediate1.der, root.der]);
        let mut policy = BasicConstraintsPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn self_issued_intermediate_does_not_count_against_path_length() {
        // "intermediate" re-issues itself (same subject name, fresh key)
        // before signing the leaf; that self-issued hop must not consume
        // the path-length budget.
        let root = self_signed_ca_with("root", |_| {});
        let intermediate = issue_ca("intermediate", &root, Some(0), |_| {});
        let self_issued = issue_ca("intermediate", &intermediate, Some(0), |_| {});
        let leaf = issue_leaf("leaf", &["www.example.com"], &self_issued);
        let chain = chain_of(vec![leaf, self_issued.der, intermediate.der, root.der]);
        let mut policy = BasicConstraintsPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn verifying_critical_extensions_includes_basic_constraints_oid() {
        let policy = BasicConstraintsPolicy;
        let oids = policy.verifying_critical_extensions();
        assert!(oids.contains(&basic_constraints_oid()));
    }
}