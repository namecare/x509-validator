use x509_validator_core::{CertificateView, ExtensionsView, Oid};
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use crate::{VerifierPolicy, PolicyEvaluationResult, PolicyFailureReason};

/// id-ce-basicConstraints, RFC 5280 §4.2.1.9: 2.5.29.19.
fn basic_constraints_oid() -> Oid {
    Oid(vec![0x55, 0x1D, 0x13])
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

impl<C: CertificateView> VerifierPolicy<C> for BasicConstraintsPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid> {
        vec![basic_constraints_oid()]
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain<C>) -> PolicyEvaluationResult {
        if chain.is_empty() {
            // Conceptually impossible (UnverifiedCertificateChain enforces
            // non-empty at construction), but tolerate it defensively.
            return Err(PolicyFailureReason::new("empty certificate chain"));
        }

        let leaf = chain.leaf();

        // Special case: the leaf is presented alone (i.e. a self-signed
        // trust anchor as the end-entity cert). We require that it be
        // marked as a CA.
        if chain.len() == 1 && !leaf.is_v1() {
            let basic_constraints = leaf
                .extensions()
                .basic_constraints()
                .map_err(|error| PolicyFailureReason::new(format!("error processing basic constraints for {:?}: {}", leaf, error)))?;

            return match basic_constraints {
                Some(bc) if bc.is_ca => Ok(()),
                _ => Err(PolicyFailureReason::new(format!("self-signed cert {:?} is not marked as a CA", leaf))),
            };
        }

        let mut sub_ca_count: u32 = 0;

        for i in 1..chain.len() {
            let cert = &chain[i];

            if !cert.is_v1() {
                let basic_constraints = cert
                    .extensions()
                    .basic_constraints()
                    .map_err(|error| PolicyFailureReason::new(format!("error processing basic constraints for {:?}: {}", cert, error)))?;

                match basic_constraints {
                    Some(bc) if bc.is_ca => {
                        if let Some(max_path_length) = bc.max_path_length {
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
    use x509_validator_core::{
        BasicConstraints, GeneralNameKind, NameConstraints, NameView, PublicKeyInfoView, SignatureAlgorithmId, Timestamp,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeName {
        der: Vec<u8>,
    }

    impl NameView for FakeName {
        fn general_names(&self) -> Vec<(GeneralNameKind, Vec<u8>)> {
            vec![]
        }
        fn canonical_der(&self) -> &[u8] {
            &self.der
        }
        fn common_name(&self) -> Option<Vec<u8>> {
            None
        }
    }

    #[derive(Debug, Clone, Default)]
    struct FakeExtensions {
        basic_constraints: Option<(bool, Option<u32>)>,
    }

    impl ExtensionsView for FakeExtensions {
        type Error = std::io::Error;

        fn oids(&self) -> Vec<(Oid, bool)> {
            vec![]
        }
        fn bytes_for(&self, _oid: &Oid) -> Option<&[u8]> {
            None
        }
        fn basic_constraints(&self) -> Result<Option<BasicConstraints>, Self::Error> {
            Ok(self.basic_constraints.map(|(is_ca, max_path_length)| BasicConstraints {
                is_ca,
                max_path_length,
            }))
        }
        fn name_constraints(&self) -> Result<Option<NameConstraints>, Self::Error> {
            Ok(None)
        }
        fn key_usage_present(&self) -> Result<bool, Self::Error> {
            Ok(false)
        }
        fn extended_key_usage_contains_ocsp_signing(&self) -> Result<bool, Self::Error> {
            Ok(false)
        }
        fn subject_alt_names(&self) -> Result<Option<Vec<(GeneralNameKind, Vec<u8>)>>, Self::Error> {
            Ok(None)
        }
        fn authority_key_identifier(&self) -> Result<Option<x509_validator_core::AuthorityKeyIdentifier>, Self::Error> {
            Ok(None)
        }
        fn subject_key_identifier(&self) -> Result<Option<x509_validator_core::SubjectKeyIdentifier>, Self::Error> {
            Ok(None)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakePublicKeyInfo(Vec<u8>);

    impl PublicKeyInfoView for FakePublicKeyInfo {
        fn subject_public_key_info_der(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Debug, Clone)]
    struct FakeCertificate {
        subject: FakeName,
        issuer: FakeName,
        is_v1: bool,
        extensions: FakeExtensions,
        public_key: FakePublicKeyInfo,
    }

    impl CertificateView for FakeCertificate {
        type Name = FakeName;
        type Extensions = FakeExtensions;
        type PublicKeyInfo = FakePublicKeyInfo;

        fn subject(&self) -> &Self::Name {
            &self.subject
        }
        fn issuer(&self) -> &Self::Name {
            &self.issuer
        }
        fn is_v1(&self) -> bool {
            self.is_v1
        }
        fn has_extensions(&self) -> bool {
            true
        }
        fn not_before(&self) -> Timestamp {
            0
        }
        fn not_after(&self) -> Timestamp {
            0
        }
        fn extensions(&self) -> &Self::Extensions {
            &self.extensions
        }
        fn public_key_info(&self) -> &Self::PublicKeyInfo {
            &self.public_key
        }
        fn signature_algorithm(&self) -> SignatureAlgorithmId {
            SignatureAlgorithmId::EcdsaP256Sha256
        }
        fn signature(&self) -> &[u8] {
            &[]
        }
        fn tbs_der(&self) -> &[u8] {
            &[]
        }
    }

    fn ca_cert(name: &str, issuer: &str, max_path_length: Option<u32>) -> FakeCertificate {
        FakeCertificate {
            subject: FakeName { der: name.as_bytes().to_vec() },
            issuer: FakeName { der: issuer.as_bytes().to_vec() },
            is_v1: false,
            extensions: FakeExtensions {
                basic_constraints: Some((true, max_path_length)),
            },
            public_key: FakePublicKeyInfo(format!("{name}-key").into_bytes()),
        }
    }

    fn leaf_cert(name: &str, issuer: &str) -> FakeCertificate {
        FakeCertificate {
            subject: FakeName { der: name.as_bytes().to_vec() },
            issuer: FakeName { der: issuer.as_bytes().to_vec() },
            is_v1: false,
            extensions: FakeExtensions { basic_constraints: None },
            public_key: FakePublicKeyInfo(format!("{name}-key").into_bytes()),
        }
    }

    #[test]
    fn leaf_and_ca_chain_is_accepted() {
        let chain = UnverifiedCertificateChain::new(vec![leaf_cert("leaf", "root"), ca_cert("root", "root", None)]);
        let mut policy = BasicConstraintsPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn self_signed_leaf_used_as_trust_anchor_must_be_a_ca() {
        let chain = UnverifiedCertificateChain::new(vec![ca_cert("root", "root", None)]);
        let mut policy = BasicConstraintsPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn self_signed_leaf_without_ca_bit_is_rejected() {
        let chain = UnverifiedCertificateChain::new(vec![leaf_cert("root", "root")]);
        let mut policy = BasicConstraintsPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn non_ca_intermediate_is_rejected() {
        let chain = UnverifiedCertificateChain::new(vec![
            leaf_cert("leaf", "intermediate"),
            leaf_cert("intermediate", "root"),
            ca_cert("root", "root", None),
        ]);
        let mut policy = BasicConstraintsPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn path_length_constraint_satisfied_is_accepted() {
        let chain = UnverifiedCertificateChain::new(vec![
            leaf_cert("leaf", "intermediate"),
            ca_cert("intermediate", "root", Some(1)),
            ca_cert("root", "root", None),
        ]);
        let mut policy = BasicConstraintsPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn path_length_constraint_violated_is_rejected() {
        let chain = UnverifiedCertificateChain::new(vec![
            leaf_cert("leaf", "intermediate2"),
            ca_cert("intermediate2", "intermediate1", None),
            ca_cert("intermediate1", "root", Some(0)),
            ca_cert("root", "root", None),
        ]);
        let mut policy = BasicConstraintsPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn self_issued_intermediate_does_not_count_against_path_length() {
        // "intermediate" re-issues itself (same subject/issuer DN) before
        // signing the leaf; that self-issued hop must not consume the
        // path-length budget.
        let self_issued = FakeCertificate {
            subject: FakeName { der: b"intermediate".to_vec() },
            issuer: FakeName { der: b"intermediate".to_vec() },
            is_v1: false,
            extensions: FakeExtensions {
                basic_constraints: Some((true, Some(0))),
            },
            public_key: FakePublicKeyInfo(b"intermediate-key".to_vec()),
        };
        let chain = UnverifiedCertificateChain::new(vec![
            leaf_cert("leaf", "intermediate"),
            self_issued,
            ca_cert("root", "root", None),
        ]);
        let mut policy = BasicConstraintsPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn verifying_critical_extensions_includes_basic_constraints_oid() {
        let policy = BasicConstraintsPolicy;
        let oids = <BasicConstraintsPolicy as VerifierPolicy<FakeCertificate>>::verifying_critical_extensions(&policy);
        assert!(oids.contains(&basic_constraints_oid()));
    }
}
