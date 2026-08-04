use x509_validator_core::{CertificateView, ExtensionsView, GeneralNameKind, NameView, Oid};
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use crate::{VerifierPolicy, PolicyEvaluationResult, PolicyFailureReason};

/// id-ce-nameConstraints, RFC 5280 §4.2.1.10: 2.5.29.30.
fn name_constraints_oid() -> Oid {
    Oid(vec![0x55, 0x1D, 0x1E])
}

/// A sub-policy of `RFC5280Policy` that polices the nameConstraints
/// extension.
///
/// The rules come from RFC 5280 §4.2.1.10. Notes:
///
/// - RFC 5280 says directoryName constraints MUST be validated, and
///   rfc822Name/URI/dNSName/iPAddress constraints SHOULD be validated.
///   Correct directoryName constraint validation requires the full RFC 5280
///   name-comparison algorithm, which this crate does not implement — so
///   any nameConstraints extension carrying a directoryName subtree is
///   rejected outright rather than partially enforced.
/// - Any constraint kind this crate doesn't understand is also rejected
///   outright, rather than silently ignored.
///
/// The walk is recursive: starting from the root and moving toward the
/// leaf, each CA certificate's constraints are applied to every certificate
/// that follows it in the chain. The one exception is a lone self-signed
/// certificate, which briefly acts as its own issuer so its own
/// constraints are enforced against itself.
pub struct NameConstraintsPolicy;

impl<C: CertificateView> VerifierPolicy<C> for NameConstraintsPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid> {
        vec![name_constraints_oid()]
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain<C>) -> PolicyEvaluationResult {
        if chain.len() == 1 {
            // A lone self-signed certificate briefly acts as its own
            // issuer, so its own constraints are enforced against itself.
            return Self::validate_name_constraints(chain, chain.leaf(), &[0]);
        }

        // Walk issuers from the root (last in leaf-first ordering) back
        // toward, but not including, the leaf; for each issuer, validate
        // every certificate that precedes it (i.e. every certificate it
        // issued, directly or transitively).
        for issuer_index in (1..chain.len()).rev() {
            let issuer = &chain[issuer_index];
            let subject_indices: Vec<usize> = (0..issuer_index).collect();
            Self::validate_name_constraints(chain, issuer, &subject_indices)?;
        }

        Ok(())
    }
}

impl NameConstraintsPolicy {
    /// Applies `issuer`'s nameConstraints (if any) to every certificate in
    /// `chain` at each of `subject_indices` — i.e. every certificate
    /// `issuer` issued, directly or transitively, in leaf-first ordering
    /// (or, in the single-certificate case, the certificate itself).
    fn validate_name_constraints<C: CertificateView>(
        chain: &UnverifiedCertificateChain<C>,
        issuer: &C,
        subject_indices: &[usize],
    ) -> PolicyEvaluationResult {
        let constraints = issuer
            .extensions()
            .name_constraints()
            .map_err(|error| PolicyFailureReason::new(format!("unable to decode name constraints from {:?}: {}", issuer, error)))?;

        let Some(constraints) = constraints else {
            return Ok(());
        };

        for &i in subject_indices {
            let cert = &chain[i];

            for name in Self::names(cert) {
                Self::validate_permitted_subtrees(&constraints.permitted_subtrees, &name)?;
                Self::validate_excluded_subtrees(&constraints.excluded_subtrees, &name)?;
            }
        }

        Ok(())
    }

    /// The unified name sequence a certificate presents for constraint
    /// checking: the subject distinguished name (as a directoryName), then
    /// every subjectAltName entry.
    fn names<C: CertificateView>(cert: &C) -> Vec<(GeneralNameKind, Vec<u8>)> {
        cert.subject().general_names()
    }

    fn validate_excluded_subtrees(
        excluded_subtrees: &[(GeneralNameKind, Vec<u8>)],
        name: &(GeneralNameKind, Vec<u8>),
    ) -> PolicyEvaluationResult {
        let (name_kind, name_value) = name;

        for (constraint_kind, constraint_value) in excluded_subtrees {
            if *constraint_kind == GeneralNameKind::DirectoryName && *name_kind == GeneralNameKind::DirectoryName {
                return Err(PolicyFailureReason::new("directoryName name constraints are not supported"));
            }

            if constraint_kind != name_kind {
                continue;
            }

            let matched = match constraint_kind {
                GeneralNameKind::DnsName => Self::dns_name_matches_constraint(name_value, constraint_value),
                GeneralNameKind::IpAddress => Self::ip_address_matches_constraint(name_value, constraint_value),
                GeneralNameKind::UniformResourceIdentifier => Self::uri_name_matches_constraint(name_value, constraint_value),
                GeneralNameKind::DirectoryName => unreachable!("handled above"),
                GeneralNameKind::Other => {
                    return Err(PolicyFailureReason::new("unable to validate excluded subtree, unsupported constraint kind"));
                }
            };

            if matched {
                return Err(PolicyFailureReason::new("name is in an excluded subtree"));
            }
        }

        Ok(())
    }

    fn validate_permitted_subtrees(
        permitted_subtrees: &[(GeneralNameKind, Vec<u8>)],
        name: &(GeneralNameKind, Vec<u8>),
    ) -> PolicyEvaluationResult {
        let (name_kind, name_value) = name;
        let mut evaluated_at_least_one_constraint = false;

        for (constraint_kind, constraint_value) in permitted_subtrees {
            if *constraint_kind == GeneralNameKind::DirectoryName && *name_kind == GeneralNameKind::DirectoryName {
                return Err(PolicyFailureReason::new("directoryName name constraints are not supported"));
            }

            if constraint_kind != name_kind {
                continue;
            }

            let matched = match constraint_kind {
                GeneralNameKind::DnsName => {
                    evaluated_at_least_one_constraint = true;
                    Self::dns_name_matches_constraint(name_value, constraint_value)
                }
                GeneralNameKind::IpAddress => {
                    evaluated_at_least_one_constraint = true;
                    Self::ip_address_matches_constraint(name_value, constraint_value)
                }
                GeneralNameKind::UniformResourceIdentifier => {
                    evaluated_at_least_one_constraint = true;
                    Self::uri_name_matches_constraint(name_value, constraint_value)
                }
                GeneralNameKind::DirectoryName => unreachable!("handled above"),
                GeneralNameKind::Other => {
                    return Err(PolicyFailureReason::new("unable to validate permitted subtree, unsupported constraint kind"));
                }
            };

            if matched {
                return Ok(());
            }
        }

        if !evaluated_at_least_one_constraint {
            return Ok(());
        }

        Err(PolicyFailureReason::new("unable to validate permitted subtree, no matches"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_validator_core::{
        AuthorityKeyIdentifier, BasicConstraints, NameConstraints, PublicKeyInfoView, SignatureAlgorithmId, SubjectKeyIdentifier, Timestamp,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeName {
        der: Vec<u8>,
        names: Vec<(GeneralNameKind, Vec<u8>)>,
    }

    impl NameView for FakeName {
        fn general_names(&self) -> Vec<(GeneralNameKind, Vec<u8>)> {
            self.names.clone()
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
        name_constraints: Option<(Vec<(GeneralNameKind, Vec<u8>)>, Vec<(GeneralNameKind, Vec<u8>)>)>,
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
            Ok(None)
        }
        fn name_constraints(&self) -> Result<Option<NameConstraints>, Self::Error> {
            Ok(self.name_constraints.clone().map(|(permitted, excluded)| NameConstraints {
                permitted_subtrees: permitted,
                excluded_subtrees: excluded,
            }))
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
        fn authority_key_identifier(&self) -> Result<Option<AuthorityKeyIdentifier>, Self::Error> {
            Ok(None)
        }
        fn subject_key_identifier(&self) -> Result<Option<SubjectKeyIdentifier>, Self::Error> {
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
            false
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

    fn dns(name: &str) -> (GeneralNameKind, Vec<u8>) {
        (GeneralNameKind::DnsName, name.as_bytes().to_vec())
    }

    fn cert(name: &str, issuer: &str, names: Vec<(GeneralNameKind, Vec<u8>)>, constraints: Option<(Vec<(GeneralNameKind, Vec<u8>)>, Vec<(GeneralNameKind, Vec<u8>)>)>) -> FakeCertificate {
        FakeCertificate {
            subject: FakeName {
                der: name.as_bytes().to_vec(),
                names,
            },
            issuer: FakeName {
                der: issuer.as_bytes().to_vec(),
                names: vec![],
            },
            extensions: FakeExtensions { name_constraints: constraints },
            public_key: FakePublicKeyInfo(format!("{name}-key").into_bytes()),
        }
    }

    #[test]
    fn chain_without_name_constraints_is_accepted() {
        let leaf = cert("leaf", "root", vec![dns("www.example.com")], None);
        let root = cert("root", "root", vec![], None);
        let chain = UnverifiedCertificateChain::new(vec![leaf, root]);
        let mut policy = NameConstraintsPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn leaf_name_in_permitted_subtree_is_accepted() {
        let leaf = cert("leaf", "root", vec![dns("www.example.com")], None);
        let root = cert("root", "root", vec![], Some((vec![dns("example.com")], vec![])));
        let chain = UnverifiedCertificateChain::new(vec![leaf, root]);
        let mut policy = NameConstraintsPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn leaf_name_outside_permitted_subtree_is_rejected() {
        let leaf = cert("leaf", "root", vec![dns("www.evil.com")], None);
        let root = cert("root", "root", vec![], Some((vec![dns("example.com")], vec![])));
        let chain = UnverifiedCertificateChain::new(vec![leaf, root]);
        let mut policy = NameConstraintsPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn leaf_name_in_excluded_subtree_is_rejected() {
        let leaf = cert("leaf", "root", vec![dns("www.example.com")], None);
        let root = cert("root", "root", vec![], Some((vec![], vec![dns("example.com")])));
        let chain = UnverifiedCertificateChain::new(vec![leaf, root]);
        let mut policy = NameConstraintsPolicy;
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("name is in an excluded subtree")
        );
    }

    #[test]
    fn constraints_apply_transitively_through_intermediate() {
        let leaf = cert("leaf", "intermediate", vec![dns("www.evil.com")], None);
        let intermediate = cert("intermediate", "root", vec![], None);
        let root = cert("root", "root", vec![], Some((vec![dns("example.com")], vec![])));
        let chain = UnverifiedCertificateChain::new(vec![leaf, intermediate, root]);
        let mut policy = NameConstraintsPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn self_signed_single_certificate_enforces_its_own_constraints() {
        let root = cert("root", "root", vec![dns("www.evil.com")], Some((vec![dns("example.com")], vec![])));
        let chain = UnverifiedCertificateChain::new(vec![root]);
        let mut policy = NameConstraintsPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn directory_name_constraint_is_rejected_outright() {
        let leaf = cert(
            "leaf",
            "root",
            vec![(GeneralNameKind::DirectoryName, b"leaf".to_vec())],
            None,
        );
        let root = cert(
            "root",
            "root",
            vec![],
            Some((vec![(GeneralNameKind::DirectoryName, b"CN=example".to_vec())], vec![])),
        );
        let chain = UnverifiedCertificateChain::new(vec![leaf, root]);
        let mut policy = NameConstraintsPolicy;
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("directoryName name constraints are not supported")
        );
    }

    #[test]
    fn verifying_critical_extensions_includes_name_constraints_oid() {
        let policy = NameConstraintsPolicy;
        let oids = <NameConstraintsPolicy as VerifierPolicy<FakeCertificate>>::verifying_critical_extensions(&policy);
        assert!(oids.contains(&name_constraints_oid()));
    }
}
