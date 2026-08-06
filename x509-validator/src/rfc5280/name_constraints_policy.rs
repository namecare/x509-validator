use crate::{VerifierPolicy, PolicyEvaluationResult, PolicyFailureReason};
use x509_parser::der_parser::Oid;
use x509_parser::extensions::{GeneralName, GeneralSubtree};
use x509_parser::oid_registry::OID_X509_EXT_NAME_CONSTRAINTS;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

/// id-ce-nameConstraints, RFC 5280 §4.2.1.10: 2.5.29.30.
fn name_constraints_oid() -> Oid<'static> {
    OID_X509_EXT_NAME_CONSTRAINTS
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

impl VerifierPolicy for NameConstraintsPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![name_constraints_oid()]
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
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
    fn validate_name_constraints(
        chain: &UnverifiedCertificateChain,
        issuer: &x509_validator_core::Certificate,
        subject_indices: &[usize],
    ) -> PolicyEvaluationResult {
        let constraints = issuer
            .tbs_certificate
            .name_constraints()
            .map_err(|error| PolicyFailureReason::new(format!("unable to decode name constraints from {:?}: {}", issuer, error)))?;

        let Some(constraints) = constraints else {
            return Ok(());
        };
        let constraints = &constraints.value;

        for &i in subject_indices {
            let cert = &chain[i];

            for name in Self::names(cert)? {
                if let Some(permitted) = &constraints.permitted_subtrees {
                    Self::validate_permitted_subtrees(permitted, &name)?;
                }
                if let Some(excluded) = &constraints.excluded_subtrees {
                    Self::validate_excluded_subtrees(excluded, &name)?;
                }
            }
        }

        Ok(())
    }

    /// The unified name sequence a certificate presents for constraint
    /// checking: the subject distinguished name (as a directoryName), then
    /// every subjectAltName entry.
    ///
    /// A subjectAltName that cannot be decoded is an error, not an empty
    /// list of names: if the names a certificate presents can't be
    /// enumerated, no constraint can be shown to hold over them, so the
    /// only safe answer is to refuse the chain. Treating a decode failure
    /// as "no names" would let a malformed extension silently suppress
    /// every name constraint that should have applied.
    fn names<'a>(cert: &'a x509_validator_core::Certificate<'a>) -> Result<Vec<GeneralName<'a>>, PolicyFailureReason> {
        let mut names = vec![GeneralName::DirectoryName(cert.subject().clone())];

        let san = cert
            .tbs_certificate
            .subject_alternative_name()
            .map_err(|error| PolicyFailureReason::new(format!("unable to decode subject alternative name from {:?}: {}", cert, error)))?;

        if let Some(san) = san {
            names.extend(san.value.general_names.iter().cloned());
        }

        Ok(names)
    }

    fn validate_excluded_subtrees(excluded_subtrees: &[GeneralSubtree], name: &GeneralName) -> PolicyEvaluationResult {
        for subtree in excluded_subtrees {
            let constraint = &subtree.base;

            if matches!(constraint, GeneralName::DirectoryName(_)) && matches!(name, GeneralName::DirectoryName(_)) {
                return Err(PolicyFailureReason::new("directoryName name constraints are not supported"));
            }

            let matched = match (name, constraint) {
                (GeneralName::DNSName(name_value), GeneralName::DNSName(constraint_value)) => {
                    Self::dns_name_matches_constraint(name_value.as_bytes(), constraint_value.as_bytes())
                }
                (GeneralName::IPAddress(name_value), GeneralName::IPAddress(constraint_value)) => {
                    Self::ip_address_matches_constraint(name_value, constraint_value)
                }
                (GeneralName::URI(name_value), GeneralName::URI(constraint_value)) => {
                    Self::uri_name_matches_constraint(name_value.as_bytes(), constraint_value.as_bytes())
                }
                (GeneralName::DirectoryName(_), GeneralName::DirectoryName(_)) => unreachable!("handled above"),
                (n, c) if std::mem::discriminant(n) == std::mem::discriminant(c) => {
                    return Err(PolicyFailureReason::new("unable to validate excluded subtree, unsupported constraint kind"));
                }
                _ => continue,
            };

            if matched {
                return Err(PolicyFailureReason::new("name is in an excluded subtree"));
            }
        }

        Ok(())
    }

    fn validate_permitted_subtrees(permitted_subtrees: &[GeneralSubtree], name: &GeneralName) -> PolicyEvaluationResult {
        let mut evaluated_at_least_one_constraint = false;

        for subtree in permitted_subtrees {
            let constraint = &subtree.base;

            if matches!(constraint, GeneralName::DirectoryName(_)) && matches!(name, GeneralName::DirectoryName(_)) {
                return Err(PolicyFailureReason::new("directoryName name constraints are not supported"));
            }

            let matched = match (name, constraint) {
                (GeneralName::DNSName(name_value), GeneralName::DNSName(constraint_value)) => {
                    evaluated_at_least_one_constraint = true;
                    Self::dns_name_matches_constraint(name_value.as_bytes(), constraint_value.as_bytes())
                }
                (GeneralName::IPAddress(name_value), GeneralName::IPAddress(constraint_value)) => {
                    evaluated_at_least_one_constraint = true;
                    Self::ip_address_matches_constraint(name_value, constraint_value)
                }
                (GeneralName::URI(name_value), GeneralName::URI(constraint_value)) => {
                    evaluated_at_least_one_constraint = true;
                    Self::uri_name_matches_constraint(name_value.as_bytes(), constraint_value.as_bytes())
                }
                (GeneralName::DirectoryName(_), GeneralName::DirectoryName(_)) => unreachable!("handled above"),
                (n, c) if std::mem::discriminant(n) == std::mem::discriminant(c) => {
                    return Err(PolicyFailureReason::new("unable to validate permitted subtree, unsupported constraint kind"));
                }
                _ => continue,
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
    use crate::test_support::{dns_subtree, issue_leaf, name_constraints, self_signed_ca_with};
    use rcgen::CertificateParams;
    use x509_parser::prelude::FromDer;
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
    fn chain_without_name_constraints_is_accepted() {
        let root = self_signed_ca_with("root", |_| {});
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let chain = chain_of(vec![leaf, root.der]);
        let mut policy = NameConstraintsPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn leaf_name_in_permitted_subtree_is_accepted() {
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
        });
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let chain = chain_of(vec![leaf, root.der]);
        let mut policy = NameConstraintsPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn leaf_name_outside_permitted_subtree_is_rejected() {
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
        });
        let leaf = issue_leaf("leaf", &["www.evil.com"], &root);
        let chain = chain_of(vec![leaf, root.der]);
        let mut policy = NameConstraintsPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn leaf_name_in_excluded_subtree_is_rejected() {
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.name_constraints = Some(name_constraints(vec![], vec![dns_subtree("example.com")]));
        });
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let chain = chain_of(vec![leaf, root.der]);
        let mut policy = NameConstraintsPolicy;
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("name is in an excluded subtree")
        );
    }

    #[test]
    fn constraints_apply_transitively_through_intermediate() {
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
        });
        let intermediate = crate::test_support::issue_ca("intermediate", &root, None, |_| {});
        let leaf = issue_leaf("leaf", &["www.evil.com"], &intermediate);
        let chain = chain_of(vec![leaf, intermediate.der, root.der]);
        let mut policy = NameConstraintsPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn self_signed_single_certificate_enforces_its_own_constraints() {
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.subject_alt_names = vec![rcgen::SanType::DnsName("www.evil.com".try_into().unwrap())];
            params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
        });
        let chain = chain_of(vec![root.der]);
        let mut policy = NameConstraintsPolicy;
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn directory_name_constraint_is_rejected_outright() {
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, "example");
            params.name_constraints = Some(name_constraints(vec![rcgen::GeneralSubtree::DirectoryName(dn)], vec![]));
        });
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let chain = chain_of(vec![leaf, root.der]);
        let mut policy = NameConstraintsPolicy;
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("directoryName name constraints are not supported")
        );
    }

    #[test]
    fn verifying_critical_extensions_includes_name_constraints_oid() {
        let policy = NameConstraintsPolicy;
        let oids = policy.verifying_critical_extensions();
        assert!(oids.contains(&name_constraints_oid()));
    }
}