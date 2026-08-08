use crate::{VerifierPolicy, PolicyEvaluationResult, PolicyFailureReason};
use x509_validator_core::der_parser::Oid;
use x509_validator_core::extensions::{GeneralName, GeneralSubtree};
use x509_validator_core::oid_registry::OID_X509_EXT_NAME_CONSTRAINTS;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

/// id-ce-nameConstraints, RFC 5280 §4.2.1.10: 2.5.29.30.
fn name_constraints_oid() -> Oid<'static> {
    OID_X509_EXT_NAME_CONSTRAINTS
}

/// A sub-policy of the [`RFC5280Policy`] that polices the nameConstraints extension.
///
/// [`RFC5280Policy`]: crate::rfc5280::RFC5280Policy
pub struct NameConstraintsPolicy;

impl VerifierPolicy for NameConstraintsPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![name_constraints_oid()]
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        // The rules for name constraints come from https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10.
        //
        // Some notes:
        //
        // - RFC 5280 says we MUST validate directoryName constraints, and SHOULD validate rfc822Name, URI, dNSName, and
        //   iPAddress constraints. However, proper directoryName constraint validation requires a complex comparison
        //   algorithm. Most implementations skip that and just compare the distinguished names by exact equality. As
        //   such, we deliberately do not validate directoryName constraints at all: if a certificate's nameConstraints
        //   extension contains a directoryName subtree, we reject the chain.
        // - If there's a constraint we don't support and can't validate, we MUST reject the cert.
        //
        // Our algorithm is recursive: starting from the root and moving towards the leaf, for each CA
        // cert we apply the name constraints to all of the other certificates in the chain. The one exception
        // is for self-signed certs where, much like with basic constraints, we briefly pretend that the
        // self-signed cert issued itself and enforce its own name constraints on it.
        if chain.len() == 1 {
            return Self::validate_name_constraints(chain, chain.leaf(), &[0]);
        }

        for issuer_index in (1..chain.len()).rev() {
            let issuer = &chain[issuer_index];
            let subject_indices: Vec<usize> = (0..issuer_index).collect();
            Self::validate_name_constraints(chain, issuer, &subject_indices)?;
        }

        Ok(())
    }
}

impl NameConstraintsPolicy {
    fn validate_name_constraints(
        chain: &UnverifiedCertificateChain,
        issuer: &x509_validator_core::Certificate,
        subject_indices: &[usize],
    ) -> PolicyEvaluationResult {
        // If we couldn't decode these, fail validation.
        let constraints = issuer
            .tbs_certificate
            .name_constraints()
            .map_err(|error| PolicyFailureReason::new(format!("unable to decode name constraints from {:?}: {}", issuer, error)))?;

        let Some(constraints) = constraints else {
            // No name constraints to enforce, we're done.
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

    fn names<'a>(cert: &'a x509_validator_core::Certificate<'a>) -> Result<Vec<GeneralName<'a>>, PolicyFailureReason> {
        let mut names = vec![GeneralName::DirectoryName(cert.subject().clone())];

        let san = cert
            .tbs_certificate
            .subject_alternative_name()
            .map_err(|error| PolicyFailureReason::new(format!("unable to decode subject alternative name from {:?}: {}", cert, error)))?;

        if let Some(san) = san {
            for name in &san.value.general_names {
                if matches!(name, GeneralName::Invalid(_, _)) {
                    // The parser surfaces a name it could not decode as `Invalid` rather than
                    // failing the extension parse. Such a name can never be compared against a
                    // constraint, so treating it as just another entry would silently exempt it
                    // from every subtree check. Refuse the chain instead.
                    return Err(PolicyFailureReason::new(format!(
                        "unable to decode a subject alternative name from {:?}",
                        cert
                    )));
                }
                names.push(name.clone());
            }
        }

        Ok(names)
    }

    /// Whether a subtree's base names a form this policy cannot compare against.
    ///
    /// RFC 5280 requires rejecting a chain constrained by something we cannot evaluate, so this
    /// is decided by the constraint alone: whether the certificate happens to carry a name of the
    /// same form has no bearing on it.
    fn constraint_kind_is_unsupported(constraint: &GeneralName) -> bool {
        !matches!(
            constraint,
            GeneralName::DNSName(_) | GeneralName::IPAddress(_) | GeneralName::URI(_) | GeneralName::DirectoryName(_)
        )
    }

    fn validate_excluded_subtrees(excluded_subtrees: &[GeneralSubtree], name: &GeneralName) -> PolicyEvaluationResult {
        // For excluded trees, if _any_ match then the name is forbidden.
        for subtree in excluded_subtrees {
            let constraint = &subtree.base;

            if matches!(constraint, GeneralName::DirectoryName(_)) && matches!(name, GeneralName::DirectoryName(_)) {
                // We immediately reject the chain if there is a directoryName name constraint involved: correct
                // validation requires the full RFC 5280 comparison algorithm which we currently do not implement.
                return Err(PolicyFailureReason::new("directoryName name constraints are not supported"));
            }

            if Self::constraint_kind_is_unsupported(constraint) {
                // We don't support constraints on these!
                //
                // Of the set that's currently unsupported, we should probably support rfc822Name (a.k.a. email address).
                // For now we're omitting it, but at some point someone is going to run into this limitation and we'll want to come
                // back and fix it.
                return Err(PolicyFailureReason::new("unable to validate excluded subtree, unsupported constraint kind"));
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
                // We support this constraint's kind, but the current name isn't of that type.
                _ => continue,
            };

            if matched {
                return Err(PolicyFailureReason::new("name is in an excluded subtree"));
            }
        }

        // No policy rejected this.
        Ok(())
    }

    fn validate_permitted_subtrees(permitted_subtrees: &[GeneralSubtree], name: &GeneralName) -> PolicyEvaluationResult {
        let mut evaluated_at_least_one_constraint = false;

        for subtree in permitted_subtrees {
            let constraint = &subtree.base;

            if matches!(constraint, GeneralName::DirectoryName(_)) && matches!(name, GeneralName::DirectoryName(_)) {
                // We immediately reject the chain if there is a directoryName name constraint involved: correct
                // validation requires the full RFC 5280 comparison algorithm which we currently do not implement.
                return Err(PolicyFailureReason::new("directoryName name constraints are not supported"));
            }

            if Self::constraint_kind_is_unsupported(constraint) {
                // We don't support constraints on these!
                //
                // Of the set that's currently unsupported, we should probably support rfc822Name (a.k.a. email address).
                // For now we're omitting it, but at some point someone is going to run into this limitation and we'll want to come
                // back and fix it.
                return Err(PolicyFailureReason::new("unable to validate permitted subtree, unsupported constraint kind"));
            }

            // A match on any of these means we're good.
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
                // We support this constraint's kind, but the current name isn't of that type. This means we
                // didn't evaluate this constraint.
                _ => continue,
            };

            if matched {
                return Ok(());
            }
        }

        // Uh-oh, nothing matched! This is only a problem if we have at least one constraint for the given type.
        if !evaluated_at_least_one_constraint {
            return Ok(());
        }

        Err(PolicyFailureReason::new("unable to validate permitted subtree, no matches"))
    }
}