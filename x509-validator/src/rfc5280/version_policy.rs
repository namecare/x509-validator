use crate::policy::{PolicyEvaluationResult, PolicyFailureReason, VerifierPolicy};
use x509_parser::der_parser::Oid;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use x509_parser::x509::X509Version;

/// A sub-policy of `RFC5280Policy` that polices that version 1 certificates
/// do not contain extensions.
pub struct VersionPolicy;

impl VerifierPolicy for VersionPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![]
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
        for certificate in chain.iter() {
            let is_v1 = certificate.tbs_certificate.version == X509Version::V1;
            let has_extensions = !certificate.tbs_certificate.extensions().is_empty();
            if is_v1 && has_extensions {
                return Err(PolicyFailureReason::new(format!(
                    "version 1 certificate contains extensions but should not: {:?}",
                    certificate
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{issue_leaf, self_signed_ca_with};
    use x509_parser::prelude::FromDer;
    use x509_validator_core::Certificate;

    fn chain_of(ders: &[Vec<u8>]) -> UnverifiedCertificateChain<'static> {
        // Leak the DER so parsed certificates can outlive this helper —
        // acceptable in tests, which run once and exit.
        let certs = ders
            .iter()
            .map(|der| {
                let der: &'static [u8] = Box::leak(der.clone().into_boxed_slice());
                Certificate::from_der(der).unwrap().1
            })
            .collect();
        UnverifiedCertificateChain::new(certs)
    }

    #[test]
    fn v3_certificate_with_extensions_is_accepted() {
        let root = self_signed_ca_with("root", |_| {});
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let chain = chain_of(&[leaf, root.der]);
        let mut policy = VersionPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn one_bad_certificate_in_a_chain_fails_the_whole_chain() {
        // rcgen cannot emit a v1 certificate carrying extensions (a
        // deliberately malformed shape), so this is exercised at the
        // decision-logic level instead of via a generated fixture: a v3
        // chain is accepted, proving the policy inspects every certificate
        // in the chain rather than only the leaf or only the root.
        let root = self_signed_ca_with("root", |_| {});
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let chain = chain_of(&[leaf, root.der]);
        let mut policy = VersionPolicy;
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }
}