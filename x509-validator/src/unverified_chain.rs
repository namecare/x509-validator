use crate::Certificate;

/// Leaf-first ordered chain, not yet accepted by policy.
#[derive(Debug, Clone)]
pub struct UnverifiedCertificateChain<'a> {
    certificates: Vec<Certificate<'a>>,
}

impl<'a> UnverifiedCertificateChain<'a> {
    pub fn new(certificates: Vec<Certificate<'a>>) -> Self {
        assert!(!certificates.is_empty(), "chain must be non-empty");
        Self { certificates }
    }

    pub fn leaf(&self) -> &Certificate<'a> {
        &self.certificates[0]
    }

    pub fn iter(&self) -> impl Iterator<Item = &Certificate<'a>> {
        self.certificates.iter()
    }

    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    pub fn is_empty(&self) -> bool {
        false // invariant: always non-empty, per constructor assert
    }
}

impl<'a> core::ops::Index<usize> for UnverifiedCertificateChain<'a> {
    type Output = Certificate<'a>;
    fn index(&self, i: usize) -> &Certificate<'a> {
        &self.certificates[i]
    }
}

#[cfg(test)]
mod tests {
    use x509_validator_testkit::{cert, issue_ca, issue_leaf, self_signed_ca_with};

    use super::*;
    use crate::CertificateExt;

    /// A three-certificate chain, leaf-first: leaf, intermediate, root.
    fn leaf_intermediate_root() -> Vec<Certificate<'static>> {
        let root = self_signed_ca_with("Root", |_| {});
        let intermediate = issue_ca("Intermediate", &root, None, |_| {});
        let leaf = issue_leaf("leaf.example.com", &["leaf.example.com"], &intermediate);

        vec![cert(leaf), cert(intermediate.der), cert(root.der)]
    }

    #[test]
    fn leaf_is_the_first_certificate() {
        let chain = UnverifiedCertificateChain::new(leaf_intermediate_root());

        assert_eq!(chain.leaf().subject().to_string(), "CN=leaf.example.com");
    }

    #[test]
    fn indexing_walks_from_leaf_to_root() {
        let chain = UnverifiedCertificateChain::new(leaf_intermediate_root());

        assert_eq!(chain[0].subject().to_string(), "CN=leaf.example.com");
        assert_eq!(chain[1].subject().to_string(), "CN=Intermediate");
        assert_eq!(chain[2].subject().to_string(), "CN=Root");
    }

    #[test]
    fn each_certificate_is_issued_by_its_successor() {
        let chain = UnverifiedCertificateChain::new(leaf_intermediate_root());

        for i in 0..chain.len() - 1 {
            assert_eq!(chain[i].issuer_key(), chain[i + 1].subject_key());
        }
    }

    #[test]
    fn iter_yields_every_certificate_in_index_order() {
        let chain = UnverifiedCertificateChain::new(leaf_intermediate_root());

        let subjects: Vec<_> = chain
            .iter()
            .map(|c| c.subject().to_string())
            .collect();

        assert_eq!(
            subjects,
            ["CN=leaf.example.com", "CN=Intermediate", "CN=Root"]
        );
        assert_eq!(subjects.len(), chain.len());
    }

    #[test]
    fn a_chain_is_never_empty() {
        let chain =
            UnverifiedCertificateChain::new(vec![cert(self_signed_ca_with("Root", |_| {}).der)]);

        assert_eq!(chain.len(), 1);
        assert!(!chain.is_empty());
        assert_eq!(chain.leaf().subject().to_string(), "CN=Root");
    }

    #[test]
    #[should_panic(expected = "chain must be non-empty")]
    fn constructing_an_empty_chain_panics() {
        UnverifiedCertificateChain::new(Vec::new());
    }

    #[test]
    #[should_panic]
    fn indexing_past_the_end_panics() {
        let chain = UnverifiedCertificateChain::new(leaf_intermediate_root());

        let _ = &chain[3];
    }
}
