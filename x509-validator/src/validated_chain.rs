use crate::Certificate;

/// A certificate chain that has passed policy evaluation, leaf-first.
#[derive(Debug, Clone)]
pub struct ValidatedCertificateChain<'a> {
    certificates: Vec<Certificate<'a>>, // leaf-first
}

impl<'a> ValidatedCertificateChain<'a> {
    pub fn new_unchecked(certificates: Vec<Certificate<'a>>) -> Self {
        assert!(!certificates.is_empty());
        Self { certificates }
    }

    pub fn leaf(&self) -> &Certificate<'a> {
        &self.certificates[0]
    }
    pub fn root(&self) -> &Certificate<'a> {
        self.certificates.last().unwrap()
    }
    
    pub fn iter(&self) -> impl Iterator<Item = &Certificate<'a>> {
        self.certificates.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CertificateExt;
    use x509_validator_testkit::{cert, issue_ca, issue_leaf, self_signed_ca_with};

    /// A three-certificate chain, leaf-first: leaf, intermediate, root.
    fn leaf_intermediate_root() -> Vec<Certificate<'static>> {
        let root = self_signed_ca_with("Root", |_| {});
        let intermediate = issue_ca("Intermediate", &root, None, |_| {});
        let leaf = issue_leaf("leaf.example.com", &["leaf.example.com"], &intermediate);

<<<<<<< Updated upstream
        vec![cert(leaf), cert(intermediate.der.clone()), cert(root.der.clone())]
=======
        vec![cert(leaf), cert(intermediate.der), cert(root.der)]
>>>>>>> Stashed changes
    }

    #[test]
    fn leaf_and_root_are_the_two_ends_of_the_chain() {
        let chain = ValidatedCertificateChain::new_unchecked(leaf_intermediate_root());

        assert_eq!(chain.leaf().subject().to_string(), "CN=leaf.example.com");
        assert_eq!(chain.root().subject().to_string(), "CN=Root");
    }

    #[test]
    fn root_is_the_self_signed_end_not_the_leaf() {
        let chain = ValidatedCertificateChain::new_unchecked(leaf_intermediate_root());

        let root = chain.root();
        assert_eq!(root.subject_key(), root.issuer_key());
        assert_ne!(chain.leaf().subject_key(), chain.leaf().issuer_key());
    }

    #[test]
    fn iter_yields_the_chain_leaf_first() {
        let chain = ValidatedCertificateChain::new_unchecked(leaf_intermediate_root());

        let subjects: Vec<_> = chain.iter().map(|c| c.subject().to_string()).collect();

        assert_eq!(subjects, ["CN=leaf.example.com", "CN=Intermediate", "CN=Root"]);
    }

    #[test]
    fn a_single_certificate_is_both_leaf_and_root() {
<<<<<<< Updated upstream
        let root = cert(self_signed_ca_with("Root", |_| {}).der.clone());
=======
        let root = cert(self_signed_ca_with("Root", |_| {}).der);
>>>>>>> Stashed changes
        let chain = ValidatedCertificateChain::new_unchecked(vec![root]);

        assert_eq!(chain.leaf().subject().to_string(), "CN=Root");
        assert_eq!(chain.root().subject().to_string(), "CN=Root");
        assert!(chain.leaf().has_same_identity_as(chain.root()));
    }

    #[test]
    fn new_unchecked_performs_no_validation() {
        // Two unrelated self-signed certificates: nothing issues anything
        // else. The constructor is named `_unchecked` because it accepts
        // this — policy evaluation is the caller's job.
<<<<<<< Updated upstream
        let a = cert(self_signed_ca_with("A", |_| {}).der.clone());
        let b = cert(self_signed_ca_with("B", |_| {}).der.clone());
=======
        let a = cert(self_signed_ca_with("A", |_| {}).der);
        let b = cert(self_signed_ca_with("B", |_| {}).der);
>>>>>>> Stashed changes

        let chain = ValidatedCertificateChain::new_unchecked(vec![a, b]);

        assert_ne!(chain.leaf().issuer_key(), chain.root().subject_key());
    }

    #[test]
    #[should_panic]
    fn constructing_an_empty_chain_panics() {
        ValidatedCertificateChain::new_unchecked(Vec::new());
    }
}