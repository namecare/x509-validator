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

impl<'a> std::ops::Index<usize> for UnverifiedCertificateChain<'a> {
    type Output = Certificate<'a>;
    fn index(&self, i: usize) -> &Certificate<'a> {
        &self.certificates[i]
    }
}