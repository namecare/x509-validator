use crate::view::CertificateView;

/// Leaf-first ordered chain, not yet accepted by policy.
#[derive(Debug, Clone)]
pub struct UnverifiedCertificateChain<C: CertificateView> {
    certificates: Vec<C>,
}

impl<C: CertificateView> UnverifiedCertificateChain<C> {
    pub fn new(certificates: Vec<C>) -> Self {
        assert!(!certificates.is_empty(), "chain must be non-empty");
        Self { certificates }
    }

    pub fn leaf(&self) -> &C {
        &self.certificates[0]
    }

    pub fn iter(&self) -> impl Iterator<Item = &C> {
        self.certificates.iter()
    }

    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    pub fn is_empty(&self) -> bool {
        false // invariant: always non-empty, per constructor assert
    }
}

impl<C: CertificateView> std::ops::Index<usize> for UnverifiedCertificateChain<C> {
    type Output = C;
    fn index(&self, i: usize) -> &C {
        &self.certificates[i]
    }
}