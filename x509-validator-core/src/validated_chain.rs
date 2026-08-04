use crate::view::CertificateView;

/// A certificate chain that has passed policy evaluation, leaf-first.
#[derive(Debug, Clone)]
pub struct ValidatedCertificateChain<C: CertificateView> {
    certificates: Vec<C>, // leaf-first
}

impl<C: CertificateView> ValidatedCertificateChain<C> {
    /// Caller-asserted: the caller is certifying this chain was actually
    /// validated through some external process, not necessarily this
    /// crate's `Verifier`.
    pub fn new_unchecked(certificates: Vec<C>) -> Self {
        assert!(!certificates.is_empty());
        Self { certificates }
    }

    pub fn leaf(&self) -> &C {
        &self.certificates[0]
    }
    pub fn root(&self) -> &C {
        self.certificates.last().unwrap()
    }
    pub fn iter(&self) -> impl Iterator<Item = &C> {
        self.certificates.iter()
    }
}