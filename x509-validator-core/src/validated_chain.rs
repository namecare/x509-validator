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