use x509_parser::certificate::X509Certificate;

/// A certificate chain that has passed policy evaluation, leaf-first.
#[derive(Debug, Clone)]
pub struct ValidatedCertificateChain<'a> {
    certificates: Vec<X509Certificate<'a>>, // leaf-first
}

impl<'a> ValidatedCertificateChain<'a> {
    /// Caller-asserted: the caller is certifying this chain was actually
    /// validated through some external process, not necessarily this
    /// crate's `Verifier`.
    pub fn new_unchecked(certificates: Vec<X509Certificate<'a>>) -> Self {
        assert!(!certificates.is_empty());
        Self { certificates }
    }

    pub fn leaf(&self) -> &X509Certificate<'a> {
        &self.certificates[0]
    }
    pub fn root(&self) -> &X509Certificate<'a> {
        self.certificates.last().unwrap()
    }
    pub fn iter(&self) -> impl Iterator<Item = &X509Certificate<'a>> {
        self.certificates.iter()
    }
}