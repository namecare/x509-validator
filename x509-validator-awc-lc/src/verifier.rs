use crate::view::AwsLcCertificate;

/// `x509_validator::BaseVerifier` with its certificate type parameter bound
/// to the aws-lc-backed `AwsLcCertificate`, so callers of this backend don't
/// need to name the certificate type themselves.
pub type Verifier<'a, P> = x509_validator::BaseVerifier<'a, AwsLcCertificate, P>;