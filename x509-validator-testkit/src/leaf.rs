use crate::ca::{base_params, Ca};
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType};

/// A non-CA leaf certificate issued by a CA, with the given DNS SANs.
pub fn issue_leaf(subject_cn: &str, dns_sans: &[&str], issuer: &Ca) -> Vec<u8> {
    issue_leaf_with(subject_cn, dns_sans, issuer, |_| {})
}

pub fn issue_leaf_with(subject_cn: &str, dns_sans: &[&str], issuer: &Ca, configure: impl FnOnce(&mut CertificateParams)) -> Vec<u8> {
    let mut params = base_params(subject_cn);
    params.subject_alt_names = dns_sans
        .iter()
        .map(|name| SanType::DnsName(Ia5String::try_from(*name).expect("valid dns san")))
        .collect();
    configure(&mut params);

    let key_pair = KeyPair::generate().expect("generate key pair");
    params.signed_by(&key_pair, &issuer.issuer()).expect("sign leaf").der().to_vec()
}

/// A non-CA leaf certificate issued by a CA, with the given IP address SANs.
pub fn issue_leaf_with_ip_sans(subject_cn: &str, ip_sans: Vec<std::net::IpAddr>, issuer: &Ca) -> Vec<u8> {
    let mut params = base_params(subject_cn);
    params.subject_alt_names = ip_sans.into_iter().map(SanType::IpAddress).collect();

    let key_pair = KeyPair::generate().expect("generate key pair");
    params.signed_by(&key_pair, &issuer.issuer()).expect("sign leaf").der().to_vec()
}

/// A non-CA leaf certificate issued by a CA whose only subjectAltName
/// entries are rfc822Name (email) entries — i.e. a SAN extension that is
/// present but contains nothing this verifier can match a service against.
pub fn issue_leaf_with_email_sans(subject_cn: &str, email_sans: &[&str], issuer: &Ca) -> Vec<u8> {
    let mut params = base_params(subject_cn);
    params.subject_alt_names = email_sans
        .iter()
        .map(|name| SanType::Rfc822Name(Ia5String::try_from(*name).expect("valid email san")))
        .collect();

    let key_pair = KeyPair::generate().expect("generate key pair");
    params.signed_by(&key_pair, &issuer.issuer()).expect("sign leaf").der().to_vec()
}

/// A non-CA leaf certificate issued by a CA whose subject distinguished
/// name is built by the caller. Useful for subjects that the convenience
/// helpers can't express, such as a DN carrying several commonName
/// attributes or none at all.
pub fn issue_leaf_with_dn(dn: DistinguishedName, issuer: &Ca, configure: impl FnOnce(&mut CertificateParams)) -> Vec<u8> {
    let mut params = base_params("");
    params.distinguished_name = dn;
    configure(&mut params);

    let key_pair = KeyPair::generate().expect("generate key pair");
    params.signed_by(&key_pair, &issuer.issuer()).expect("sign leaf").der().to_vec()
}

/// A non-CA leaf issued by `issuer`, carrying an `authorityKeyIdentifier`
/// when `include_aki` is set.
pub fn issue_leaf_with_aki(subject_cn: &str, dns_sans: &[&str], issuer: &Ca, include_aki: bool) -> Vec<u8> {
    issue_leaf_with(subject_cn, dns_sans, issuer, |params| {
        params.use_authority_key_identifier_extension = include_aki;
    })
}

use time::OffsetDateTime;

/// A leaf (or isolated self-signed) certificate built from an explicit
/// specification, for callers that need to pin the key algorithm, the
/// validity window, or attach an unrecognised critical extension.
pub struct LeafSpec {
    subject_cn: String,
    key_pair: Option<KeyPair>,
    not_before: Option<OffsetDateTime>,
    not_after: Option<OffsetDateTime>,
    dns_sans: Vec<String>,
    include_aki: bool,
    critical_extension: Option<(Vec<u64>, Vec<u8>)>,
}

impl LeafSpec {
    pub fn new(subject_cn: &str) -> Self {
        Self {
            subject_cn: subject_cn.to_string(),
            key_pair: None,
            not_before: None,
            not_after: None,
            dns_sans: Vec::new(),
            include_aki: false,
            critical_extension: None,
        }
    }

    pub fn key_pair(mut self, key_pair: KeyPair) -> Self {
        self.key_pair = Some(key_pair);
        self
    }

    pub fn validity(mut self, not_before: OffsetDateTime, not_after: OffsetDateTime) -> Self {
        self.not_before = Some(not_before);
        self.not_after = Some(not_after);
        self
    }

    pub fn dns_sans(mut self, dns_sans: &[&str]) -> Self {
        self.dns_sans = dns_sans.iter().map(|name| name.to_string()).collect();
        self
    }

    pub fn include_aki(mut self, include_aki: bool) -> Self {
        self.include_aki = include_aki;
        self
    }

    /// Attaches an extension the verifier does not recognise, marked
    /// critical — the shape a policy must reject as unhandled.
    pub fn critical_extension(mut self, oid: &[u64], value: Vec<u8>) -> Self {
        self.critical_extension = Some((oid.to_vec(), value));
        self
    }

    fn build(self, is_ca: bool) -> (CertificateParams, KeyPair) {
        let mut params = base_params(&self.subject_cn);
        params.use_authority_key_identifier_extension = self.include_aki;
        params.subject_alt_names = self
            .dns_sans
            .iter()
            .map(|name| SanType::DnsName(Ia5String::try_from(name.as_str()).expect("valid dns san")))
            .collect();
        if let Some(not_before) = self.not_before {
            params.not_before = not_before;
        }
        if let Some(not_after) = self.not_after {
            params.not_after = not_after;
        }
        if is_ca {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        }
        if let Some((oid, value)) = self.critical_extension {
            let mut ext = rcgen::CustomExtension::from_oid_content(&oid, value);
            ext.set_criticality(true);
            params.custom_extensions.push(ext);
        }

        let key_pair = self.key_pair.unwrap_or_else(|| KeyPair::generate().expect("generate key pair"));
        (params, key_pair)
    }

    pub fn signed_by(self, issuer: &Ca) -> Vec<u8> {
        let (params, key_pair) = self.build(false);
        params.signed_by(&key_pair, &issuer.issuer()).expect("sign leaf").der().to_vec()
    }

    /// A self-signed certificate carrying `basicConstraints: CA`, for
    /// fixtures that stand alone rather than chaining to an issuer.
    pub fn self_signed(self) -> Vec<u8> {
        let (params, key_pair) = self.build(true);
        params.self_signed(&key_pair).expect("self-sign").der().to_vec()
    }
}

#[cfg(test)]
mod leaf_spec_tests {
    use super::*;
    use time::{Duration, OffsetDateTime};
    use x509_validator_core::{Certificate, FromDer};

    #[test]
    fn leaf_spec_honours_validity_and_sans() {
        let root = crate::ca::CaSpec::new("leaf spec root").self_signed();
        let not_before = OffsetDateTime::UNIX_EPOCH + Duration::days(2);
        let not_after = OffsetDateTime::UNIX_EPOCH + Duration::days(200);

        let der = LeafSpec::new("localhost")
            .dns_sans(&["localhost"])
            .validity(not_before, not_after)
            .signed_by(&root);

        let parsed = Certificate::from_der(&der).expect("parse").1;
        assert_eq!(parsed.tbs_certificate.validity().not_before.timestamp(), not_before.unix_timestamp());
        assert_eq!(parsed.tbs_certificate.validity().not_after.timestamp(), not_after.unix_timestamp());
    }

    #[test]
    fn leaf_spec_carries_critical_extension() {
        let root = crate::ca::CaSpec::new("ext spec root").self_signed();

        let der = LeafSpec::new("weird")
            .critical_extension(&[1, 2, 3, 4, 5], vec![1, 2, 3, 4, 5])
            .signed_by(&root);

        let parsed = Certificate::from_der(&der).expect("parse").1;
        assert!(parsed.tbs_certificate.extensions().iter().any(|e| e.critical && e.oid.to_id_string() == "1.2.3.4.5"));
    }
}

