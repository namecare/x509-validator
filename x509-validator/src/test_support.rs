//! Helpers for building real DER-encoded certificates in tests.
//!
//! `x509_validator_core::Certificate` (`x509_parser::certificate::X509Certificate`)
//! borrows from the DER bytes it was parsed from and has no public
//! constructor, so tests can't hand-build fake instances — every test
//! exercises a certificate produced by `rcgen` and re-parsed via
//! `Certificate::from_der`.
#![cfg(test)]

use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, GeneralSubtree, IsCa, Issuer, KeyPair,
    NameConstraints, SanType,
};
use time::{Duration, OffsetDateTime};

/// A CA (or self-signed root) produced for use as an issuer in further
/// `issue_ca`/`issue_leaf` calls. Keeps the params and key pair alongside
/// the DER, since rcgen needs both to sign further certificates.
pub struct Ca {
    pub der: Vec<u8>,
    params: CertificateParams,
    key_pair: KeyPair,
}

impl Ca {
    fn issuer(&self) -> Issuer<'_, &KeyPair> {
        Issuer::from_params(&self.params, &self.key_pair)
    }
}

fn base_params(subject_cn: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, subject_cn);
    params.distinguished_name = dn;
    params.not_before = OffsetDateTime::UNIX_EPOCH + Duration::seconds(1000);
    params.not_after = OffsetDateTime::UNIX_EPOCH + Duration::seconds(2000);
    params
}

/// A self-signed CA certificate (unconstrained path length).
pub fn self_signed_ca(subject_cn: &str) -> Vec<u8> {
    self_signed_ca_with(subject_cn, |_| {}).der
}

pub fn self_signed_ca_with(subject_cn: &str, configure: impl FnOnce(&mut CertificateParams)) -> Ca {
    let mut params = base_params(subject_cn);
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    configure(&mut params);
    let key_pair = KeyPair::generate().expect("generate key pair");
    let der = params.self_signed(&key_pair).expect("self-sign CA").der().to_vec();
    Ca { der, params, key_pair }
}

/// A CA certificate issued by another CA (path length optionally constrained).
pub fn issue_ca(subject_cn: &str, issuer: &Ca, path_len_constraint: Option<u8>, configure: impl FnOnce(&mut CertificateParams)) -> Ca {
    let mut params = base_params(subject_cn);
    params.is_ca = IsCa::Ca(match path_len_constraint {
        Some(n) => rcgen::BasicConstraints::Constrained(n),
        None => rcgen::BasicConstraints::Unconstrained,
    });
    configure(&mut params);

    let key_pair = KeyPair::generate().expect("generate key pair");
    let der = params.signed_by(&key_pair, &issuer.issuer()).expect("sign CA").der().to_vec();
    Ca { der, params, key_pair }
}

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

pub fn dns_subtree(name: &str) -> GeneralSubtree {
    GeneralSubtree::DnsName(name.to_string())
}

pub fn name_constraints(permitted: Vec<GeneralSubtree>, excluded: Vec<GeneralSubtree>) -> NameConstraints {
    NameConstraints {
        permitted_subtrees: permitted,
        excluded_subtrees: excluded,
    }
}