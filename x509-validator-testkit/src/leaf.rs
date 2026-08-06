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
