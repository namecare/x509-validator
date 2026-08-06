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

    /// The DER-encoded `SubjectPublicKeyInfo` of this CA's key pair. This is
    /// byte-identical to the `subjectPublicKeyInfo` field of any certificate
    /// carrying this key, which lets a test identify "the key that signed
    /// this" without doing real asymmetric crypto.
    pub fn public_key_der(&self) -> Vec<u8> {
        rcgen::PublicKeyData::subject_public_key_info(&self.key_pair)
    }

    /// A second certificate for this CA's identity, signed by `issuer`
    /// rather than self-signed: same subject name and same public key, a
    /// different signature. This is the shape of a cross-signed root.
    ///
    /// A copy of this CA's key pair. The generator's `KeyPair` is not
    /// `Clone`, so this round-trips through the serialized private key.
    pub fn copy_of_key_pair(&self) -> KeyPair {
        KeyPair::from_pem(&self.key_pair.serialize_pem()).expect("round-trip key pair")
    }

    pub fn cross_signed_by(&self, issuer: &Ca) -> Ca {
        let mut params = self.params.clone();
        params.use_authority_key_identifier_extension = true;
        let key_pair = self.copy_of_key_pair();
        let der = params
            .signed_by(&key_pair, &issuer.issuer())
            .expect("cross-sign CA")
            .der()
            .to_vec();
        Ca { der, params, key_pair }
    }

    /// The `subjectKeyIdentifier` value this CA's own certificate carries,
    /// derived the same way the generator derives it. Useful for building
    /// another certificate whose `authorityKeyIdentifier` must equal — or
    /// deliberately differ from — this one.
    pub fn key_identifier(&self) -> Vec<u8> {
        self.params.key_identifier(&self.key_pair)
    }
}

/// A signing identity that is *not* itself a certificate: a subject
/// distinguished name plus the key that signs on its behalf, usable
/// anywhere a [`Ca`] is accepted as an issuer.
///
/// RFC 5280 §4.1.2.4 ties a certificate to its issuer by name alone, so a
/// PKI can contain cycles in which the certificate naming an issuer is
/// itself issued by that issuer's subject. Building such a PKI needs a way
/// to sign "as" a name before any certificate for that name exists, which
/// is what this provides. `der` is empty: this identity has no certificate
/// of its own and must never be put in a store.
///
/// `authority_key_identifier` fixes the `authorityKeyIdentifier` value that
/// certificates issued by this identity will carry, independently of the
/// signing key — the mismatch RFC 5280 §4.2.1.1 does not forbid, and which
/// chain building has to tolerate.
pub fn signing_identity(subject_cn: &str, key_pair: KeyPair, authority_key_identifier: Option<Vec<u8>>) -> Ca {
    let mut params = base_params(subject_cn);
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    if let Some(bytes) = authority_key_identifier {
        params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(bytes);
    }
    Ca {
        der: Vec::new(),
        params,
        key_pair,
    }
}

/// A CA certificate issued by `issuer`, with full control over its subject
/// name, its own key, its `subjectKeyIdentifier`, whether it carries an
/// `authorityKeyIdentifier`, and any further parameters.
pub fn issue_ca_with_key_and_name(
    subject_cn: &str,
    issuer: &Ca,
    key_pair: KeyPair,
    path_len_constraint: Option<u8>,
    ski: Ski,
    include_aki: bool,
    configure: impl FnOnce(&mut CertificateParams),
) -> Ca {
    let mut params = base_params(subject_cn);
    params.is_ca = IsCa::Ca(match path_len_constraint {
        Some(n) => rcgen::BasicConstraints::Constrained(n),
        None => rcgen::BasicConstraints::Unconstrained,
    });
    params.use_authority_key_identifier_extension = include_aki;
    apply_ski(&mut params, ski, true);
    configure(&mut params);

    let der = params.signed_by(&key_pair, &issuer.issuer()).expect("sign CA").der().to_vec();
    Ca { der, params, key_pair }
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

// ---------------------------------------------------------------------------
// Subject/authority key identifier control.
//
// The certificate generator emits a subjectKeyIdentifier unconditionally for
// anything it considers a CA, and its `key_identifier_method` setting only
// chooses the *value* of that extension, never whether it appears at all. To
// build a CA that genuinely omits the extension — the case RFC 5280 §4.2.1.2
// permits and that chain building must cope with — the certificate is
// generated as a non-CA and the `basicConstraints` extension is attached by
// hand instead.
// ---------------------------------------------------------------------------

/// id-ce-basicConstraints, RFC 5280 §4.2.1.9: 2.5.29.19.
const BASIC_CONSTRAINTS_OID: &[u64] = &[2, 5, 29, 19];

/// A critical `basicConstraints` extension asserting `cA = TRUE`, with
/// `pathLenConstraint` absent.
fn manual_basic_constraints_ca() -> rcgen::CustomExtension {
    // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
    let contents = der_tlv(0x30, &der_tlv(0x01, &[0xff]));
    let mut extension = rcgen::CustomExtension::from_oid_content(BASIC_CONSTRAINTS_OID, contents);
    extension.set_criticality(true);
    extension
}

/// How a generated certificate should carry its `subjectKeyIdentifier`.
pub enum Ski {
    /// The generator's default: a digest over the subject public key.
    Derived,
    /// The exact bytes given, so a test can make an SKI that matches — or
    /// deliberately fails to match — some other certificate's AKI.
    Exactly(Vec<u8>),
    /// No `subjectKeyIdentifier` extension at all.
    Absent,
}

/// Applies `ski` to `params`, which must otherwise already be configured.
/// Returns the `IsCa` the caller should not overwrite: suppressing the
/// extension requires generating a non-CA and re-adding `basicConstraints`
/// by hand.
fn apply_ski(params: &mut CertificateParams, ski: Ski, is_ca: bool) {
    match ski {
        Ski::Derived => {}
        Ski::Exactly(bytes) => {
            params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(bytes);
        }
        Ski::Absent => {
            if is_ca {
                params.is_ca = IsCa::NoCa;
                params.custom_extensions.push(manual_basic_constraints_ca());
            }
        }
    }
}

/// A CA issued by `issuer`, with explicit control over its own
/// `subjectKeyIdentifier` and over whether it carries an
/// `authorityKeyIdentifier` at all.
///
/// The AKI value, when requested, is derived by the generator from
/// `issuer`'s own key identifier method, so it matches `issuer`'s SKI
/// exactly — which is what RFC 5280 §4.2.1.1 intends the extension to do.
pub fn issue_ca_with_key_ids(
    subject_cn: &str,
    issuer: &Ca,
    path_len_constraint: Option<u8>,
    ski: Ski,
    include_aki: bool,
) -> Ca {
    let mut params = base_params(subject_cn);
    params.is_ca = IsCa::Ca(match path_len_constraint {
        Some(n) => rcgen::BasicConstraints::Constrained(n),
        None => rcgen::BasicConstraints::Unconstrained,
    });
    params.use_authority_key_identifier_extension = include_aki;
    apply_ski(&mut params, ski, true);

    let key_pair = KeyPair::generate().expect("generate key pair");
    let der = params.signed_by(&key_pair, &issuer.issuer()).expect("sign CA").der().to_vec();
    Ca { der, params, key_pair }
}

/// Like [`issue_ca_with_key_ids`], but reusing an existing `key_pair` rather
/// than generating a fresh one — so two such certificates share a public key
/// and differ only in the rest of their content.
pub fn issue_ca_with_key(
    subject_cn: &str,
    issuer: &Ca,
    key_pair: KeyPair,
    ski: Ski,
    include_aki: bool,
    configure: impl FnOnce(&mut CertificateParams),
) -> Ca {
    let mut params = base_params(subject_cn);
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.use_authority_key_identifier_extension = include_aki;
    apply_ski(&mut params, ski, true);
    configure(&mut params);

    let der = params.signed_by(&key_pair, &issuer.issuer()).expect("sign CA").der().to_vec();
    Ca { der, params, key_pair }
}

/// A self-signed CA whose `subjectKeyIdentifier` is controlled by `ski`,
/// optionally reusing an existing key pair so that two roots can share one
/// identity while differing in their extensions.
pub fn self_signed_ca_with_key_ids(subject_cn: &str, key_pair: Option<KeyPair>, ski: Ski) -> Ca {
    let mut params = base_params(subject_cn);
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    apply_ski(&mut params, ski, true);

    let key_pair = key_pair.unwrap_or_else(|| KeyPair::generate().expect("generate key pair"));
    let der = params.self_signed(&key_pair).expect("self-sign CA").der().to_vec();
    Ca { der, params, key_pair }
}

/// A non-CA leaf issued by `issuer`, carrying an `authorityKeyIdentifier`
/// when `include_aki` is set.
pub fn issue_leaf_with_aki(subject_cn: &str, dns_sans: &[&str], issuer: &Ca, include_aki: bool) -> Vec<u8> {
    issue_leaf_with(subject_cn, dns_sans, issuer, |params| {
        params.use_authority_key_identifier_extension = include_aki;
    })
}

pub fn dns_subtree(name: &str) -> GeneralSubtree {
    GeneralSubtree::DnsName(name.to_string())
}

/// An iPAddress subtree covering the given IPv4 base/mask pair.
pub fn ipv4_subtree(base: [u8; 4], mask: [u8; 4]) -> GeneralSubtree {
    GeneralSubtree::IpAddress(rcgen::CidrSubnet::V4(base, mask))
}

/// A directoryName subtree carrying a single commonName attribute.
pub fn directory_name_subtree(common_name: &str) -> GeneralSubtree {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    GeneralSubtree::DirectoryName(dn)
}

pub fn name_constraints(permitted: Vec<GeneralSubtree>, excluded: Vec<GeneralSubtree>) -> NameConstraints {
    NameConstraints {
        permitted_subtrees: permitted,
        excluded_subtrees: excluded,
    }
}

// ---------------------------------------------------------------------------
// Hand-encoded nameConstraints extensions.
//
// The certificate generator's `GeneralSubtree` type only models a subset of
// the GeneralName choices in RFC 5280 §4.2.1.6 — notably it cannot express
// `uniformResourceIdentifier`, nor any of the choices this crate treats as
// unsupported (otherName, x400Address, ediPartyName, registeredID). Those
// subtree kinds are built here as raw DER instead, and attached with a
// custom extension carrying the nameConstraints OID.
// ---------------------------------------------------------------------------

/// id-ce-nameConstraints, RFC 5280 §4.2.1.10: 2.5.29.30.
const NAME_CONSTRAINTS_OID: &[u64] = &[2, 5, 29, 30];

/// id-ce-subjectAltName, RFC 5280 §4.2.1.6: 2.5.29.17.
const SUBJECT_ALT_NAME_OID: &[u64] = &[2, 5, 29, 17];

/// A DER TLV: `tag`, a definite-form length, then `contents`.
fn der_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
    out.extend_from_slice(contents);
    out
}

/// One GeneralName, as the context-specific primitive `[tag] contents`.
///
/// The GeneralName CHOICE tags are assigned in RFC 5280 §4.2.1.6:
/// otherName \[0\], rfc822Name \[1\], dNSName \[2\], x400Address \[3\],
/// directoryName \[4\], ediPartyName \[5\], uniformResourceIdentifier \[6\],
/// iPAddress \[7\], registeredID \[8\].
#[derive(Clone)]
pub struct RawGeneralName(Vec<u8>);

impl RawGeneralName {
    fn primitive(tag_number: u8, contents: &[u8]) -> Self {
        Self(der_tlv(0x80 | tag_number, contents))
    }

    /// uniformResourceIdentifier \[6\], an IA5String.
    pub fn uri(value: &str) -> Self {
        Self::primitive(6, value.as_bytes())
    }

    /// dNSName \[2\], an IA5String.
    pub fn dns(value: &str) -> Self {
        Self::primitive(2, value.as_bytes())
    }

    /// iPAddress \[7\], a raw octet string. For a constraint this is the
    /// base address followed by the mask; for a name it is the address
    /// alone.
    pub fn ip(value: &[u8]) -> Self {
        Self::primitive(7, value)
    }

    /// rfc822Name \[1\] — a kind this crate does not know how to match.
    pub fn rfc822(value: &str) -> Self {
        Self::primitive(1, value.as_bytes())
    }

    /// registeredID \[8\], carrying the OID 1.2.1.1.
    pub fn registered_id() -> Self {
        Self::primitive(8, &[0x2a, 0x01, 0x01])
    }

    /// otherName \[0\]: a constructed SEQUENCE of a type OID and a value.
    pub fn other_name() -> Self {
        let mut contents = Vec::new();
        contents.extend_from_slice(&der_tlv(0x06, &[0x2a, 0x01, 0x01])); // OID 1.2.1.1
        contents.extend_from_slice(&der_tlv(0xa0, &der_tlv(0x05, &[]))); // [0] NULL
        Self(der_tlv(0xa0, &contents))
    }

    /// x400Address \[3\], a constructed value this crate cannot interpret.
    pub fn x400_address() -> Self {
        Self(der_tlv(0xa3, &der_tlv(0x05, &[])))
    }

    /// ediPartyName \[5\], a constructed value this crate cannot interpret.
    pub fn edi_party_name() -> Self {
        Self(der_tlv(0xa5, &der_tlv(0x05, &[])))
    }
}

/// A GeneralSubtree wrapping one GeneralName, with `minimum`/`maximum`
/// omitted as RFC 5280 §4.2.1.10 requires.
fn general_subtree(name: &RawGeneralName) -> Vec<u8> {
    der_tlv(0x30, &name.0)
}

/// A nameConstraints extension built from raw GeneralNames, encoded as
/// `SEQUENCE { [0] permittedSubtrees OPTIONAL, [1] excludedSubtrees OPTIONAL }`.
pub fn raw_name_constraints_extension(permitted: &[RawGeneralName], excluded: &[RawGeneralName]) -> rcgen::CustomExtension {
    let mut body = Vec::new();

    if !permitted.is_empty() {
        let subtrees: Vec<u8> = permitted.iter().flat_map(general_subtree).collect();
        body.extend_from_slice(&der_tlv(0xa0, &subtrees));
    }
    if !excluded.is_empty() {
        let subtrees: Vec<u8> = excluded.iter().flat_map(general_subtree).collect();
        body.extend_from_slice(&der_tlv(0xa1, &subtrees));
    }

    let mut extension = rcgen::CustomExtension::from_oid_content(NAME_CONSTRAINTS_OID, der_tlv(0x30, &body));
    extension.set_criticality(true);
    extension
}

/// A subjectAltName extension built from raw GeneralNames, for name forms
/// the generator's own `SanType` cannot express.
pub fn raw_subject_alt_name_extension(names: &[RawGeneralName]) -> rcgen::CustomExtension {
    let contents: Vec<u8> = names.iter().flat_map(|n| n.0.clone()).collect();
    let mut extension = rcgen::CustomExtension::from_oid_content(SUBJECT_ALT_NAME_OID, der_tlv(0x30, &contents));
    extension.set_criticality(true);
    extension
}

/// A nameConstraints extension whose contents are undecodable gibberish.
pub fn broken_name_constraints_extension() -> rcgen::CustomExtension {
    let mut extension = rcgen::CustomExtension::from_oid_content(NAME_CONSTRAINTS_OID, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    extension.set_criticality(true);
    extension
}

/// A subjectAltName extension whose contents are undecodable gibberish.
pub fn broken_subject_alt_name_extension() -> rcgen::CustomExtension {
    let mut extension = rcgen::CustomExtension::from_oid_content(SUBJECT_ALT_NAME_OID, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    extension.set_criticality(true);
    extension
}

/// A critical extension with an OID no policy in this crate claims.
pub fn weird_critical_extension() -> rcgen::CustomExtension {
    let mut extension = rcgen::CustomExtension::from_oid_content(&[1, 2, 3, 4, 5], vec![1, 2, 3, 4, 5]);
    extension.set_criticality(true);
    extension
}

/// A CA certificate issued by another CA, keeping the issuer's own subject
/// distinguished name — i.e. a self-issued certificate from the issuer's
/// point of view, signed with a fresh key.
pub fn issue_self_issued_ca(issuer: &Ca, path_len_constraint: Option<u8>) -> Ca {
    let mut params = CertificateParams::default();
    params.distinguished_name = issuer.params.distinguished_name.clone();
    params.not_before = issuer.params.not_before;
    params.not_after = issuer.params.not_after;
    params.is_ca = IsCa::Ca(match path_len_constraint {
        Some(n) => rcgen::BasicConstraints::Constrained(n),
        None => rcgen::BasicConstraints::Unconstrained,
    });

    let key_pair = KeyPair::generate().expect("generate key pair");
    let der = params.signed_by(&key_pair, &issuer.issuer()).expect("sign CA").der().to_vec();
    Ca { der, params, key_pair }
}
