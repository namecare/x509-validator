use crate::raw::der_tlv;
use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair};
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
    pub(crate) fn issuer(&self) -> Issuer<'_, &KeyPair> {
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

pub(crate) fn base_params(subject_cn: &str) -> CertificateParams {
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
pub(crate) fn apply_ski(params: &mut CertificateParams, ski: Ski, is_ca: bool) {
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

/// A CA built from an explicit specification rather than the defaults in
/// [`base_params`], for callers that need to pin the key algorithm and the
/// validity window — the two axes the older helpers fix internally.
///
/// The older `issue_ca*` / `self_signed_ca*` helpers remain the shorter path
/// when those defaults are fine.
pub struct CaSpec {
    subject_cn: String,
    key_pair: Option<KeyPair>,
    not_before: Option<OffsetDateTime>,
    not_after: Option<OffsetDateTime>,
    path_len: Option<u8>,
    ski: Ski,
    include_aki: bool,
}

impl CaSpec {
    pub fn new(subject_cn: &str) -> Self {
        Self {
            subject_cn: subject_cn.to_string(),
            key_pair: None,
            not_before: None,
            not_after: None,
            path_len: None,
            ski: Ski::Derived,
            include_aki: false,
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

    pub fn path_len(mut self, path_len: Option<u8>) -> Self {
        self.path_len = path_len;
        self
    }

    pub fn ski(mut self, ski: Ski) -> Self {
        self.ski = ski;
        self
    }

    pub fn include_aki(mut self, include_aki: bool) -> Self {
        self.include_aki = include_aki;
        self
    }

    /// The params and key pair this spec describes, shared by both
    /// `self_signed` and `signed_by`.
    fn build(self) -> (CertificateParams, KeyPair) {
        let mut params = base_params(&self.subject_cn);
        params.is_ca = IsCa::Ca(match self.path_len {
            Some(n) => rcgen::BasicConstraints::Constrained(n),
            None => rcgen::BasicConstraints::Unconstrained,
        });
        params.use_authority_key_identifier_extension = self.include_aki;
        if let Some(not_before) = self.not_before {
            params.not_before = not_before;
        }
        if let Some(not_after) = self.not_after {
            params.not_after = not_after;
        }
        apply_ski(&mut params, self.ski, true);

        let key_pair = self.key_pair.unwrap_or_else(|| KeyPair::generate().expect("generate key pair"));
        (params, key_pair)
    }

    pub fn self_signed(self) -> Ca {
        let (params, key_pair) = self.build();
        let der = params.self_signed(&key_pair).expect("self-sign CA").der().to_vec();
        Ca { der, params, key_pair }
    }

    pub fn signed_by(self, issuer: &Ca) -> Ca {
        let (params, key_pair) = self.build();
        let der = params.signed_by(&key_pair, &issuer.issuer()).expect("sign CA").der().to_vec();
        Ca { der, params, key_pair }
    }
}

pub fn self_signed(key_pair: &KeyPair) -> Vec<u8> {
    let params = CertificateParams::default();
    params.self_signed(key_pair).expect("self-sign").der().to_vec()
}

#[cfg(test)]
mod ca_spec_tests {
    use super::*;
    use x509_validator::{Certificate, CertificateExt};

    #[test]
    fn ca_spec_honours_key_algorithm_and_validity() {
        let not_before = OffsetDateTime::UNIX_EPOCH + Duration::days(1);
        let not_after = OffsetDateTime::UNIX_EPOCH + Duration::days(365);

        let ca = CaSpec::new("spec root")
            .key_pair(KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("p384 key"))
            .validity(not_before, not_after)
            .self_signed();

        let parsed = Certificate::parse(&ca.der).expect("parse");
        let validity = parsed.tbs_certificate.validity();

        assert_eq!(validity.not_before.timestamp(), not_before.unix_timestamp());
        assert_eq!(validity.not_after.timestamp(), not_after.unix_timestamp());

        // The named curve carried in the SPKI algorithm parameters, which is
        // what "this key is P-384" actually means.
        let curve = parsed
            .tbs_certificate
            .subject_pki
            .algorithm
            .parameters
            .as_ref()
            .expect("EC public key carries curve parameters")
            .as_oid()
            .expect("curve parameters are an OID");
        assert_eq!(curve, x509_validator::oid_registry::OID_NIST_EC_P384);
    }

    #[test]
    fn ca_spec_signed_by_chains_to_issuer() {
        let root = CaSpec::new("spec issuer").self_signed();
        let intermediate = CaSpec::new("spec intermediate").path_len(Some(1)).signed_by(&root);

        let parsed = Certificate::parse(&intermediate.der).expect("parse");
        assert_eq!(parsed.issuer().as_raw(), Certificate::parse(&root.der).expect("parse").subject().as_raw());
    }
}
