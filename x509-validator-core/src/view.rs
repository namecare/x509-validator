use std::fmt::Debug;

pub type Timestamp = i64; // seconds since Unix epoch; matches GeneralizedTime precision needs (whole seconds)

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Oid(pub Vec<u8>); // raw DER content bytes of the OID, comparable

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithmId {
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    EcdsaP521Sha512,
    Ed25519,
    RsaPkcs1Sha256,
    RsaPssSha256,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneralNameKind {
    DnsName,
    IpAddress,
    UniformResourceIdentifier,
    DirectoryName,
    Other,
}

/// A backend is free to choose, per method, whether to decode eagerly (at
/// construction time, caching the result) or lazily (re-deriving the answer
/// from its own retained parsed representation on every call). Nothing in
/// this trait mandates either strategy. `canonical_der()` is the primitive
/// escape hatch: it hands back the raw DER bytes of the Name with no
/// decoding at all, so a backend that wants to stay lazy can implement
/// `general_names()`/`common_name()` by decoding `canonical_der()` on demand
/// (using whatever native parsing capability it has) instead of being forced
/// to pre-compute and store the decoded form.
pub trait NameView: PartialEq + Eq + Debug {
    /// Every name attached to this certificate as a unified sequence: the
    /// subject distinguished name (as a directoryName GeneralName), followed
    /// by every subjectAltName entry. NameConstraintsPolicy walks this
    /// unified sequence, not subject_alt_names() alone.
    ///
    /// May be computed eagerly and cached, or decoded on demand from
    /// `canonical_der()` — see the trait-level doc comment.
    fn general_names(&self) -> Vec<(GeneralNameKind, Vec<u8>)>;

    /// Canonical DER-encoded bytes of this Name, suitable for use as a HashMap key in certificate stores.
    ///
    /// This is the primitive, always-cheap accessor: no ASN.1 decoding
    /// beyond what's needed to locate the Name's bytes. A lazy backend can
    /// use this as the source it decodes on every call to
    /// `general_names()`/`common_name()`, rather than eagerly materializing
    /// those decoded forms up front.
    fn canonical_der(&self) -> &[u8];

    /// Raw value bytes of the LAST (most specific, i.e. last in RDN
    /// iteration order) `commonName` attribute in this distinguished name,
    /// or `None` if the name carries no `commonName` attribute at all.
    /// Needed by `ServerIdentityPolicy` for the fallback case where a leaf
    /// certificate has no usable subjectAltName entries and the subject's
    /// common name is the only identity available to match a hostname
    /// against.
    ///
    /// May be computed eagerly and cached, or decoded on demand from
    /// `canonical_der()` — see the trait-level doc comment.
    fn common_name(&self) -> Option<Vec<u8>>;
}

pub trait PublicKeyInfoView: PartialEq + Eq + Debug {
    fn subject_public_key_info_der(&self) -> &[u8];
}

#[derive(Debug, Clone)]
pub struct BasicConstraints {
    pub is_ca: bool,
    pub max_path_length: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct NameConstraints {
    pub permitted_subtrees: Vec<(GeneralNameKind, Vec<u8>)>,
    pub excluded_subtrees: Vec<(GeneralNameKind, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct AuthorityKeyIdentifier {
    pub key_identifier: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SubjectKeyIdentifier {
    pub key_identifier: Vec<u8>,
}

/// Every subjectAltName entry attached to a certificate. The Rust equivalent
/// of swift-certificates' `SubjectAlternativeNames`, but represented as the
/// plain `(GeneralNameKind, Vec<u8>)` shape `NameView::general_names` and
/// `ExtensionsView::subject_alt_names` already use, rather than a distinct
/// wrapper type — there's only ever one caller-visible shape for a GeneralName
/// sequence, so a newtype here would just be forwarded through immediately.
#[derive(Debug, Clone)]
pub struct SubjectAlternativeNames(pub Vec<(GeneralNameKind, Vec<u8>)>);

/// A type that can be decoded from raw DER content bytes.
///
/// This is the Rust equivalent of swift-certificates'
/// `init(_ ext: Certificate.Extension) throws` pattern (see
/// `Certificate.Extension` and `BasicConstraints.init(_:)` in
/// swift-certificates). Every backend supplies its own `from_der`
/// implementation using whatever ASN.1 parsing capability it has; core only
/// fixes the shape.
pub trait DerDecodable: Sized {
    type Error: std::error::Error;

    fn from_der(bytes: &[u8]) -> Result<Self, Self::Error>;
}

/// Purely the type-erased raw-access layer over a certificate's extensions —
/// the Rust equivalent of swift-certificates' `Certificate.Extension`
/// `{oid, critical, value}` triple and `Certificate.Extensions`' underlying
/// storage, plus the typed convenience accessors swift-certificates exposes
/// as an extension on `Certificate.Extensions`.
///
/// `ExtensionsView` itself implements `DerDecodable`: a backend constructs
/// its concrete `Extensions` type directly from the DER bytes of the
/// certificate's `Extensions` SEQUENCE.
pub trait ExtensionsView: Debug + DerDecodable {
    /// Every extension present, regardless of whether any `DerDecodable`
    /// type understands it. Backs any custom policy that only needs OID
    /// presence (e.g. an app-specific "leaf must carry OID X" check).
    fn oids(&self) -> Vec<(Oid, bool /* critical */)>;
    fn bytes_for(&self, oid: &Oid) -> Option<&[u8]>;

    /// Loads the basicConstraints extension, if present. RFC 5280 §4.2.1.9.
    fn basic_constraints(&self) -> Result<Option<BasicConstraints>, <BasicConstraints as DerDecodable>::Error> {
        self.bytes_for(&basic_constraints_oid()).map(BasicConstraints::from_der).transpose()
    }

    /// Loads the nameConstraints extension, if present. RFC 5280 §4.2.1.10.
    fn name_constraints(&self) -> Result<Option<NameConstraints>, <NameConstraints as DerDecodable>::Error> {
        self.bytes_for(&name_constraints_oid()).map(NameConstraints::from_der).transpose()
    }

    /// Loads the authorityKeyIdentifier extension, if present. RFC 5280 §4.2.1.1.
    fn authority_key_identifier(
        &self,
    ) -> Result<Option<AuthorityKeyIdentifier>, <AuthorityKeyIdentifier as DerDecodable>::Error> {
        self.bytes_for(&authority_key_identifier_oid()).map(AuthorityKeyIdentifier::from_der).transpose()
    }

    /// Loads the subjectKeyIdentifier extension, if present. RFC 5280 §4.2.1.2.
    fn subject_key_identifier(&self) -> Result<Option<SubjectKeyIdentifier>, <SubjectKeyIdentifier as DerDecodable>::Error> {
        self.bytes_for(&subject_key_identifier_oid()).map(SubjectKeyIdentifier::from_der).transpose()
    }

    /// Loads the subjectAltName extension, if present, as its unwrapped
    /// `(GeneralNameKind, Vec<u8>)` entries. RFC 5280 §4.2.1.6.
    fn subject_alt_names(
        &self,
    ) -> Result<Option<Vec<(GeneralNameKind, Vec<u8>)>>, <SubjectAlternativeNames as DerDecodable>::Error> {
        Ok(self.bytes_for(&subject_alt_name_oid()).map(SubjectAlternativeNames::from_der).transpose()?.map(|sans| sans.0))
    }
}

/// id-ce-basicConstraints, RFC 5280 §4.2.1.9: 2.5.29.19.
fn basic_constraints_oid() -> Oid {
    Oid(vec![0x55, 0x1D, 0x13])
}

/// id-ce-nameConstraints, RFC 5280 §4.2.1.10: 2.5.29.30.
fn name_constraints_oid() -> Oid {
    Oid(vec![0x55, 0x1D, 0x1E])
}

/// id-ce-authorityKeyIdentifier, RFC 5280 §4.2.1.1: 2.5.29.35.
fn authority_key_identifier_oid() -> Oid {
    Oid(vec![0x55, 0x1D, 0x23])
}

/// id-ce-subjectKeyIdentifier, RFC 5280 §4.2.1.2: 2.5.29.14.
fn subject_key_identifier_oid() -> Oid {
    Oid(vec![0x55, 0x1D, 0x0E])
}

/// id-ce-subjectAltName, RFC 5280 §4.2.1.6: 2.5.29.17.
fn subject_alt_name_oid() -> Oid {
    Oid(vec![0x55, 0x1D, 0x11])
}

pub trait CertificateView: Debug + Sized {
    type Name: NameView;
    type Extensions: ExtensionsView;
    type PublicKeyInfo: PublicKeyInfoView;
    type Error: std::error::Error;

    /// Parses a DER-encoded certificate into this backend's concrete
    /// certificate type. The one entry point a `Verifier` implementation
    /// needs to turn caller-supplied DER (leaf, intermediates, roots) into
    /// `Self` without core depending on any particular parsing backend.
    fn from_der(der: &[u8]) -> Result<Self, Self::Error>;

    fn subject(&self) -> &Self::Name;
    fn issuer(&self) -> &Self::Name;
    fn is_v1(&self) -> bool;
    fn has_extensions(&self) -> bool;
    fn not_before(&self) -> Timestamp;
    fn not_after(&self) -> Timestamp;
    fn extensions(&self) -> &Self::Extensions;
    fn public_key_info(&self) -> &Self::PublicKeyInfo;
    fn signature_algorithm(&self) -> SignatureAlgorithmId;
    fn signature(&self) -> &[u8];
    fn tbs_der(&self) -> &[u8]; // bytes actually covered by the signature
}