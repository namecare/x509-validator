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

pub trait NameView: PartialEq + Eq + Debug {
    /// Every name attached to this certificate as a unified sequence: the
    /// subject distinguished name (as a directoryName GeneralName), followed
    /// by every subjectAltName entry. NameConstraintsPolicy walks this
    /// unified sequence, not subject_alt_names() alone.
    fn general_names(&self) -> Vec<(GeneralNameKind, Vec<u8>)>;

    /// Canonical DER-encoded bytes of this Name, suitable for use as a HashMap key in certificate stores.
    fn canonical_der(&self) -> &[u8];

    /// Raw value bytes of the LAST (most specific, i.e. last in RDN
    /// iteration order) `commonName` attribute in this distinguished name,
    /// or `None` if the name carries no `commonName` attribute at all.
    /// Needed by `ServerIdentityPolicy` for the fallback case where a leaf
    /// certificate has no usable subjectAltName entries and the subject's
    /// common name is the only identity available to match a hostname
    /// against.
    fn common_name(&self) -> Option<Vec<u8>>;
}

pub trait PublicKeyInfoView: PartialEq + Eq + Debug {
    fn subject_public_key_info_der(&self) -> &[u8];
}

pub struct BasicConstraints {
    pub is_ca: bool,
    pub max_path_length: Option<u32>,
}

pub struct NameConstraints {
    pub permitted_subtrees: Vec<(GeneralNameKind, Vec<u8>)>,
    pub excluded_subtrees: Vec<(GeneralNameKind, Vec<u8>)>,
}

pub struct AuthorityKeyIdentifier {
    pub key_identifier: Option<Vec<u8>>,
}

pub struct SubjectKeyIdentifier {
    pub key_identifier: Vec<u8>,
}

pub trait ExtensionsView: Debug {
    type Error: std::error::Error;

    /// Every extension present, regardless of whether this trait has a typed
    /// getter for it. Backs any custom policy that only needs OID presence
    /// (e.g. an app-specific "leaf must carry OID X" check).
    fn oids(&self) -> Vec<(Oid, bool /* critical */)>;
    fn bytes_for(&self, oid: &Oid) -> Option<&[u8]>;

    fn basic_constraints(&self) -> Result<Option<BasicConstraints>, Self::Error>;
    fn name_constraints(&self) -> Result<Option<NameConstraints>, Self::Error>;
    fn key_usage_present(&self) -> Result<bool, Self::Error>;
    fn extended_key_usage_contains_ocsp_signing(&self) -> Result<bool, Self::Error>;
    fn subject_alt_names(&self) -> Result<Option<Vec<(GeneralNameKind, Vec<u8>)>>, Self::Error>;
    fn authority_key_identifier(&self) -> Result<Option<AuthorityKeyIdentifier>, Self::Error>;
    fn subject_key_identifier(&self) -> Result<Option<SubjectKeyIdentifier>, Self::Error>;
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