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
    /// unified sequence, not the decoded subjectAlternativeNames extension
    /// alone.
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

/// A single X.509 certificate extension: the Rust equivalent of
/// swift-certificates' `Certificate.Extension` `{oid, critical, value}`
/// triple.
pub trait ExtensionView: Debug {
    fn oid(&self) -> &Oid;
    fn critical(&self) -> bool;
    fn value(&self) -> &[u8];

    /// Decodes this extension's value bytes as `T`. The Rust equivalent of
    /// swift-certificates' `init(_ ext: Certificate.Extension) throws`
    /// pattern (see e.g. `BasicConstraints.init(_:)`).
    fn decode<T: DerDecodable>(&self) -> Result<T, T::Error> {
        T::from_der(self.value())
    }
}

/// id-ce-basicConstraints, RFC 5280 §4.2.1.9: 2.5.29.19.
///
/// The Rust equivalent of swift-certificates' `BasicConstraints`.
pub trait BasicConstraintsView: DerDecodable {
    fn is_ca(&self) -> bool;
    fn max_path_length(&self) -> Option<u32>;
}

/// id-ce-nameConstraints, RFC 5280 §4.2.1.10: 2.5.29.30.
///
/// The Rust equivalent of swift-certificates' `NameConstraints`.
pub trait NameConstraintsView: DerDecodable {
    fn permitted_subtrees(&self) -> &[(GeneralNameKind, Vec<u8>)];
    fn excluded_subtrees(&self) -> &[(GeneralNameKind, Vec<u8>)];
}

/// id-ce-authorityKeyIdentifier, RFC 5280 §4.2.1.1: 2.5.29.35.
///
/// The Rust equivalent of swift-certificates' `AuthorityKeyIdentifier`.
pub trait AuthorityKeyIdentifierView: DerDecodable {
    fn key_identifier(&self) -> Option<&[u8]>;
}

/// id-ce-subjectKeyIdentifier, RFC 5280 §4.2.1.2: 2.5.29.14.
///
/// The Rust equivalent of swift-certificates' `SubjectKeyIdentifier`.
pub trait SubjectKeyIdentifierView: DerDecodable {
    fn key_identifier(&self) -> &[u8];
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

/// Typed convenience accessors over a certificate's extensions, mirroring
/// swift-certificates' `extension Certificate.Extensions { ... }` (see e.g.
/// its `basicConstraints`/`subjectKeyIdentifier` computed properties). These
/// live as a blanket impl over `[E]` rather than a dedicated collection
/// trait, since "a certificate's extensions" is just a plain slice of
/// `ExtensionView` items — no additional storage or behavior beyond what the
/// slice already provides.
pub trait ExtensionsExt<E: ExtensionView> {
    /// Every critical extension OID present that isn't in `handled` (the set
    /// a policy declares it understands and enforces). Per RFC 5280 §4.2, a
    /// certificate consumer must reject a certificate carrying a critical
    /// extension it does not recognize.
    fn unhandled_critical_extensions(&self, handled: &[Oid]) -> Vec<Oid>;

    /// Loads the basicConstraints extension, if present.
    fn basic_constraints<T: BasicConstraintsView>(&self) -> Result<Option<T>, T::Error>;

    /// Loads the nameConstraints extension, if present.
    fn name_constraints<T: NameConstraintsView>(&self) -> Result<Option<T>, T::Error>;

    /// Loads the authorityKeyIdentifier extension, if present.
    fn authority_key_identifier<T: AuthorityKeyIdentifierView>(&self) -> Result<Option<T>, T::Error>;

    /// Loads the subjectKeyIdentifier extension, if present.
    fn subject_key_identifier<T: SubjectKeyIdentifierView>(&self) -> Result<Option<T>, T::Error>;

    /// Loads the subjectAltName extension, if present, decoded as its
    /// unwrapped `(GeneralNameKind, Vec<u8>)` entries. Unlike the other four
    /// extensions, callers only ever want the decoded GeneralName list
    /// itself (see `NameConstraintsPolicy`, `ServerIdentityPolicy`,
    /// `same_certificate_identity`) — never a richer typed wrapper — so `T`
    /// decodes directly to that shape rather than through a dedicated view
    /// trait.
    fn subject_alternative_names<T>(&self) -> Result<Option<Vec<(GeneralNameKind, Vec<u8>)>>, T::Error>
    where
        T: DerDecodable + Into<Vec<(GeneralNameKind, Vec<u8>)>>;

    /// Raw DER content bytes of the subjectAltName extension, if present,
    /// with no GeneralName decoding at all. Distinct from
    /// `subject_alternative_names()`: some callers (see `Verifier`'s
    /// `same_certificate_identity`) only need the bytes to compare identity,
    /// not the parsed GeneralName list.
    fn subject_alternative_name_bytes(&self) -> Option<&[u8]>;
}

impl<E: ExtensionView> ExtensionsExt<E> for [E] {
    fn unhandled_critical_extensions(&self, handled: &[Oid]) -> Vec<Oid> {
        self.iter()
            .filter(|ext| ext.critical() && !handled.contains(ext.oid()))
            .map(|ext| ext.oid().clone())
            .collect()
    }

    fn basic_constraints<T: BasicConstraintsView>(&self) -> Result<Option<T>, T::Error> {
        self.iter().find(|ext| *ext.oid() == basic_constraints_oid()).map(|ext| ext.decode()).transpose()
    }

    fn name_constraints<T: NameConstraintsView>(&self) -> Result<Option<T>, T::Error> {
        self.iter().find(|ext| *ext.oid() == name_constraints_oid()).map(|ext| ext.decode()).transpose()
    }

    fn authority_key_identifier<T: AuthorityKeyIdentifierView>(&self) -> Result<Option<T>, T::Error> {
        self.iter().find(|ext| *ext.oid() == authority_key_identifier_oid()).map(|ext| ext.decode()).transpose()
    }

    fn subject_key_identifier<T: SubjectKeyIdentifierView>(&self) -> Result<Option<T>, T::Error> {
        self.iter().find(|ext| *ext.oid() == subject_key_identifier_oid()).map(|ext| ext.decode()).transpose()
    }

    fn subject_alternative_names<T>(&self) -> Result<Option<Vec<(GeneralNameKind, Vec<u8>)>>, T::Error>
    where
        T: DerDecodable + Into<Vec<(GeneralNameKind, Vec<u8>)>>,
    {
        self.iter()
            .find(|ext| *ext.oid() == subject_alt_name_oid())
            .map(|ext| ext.decode::<T>().map(Into::into))
            .transpose()
    }

    fn subject_alternative_name_bytes(&self) -> Option<&[u8]> {
        self.iter().find(|ext| *ext.oid() == subject_alt_name_oid()).map(|ext| ext.value())
    }
}

/// The x509 `Certificate` object (RFC 5280 §4.1): the union of
/// `TBSCertificate`'s fields with the outer `signatureAlgorithm` and
/// `signature` that sign it. Rust's equivalent of swift-certificates'
/// `Certificate`, flattened into a single view trait since core has no
/// separate need to name `TBSCertificate` on its own.
pub trait CertificateView: Debug + Sized {
    type Name: NameView;
    type Extension: ExtensionView;
    type PublicKeyInfo: PublicKeyInfoView;
    type Error: std::error::Error;

    /// Parses a DER-encoded certificate into this backend's concrete
    /// certificate type. The one entry point a `Verifier` implementation
    /// needs to turn caller-supplied DER (leaf, intermediates, roots) into
    /// `Self` without core depending on any particular parsing backend.
    fn from_der(der: &[u8]) -> Result<Self, Self::Error>;

    /// The certificate's X.509 version (0 = v1, 1 = v2, 2 = v3).
    fn version(&self) -> u8;
    fn subject(&self) -> &Self::Name;
    fn issuer(&self) -> &Self::Name;
    fn not_before(&self) -> Timestamp;
    fn not_after(&self) -> Timestamp;
    fn extensions(&self) -> &[Self::Extension];
    fn public_key_info(&self) -> &Self::PublicKeyInfo;
    fn tbs_der(&self) -> &[u8]; // bytes actually covered by the signature

    fn signature_algorithm(&self) -> SignatureAlgorithmId;
    fn signature(&self) -> &[u8];
}
