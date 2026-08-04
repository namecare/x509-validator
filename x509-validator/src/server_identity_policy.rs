use crate::policy::{PolicyEvaluationResult, PolicyFailureReason, VerifierPolicy};
use x509_validator_core::{CertificateView, ExtensionsView, GeneralNameKind, NameView, Oid};
use std::net::{Ipv4Addr, Ipv6Addr};
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;

const ASCII_PERIOD: u8 = b'.';
const ASCII_ASTERISK: u8 = b'*';
const ASCII_IDNA_IDENTIFIER: &[u8] = b"xn--";

/// A `VerifierPolicy` that checks whether the leaf certificate is
/// authoritative for a given hostname or IP address.
///
/// This policy is most commonly used to validate the leaf certificate
/// presented by a server during a TLS handshake.
///
/// This policy implements the logic for service validation as specified by
/// RFC 6125, which loosely speaking defines the common algorithm used for
/// validating that an X.509 certificate is valid for a given service.
pub struct ServerIdentityPolicy {
    server_hostname: Option<PreparedServerHostname>,
    server_ip: Option<IpAddress>,
}

impl ServerIdentityPolicy {
    /// Constructs a new `ServerIdentityPolicy`.
    ///
    /// `server_hostname` is the hostname used to connect to the server;
    /// `server_ip` is the server's IP address, if known. A hostname that
    /// contains non-ASCII bytes is treated the same as no hostname at all
    /// (it can never match, since certificate hostnames are always ASCII):
    /// see `PreparedServerHostname::new`.
    pub fn new(server_hostname: Option<&str>, server_ip: Option<&str>) -> Self {
        Self {
            server_hostname: server_hostname.and_then(PreparedServerHostname::new),
            server_ip: server_ip.and_then(IpAddress::parse),
        }
    }
}

/// id-ce-subjectAltName, RFC 5280 §4.2.1.6: 2.5.29.17.
fn subject_alt_name_oid() -> Oid {
    Oid(vec![0x55, 0x1D, 0x11])
}

impl<C: CertificateView> VerifierPolicy<C> for ServerIdentityPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid> {
        vec![subject_alt_name_oid()]
    }

    fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain<C>) -> PolicyEvaluationResult {
        // We only validate the leaf.
        has_valid_identity_for_service(chain.leaf(), self.server_hostname.as_ref(), self.server_ip.as_ref())
    }
}

/// Validates that a given leaf certificate is valid for a service.
///
/// This implements RFC 6125 §6: we first check the subjectAlternativeName
/// extension. If it contains any entries we could validate against (either
/// a DNS name or an IP address), we validate against those and never fall
/// back to the subject's common name. If there are no matchable
/// subjectAltName entries at all, we fall back to the (deprecated) practice
/// of matching against the subject's common name.
fn has_valid_identity_for_service<C: CertificateView>(
    leaf: &C,
    server_hostname: Option<&PreparedServerHostname>,
    server_ip: Option<&IpAddress>,
) -> PolicyEvaluationResult {
    let subject_alt_names = leaf
        .extensions()
        .subject_alt_names()
        .map_err(|error| PolicyFailureReason::new(format!("error parsing SAN field, cert cannot be trusted: {}", error)))?
        .unwrap_or_default();

    let mut checked_match = false;

    for (kind, value) in &subject_alt_names {
        match kind {
            GeneralNameKind::DnsName => {
                checked_match = true;
                if match_hostname(server_hostname, value) {
                    return Ok(());
                }
            }
            GeneralNameKind::IpAddress => {
                checked_match = true;
                if let (Some(server_ip), Some(certificate_ip)) = (server_ip, IpAddress::from_san_bytes(value)) {
                    if match_ip_address(server_ip, &certificate_ip) {
                        return Ok(());
                    }
                }
            }
            _ => continue,
        }
    }

    if checked_match {
        // We had matchable SAN entries, but none of them matched.
        return Err(PolicyFailureReason::new("none of the names in the SAN extension matched"));
    }

    // No matchable subjectAltName entries — fall back to the subject's
    // common name. As distinguished names run least-significant to
    // most-significant, the last commonName attribute is the one that
    // matters.
    let Some(common_name) = leaf.subject().common_name() else {
        return Err(PolicyFailureReason::new("no SAN extension and no common name"));
    };

    if match_hostname(server_hostname, &common_name) {
        Ok(())
    } else {
        Err(PolicyFailureReason::new("common name does not match expected hostname"))
    }
}

fn match_hostname(server_hostname: Option<&PreparedServerHostname>, dns_name: &[u8]) -> bool {
    let Some(server_hostname) = server_hostname else {
        return false;
    };

    let Some(analysed) = AnalysedCertificateHostname::new(dns_name) else {
        return false;
    };

    analysed.valid_match_for_name(server_hostname)
}

fn match_ip_address(server_ip: &IpAddress, certificate_ip: &IpAddress) -> bool {
    server_ip == certificate_ip
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl IpAddress {
    fn parse(s: &str) -> Option<Self> {
        if let Ok(v4) = s.parse::<Ipv4Addr>() {
            return Some(IpAddress::V4(v4));
        }
        if let Ok(v6) = s.parse::<Ipv6Addr>() {
            return Some(IpAddress::V6(v6));
        }
        None
    }

    /// Interprets raw subjectAltName iPAddress bytes: 4 bytes for IPv4, 16
    /// bytes for IPv6, anything else is not a usable address.
    fn from_san_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            4 => {
                let mut octets = [0u8; 4];
                octets.copy_from_slice(bytes);
                Some(IpAddress::V4(Ipv4Addr::from(octets)))
            }
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(bytes);
                Some(IpAddress::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    }
}

/// A server hostname prepared once for repeated matching: lowercased ASCII
/// bytes, with a trailing period stripped and the index of the first period
/// recorded (used to locate the wildcard-eligible first label).
///
/// Preparing this once avoids repeated passes over the hostname: a naive
/// implementation would separately lowercase the string, validate it's
/// ASCII, and find the first period, each requiring its own scan.
#[derive(Debug, Clone)]
struct PreparedServerHostname {
    bytes: Vec<u8>,
    first_period_index: Option<usize>,
}

impl PreparedServerHostname {
    fn new(hostname: &str) -> Option<Self> {
        let mut first_period_index = None;
        let mut value = Vec::with_capacity(hostname.len());

        for &byte in hostname.as_bytes() {
            if !is_valid_dns_character(byte) {
                return None;
            }

            if first_period_index.is_none() && byte == ASCII_PERIOD {
                first_period_index = Some(value.len());
            }

            // Only ASCII printable bytes reach this point, so unconditionally
            // setting bit 5 safely lowercases.
            value.push(byte | 0x20);
        }

        if value.last() == Some(&ASCII_PERIOD) {
            value.pop();
            // A trailing period removed from the very end never invalidates
            // an already-recorded first_period_index, since that index
            // points earlier in the (now shorter) buffer or is unaffected.
        }

        Some(Self {
            bytes: value,
            first_period_index,
        })
    }
}

fn is_valid_dns_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == ASCII_PERIOD
}

/// Splits a byte slice in two around a given index. The byte at `index`
/// itself is dropped (it's the separator, e.g. the period or the
/// wildcard character). `None` splits around the end, giving `(whole, [])`.
fn split_around_index(bytes: &[u8], index: Option<usize>) -> (&[u8], &[u8]) {
    match index {
        None => (bytes, &bytes[bytes.len()..]),
        Some(index) => (&bytes[..index], &bytes[index + 1..]),
    }
}

fn case_insensitive_ascii_match(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(&x, &y)| x.eq_ignore_ascii_case(&y))
}

/// A certificate hostname (from a SAN dNSName entry, or the subject's
/// common name) that has been analysed and prepared for matching.
///
/// A certificate hostname that is valid for matching meets the following
/// criteria:
///
/// 1. Contains only valid DNS characters, plus the ASCII asterisk.
/// 2. Contains zero or one ASCII asterisks.
/// 3. Any ASCII asterisk present must be in the first DNS label (i.e.
///    before the first period).
/// 4. If the first label contains an ASCII asterisk, it must not also be an
///    IDNA A-label (i.e. must not start with "xn--") — this closes off a
///    homograph-style attack where a wildcard could otherwise be combined
///    with a punycode label to visually spoof an unrelated name.
enum AnalysedCertificateHostname<'a> {
    SingleName(&'a [u8]),
    Wildcard {
        base_name: &'a [u8],
        asterisk_index: usize,
        first_period_index: Option<usize>,
    },
}

impl<'a> AnalysedCertificateHostname<'a> {
    fn new(base_name: &'a [u8]) -> Option<Self> {
        let mut base_name = base_name;

        if base_name.last() == Some(&ASCII_PERIOD) {
            base_name = &base_name[..base_name.len() - 1];
        }

        let mut first_period_index = None;
        let mut asterisk_index = None;

        for (index, &byte) in base_name.iter().enumerate() {
            match byte {
                ASCII_PERIOD if first_period_index.is_none() => {
                    first_period_index = Some(index);
                }
                b if is_valid_dns_character(b) => {
                    // Valid character, no notes (this also matches
                    // ASCII_PERIOD on subsequent occurrences, which is fine).
                }
                ASCII_ASTERISK if asterisk_index.is_none() && first_period_index.is_none() => {
                    asterisk_index = Some(index);
                }
                ASCII_ASTERISK => {
                    // An extra asterisk, or an asterisk after a period, is unacceptable.
                    return None;
                }
                _ => {
                    // Unacceptable character in the name.
                    return None;
                }
            }
        }

        if let Some(asterisk_index) = asterisk_index {
            // If we found a wildcard, confirm the first label isn't an IDNA A-label.
            let prefix_len = base_name.len().min(4);
            if case_insensitive_ascii_match(&base_name[..prefix_len], &ASCII_IDNA_IDENTIFIER[..prefix_len]) {
                return None;
            }

            Some(AnalysedCertificateHostname::Wildcard {
                base_name,
                asterisk_index,
                first_period_index,
            })
        } else {
            Some(AnalysedCertificateHostname::SingleName(base_name))
        }
    }

    /// Whether this parsed name is a valid match for the target hostname.
    fn valid_match_for_name(&self, target: &PreparedServerHostname) -> bool {
        match self {
            AnalysedCertificateHostname::SingleName(base_name) => case_insensitive_ascii_match(base_name, &target.bytes),

            AnalysedCertificateHostname::Wildcard {
                base_name,
                asterisk_index,
                first_period_index,
            } => {
                // The wildcard can appear anywhere in the first label, and
                // must match at least one character. We split both names on
                // their first period to get their first label and remaining
                // components; the remaining components must match exactly,
                // and the wildcard label's prefix/suffix (split around the
                // asterisk) must be, respectively, a prefix and suffix of
                // the target's first label.
                let (wildcard_label, remaining_components) = split_around_index(base_name, *first_period_index);
                let (target_first_label, target_remaining_components) = split_around_index(&target.bytes, target.first_period_index);

                if !case_insensitive_ascii_match(remaining_components, target_remaining_components) {
                    return false;
                }

                if target_first_label.len() < wildcard_label.len() {
                    return false;
                }

                let (wildcard_prefix, wildcard_suffix) = split_around_index(wildcard_label, Some(*asterisk_index));
                let target_before_wildcard = &target_first_label[..wildcard_prefix.len()];
                let target_after_wildcard = &target_first_label[target_first_label.len() - wildcard_suffix.len()..];

                case_insensitive_ascii_match(target_before_wildcard, wildcard_prefix)
                    && case_insensitive_ascii_match(target_after_wildcard, wildcard_suffix)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_validator_core::{AuthorityKeyIdentifier, BasicConstraints, NameConstraints, PublicKeyInfoView, SignatureAlgorithmId, SubjectKeyIdentifier, Timestamp};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeName {
        der: Vec<u8>,
        common_name: Option<Vec<u8>>,
    }

    impl NameView for FakeName {
        fn general_names(&self) -> Vec<(GeneralNameKind, Vec<u8>)> {
            vec![]
        }
        fn canonical_der(&self) -> &[u8] {
            &self.der
        }
        fn common_name(&self) -> Option<Vec<u8>> {
            self.common_name.clone()
        }
    }

    #[derive(Debug, Clone, Default)]
    struct FakeExtensions {
        subject_alt_names: Option<Vec<(GeneralNameKind, Vec<u8>)>>,
        error: bool,
    }

    #[derive(Debug)]
    struct FakeError;
    impl std::fmt::Display for FakeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "fake error")
        }
    }
    impl std::error::Error for FakeError {}

    impl ExtensionsView for FakeExtensions {
        type Error = FakeError;

        fn oids(&self) -> Vec<(Oid, bool)> {
            vec![]
        }
        fn bytes_for(&self, _oid: &Oid) -> Option<&[u8]> {
            None
        }
        fn basic_constraints(&self) -> Result<Option<BasicConstraints>, Self::Error> {
            Ok(None)
        }
        fn name_constraints(&self) -> Result<Option<NameConstraints>, Self::Error> {
            Ok(None)
        }
        fn key_usage_present(&self) -> Result<bool, Self::Error> {
            Ok(false)
        }
        fn extended_key_usage_contains_ocsp_signing(&self) -> Result<bool, Self::Error> {
            Ok(false)
        }
        fn subject_alt_names(&self) -> Result<Option<Vec<(GeneralNameKind, Vec<u8>)>>, Self::Error> {
            if self.error {
                Err(FakeError)
            } else {
                Ok(self.subject_alt_names.clone())
            }
        }
        fn authority_key_identifier(&self) -> Result<Option<AuthorityKeyIdentifier>, Self::Error> {
            Ok(None)
        }
        fn subject_key_identifier(&self) -> Result<Option<SubjectKeyIdentifier>, Self::Error> {
            Ok(None)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakePublicKeyInfo(Vec<u8>);

    impl PublicKeyInfoView for FakePublicKeyInfo {
        fn subject_public_key_info_der(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Debug, Clone)]
    struct FakeCertificate {
        subject: FakeName,
        issuer: FakeName,
        extensions: FakeExtensions,
        public_key: FakePublicKeyInfo,
    }

    impl CertificateView for FakeCertificate {
        type Name = FakeName;
        type Extensions = FakeExtensions;
        type PublicKeyInfo = FakePublicKeyInfo;

        fn subject(&self) -> &Self::Name {
            &self.subject
        }
        fn issuer(&self) -> &Self::Name {
            &self.issuer
        }
        fn is_v1(&self) -> bool {
            false
        }
        fn has_extensions(&self) -> bool {
            true
        }
        fn not_before(&self) -> Timestamp {
            0
        }
        fn not_after(&self) -> Timestamp {
            0
        }
        fn extensions(&self) -> &Self::Extensions {
            &self.extensions
        }
        fn public_key_info(&self) -> &Self::PublicKeyInfo {
            &self.public_key
        }
        fn signature_algorithm(&self) -> SignatureAlgorithmId {
            SignatureAlgorithmId::EcdsaP256Sha256
        }
        fn signature(&self) -> &[u8] {
            &[]
        }
        fn tbs_der(&self) -> &[u8] {
            &[]
        }
    }

    fn dns(name: &str) -> (GeneralNameKind, Vec<u8>) {
        (GeneralNameKind::DnsName, name.as_bytes().to_vec())
    }

    fn ip(bytes: Vec<u8>) -> (GeneralNameKind, Vec<u8>) {
        (GeneralNameKind::IpAddress, bytes)
    }

    fn cert_with_sans(sans: Vec<(GeneralNameKind, Vec<u8>)>) -> FakeCertificate {
        FakeCertificate {
            subject: FakeName { der: b"leaf".to_vec(), common_name: None },
            issuer: FakeName { der: b"issuer".to_vec(), common_name: None },
            extensions: FakeExtensions {
                subject_alt_names: Some(sans),
                error: false,
            },
            public_key: FakePublicKeyInfo(b"key".to_vec()),
        }
    }

    fn cert_with_common_name(cn: &str) -> FakeCertificate {
        FakeCertificate {
            subject: FakeName {
                der: b"leaf".to_vec(),
                common_name: Some(cn.as_bytes().to_vec()),
            },
            issuer: FakeName { der: b"issuer".to_vec(), common_name: None },
            extensions: FakeExtensions {
                subject_alt_names: None,
                error: false,
            },
            public_key: FakePublicKeyInfo(b"key".to_vec()),
        }
    }

    fn chain_of(cert: FakeCertificate) -> UnverifiedCertificateChain<FakeCertificate> {
        UnverifiedCertificateChain::new(vec![cert])
    }

    #[test]
    fn exact_dns_name_match_is_accepted() {
        let chain = chain_of(cert_with_sans(vec![dns("www.example.com")]));
        let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn dns_name_match_is_case_insensitive() {
        let chain = chain_of(cert_with_sans(vec![dns("WWW.EXAMPLE.COM")]));
        let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn dns_name_match_tolerates_trailing_period() {
        let chain = chain_of(cert_with_sans(vec![dns("www.example.com")]));
        let mut policy = ServerIdentityPolicy::new(Some("www.example.com."), None);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn non_matching_dns_name_is_rejected() {
        let chain = chain_of(cert_with_sans(vec![dns("www.example.com")]));
        let mut policy = ServerIdentityPolicy::new(Some("evil.com"), None);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn wildcard_matches_single_label() {
        let chain = chain_of(cert_with_sans(vec![dns("*.example.com")]));
        let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn wildcard_does_not_match_multiple_labels() {
        let chain = chain_of(cert_with_sans(vec![dns("*.example.com")]));
        let mut policy = ServerIdentityPolicy::new(Some("foo.bar.example.com"), None);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn wildcard_must_match_at_least_one_character() {
        let chain = chain_of(cert_with_sans(vec![dns("*.example.com")]));
        let mut policy = ServerIdentityPolicy::new(Some(".example.com"), None);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn partial_wildcard_matches_prefix_and_suffix() {
        let chain = chain_of(cert_with_sans(vec![dns("f*o.example.com")]));
        let mut policy = ServerIdentityPolicy::new(Some("foo.example.com"), None);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn wildcard_after_first_label_is_rejected() {
        // "www.*.com" has the asterisk after the first period — invalid.
        let chain = chain_of(cert_with_sans(vec![dns("www.*.com")]));
        let mut policy = ServerIdentityPolicy::new(Some("www.anything.com"), None);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn wildcard_combined_with_idna_a_label_is_rejected() {
        // "xn--*.example.com" pairs a wildcard with a punycode-looking
        // first label; this must never validate, closing the homograph
        // attack the IDNA check exists to prevent.
        let chain = chain_of(cert_with_sans(vec![dns("xn--*.example.com")]));
        let mut policy = ServerIdentityPolicy::new(Some("xn--anything.example.com"), None);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn ipv4_san_matches_server_ip() {
        let chain = chain_of(cert_with_sans(vec![ip(vec![127, 0, 0, 1])]));
        let mut policy = ServerIdentityPolicy::new(None, Some("127.0.0.1"));
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn ipv4_san_does_not_match_different_server_ip() {
        let chain = chain_of(cert_with_sans(vec![ip(vec![127, 0, 0, 1])]));
        let mut policy = ServerIdentityPolicy::new(None, Some("127.0.0.2"));
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn ipv6_san_matches_server_ip() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let chain = chain_of(cert_with_sans(vec![ip(addr.octets().to_vec())]));
        let mut policy = ServerIdentityPolicy::new(None, Some("2001:db8::1"));
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn san_present_but_no_match_never_falls_back_to_common_name() {
        // Even though the common name would match, having a (non-matching)
        // SAN extension present must suppress the CN fallback entirely.
        let mut cert = cert_with_sans(vec![dns("other.example.com")]);
        cert.subject.common_name = Some(b"www.example.com".to_vec());
        let chain = chain_of(cert);
        let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn no_san_falls_back_to_common_name() {
        let chain = chain_of(cert_with_common_name("www.example.com"));
        let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn no_san_and_no_common_name_is_rejected() {
        let cert = FakeCertificate {
            subject: FakeName { der: b"leaf".to_vec(), common_name: None },
            issuer: FakeName { der: b"issuer".to_vec(), common_name: None },
            extensions: FakeExtensions { subject_alt_names: None, error: false },
            public_key: FakePublicKeyInfo(b"key".to_vec()),
        };
        let chain = chain_of(cert);
        let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn common_name_is_never_matched_against_an_ip_address() {
        let chain = chain_of(cert_with_common_name("127.0.0.1"));
        let mut policy = ServerIdentityPolicy::new(None, Some("127.0.0.1"));
        // No hostname supplied, only an IP — the CN path only ever compares
        // against a hostname, never an IP, so this must fail even though
        // the CN textually equals the target IP.
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn error_parsing_san_extension_fails_closed() {
        let cert = FakeCertificate {
            subject: FakeName { der: b"leaf".to_vec(), common_name: None },
            issuer: FakeName { der: b"issuer".to_vec(), common_name: None },
            extensions: FakeExtensions { subject_alt_names: None, error: true },
            public_key: FakePublicKeyInfo(b"key".to_vec()),
        };
        let chain = chain_of(cert);
        let mut policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn no_server_hostname_never_matches_dns_san() {
        let chain = chain_of(cert_with_sans(vec![dns("www.example.com")]));
        let mut policy = ServerIdentityPolicy::new(None, None);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn verifying_critical_extensions_includes_subject_alt_name_oid() {
        let policy = ServerIdentityPolicy::new(Some("www.example.com"), None);
        let oids = <ServerIdentityPolicy as VerifierPolicy<FakeCertificate>>::verifying_critical_extensions(&policy);
        assert!(oids.contains(&subject_alt_name_oid()));
    }
}

