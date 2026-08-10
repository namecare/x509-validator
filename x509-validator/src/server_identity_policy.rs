use core::net::{Ipv4Addr, Ipv6Addr};

use crate::der_parser::Oid;
use crate::extensions::GeneralName;
use crate::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME;
use crate::policy::{PolicyEvaluationResult, ValidationPolicy};
use crate::unverified_chain::UnverifiedCertificateChain;
use crate::{Certificate, PolicyFailureReason};

const ASCII_PERIOD: u8 = b'.';
const ASCII_ASTERISK: u8 = b'*';
const ASCII_IDNA_IDENTIFIER: &[u8] = b"xn--";

/// A [`ValidationPolicy`] that checks whether the leaf certificate is authoritative
/// for a given hostname or IP address.
///
/// This policy is most commonly used to validate the leaf certificate presented by a server
/// during a TLS handshake.
///
/// This policy implements the logic for service validation as specified by
/// RFC 6125 (<https://tools.ietf.org/search/rfc6125>), which loosely speaking
/// defines the common algorithm used for validating that an X.509 certificate
/// is valid for a given service
pub struct ServerIdentityPolicy {
    server_hostname: Option<PreparedServerHostname>,
    server_ip: Option<IpAddress>,
}

impl ServerIdentityPolicy {
    /// Constructs a new [`ServerIdentityPolicy`].
    ///
    /// - Parameters:
    ///     - server_hostname: The hostname used to connect to the server.
    ///     - server_ip: The IP address of the server, if known.
    pub fn new(server_hostname: Option<&str>, server_ip: Option<&str>) -> Self {
        Self {
            server_hostname: server_hostname.and_then(PreparedServerHostname::new),
            server_ip: server_ip.and_then(IpAddress::parse),
        }
    }
}

/// id-ce-subjectAltName, RFC 5280 §4.2.1.6: 2.5.29.17.
fn subject_alt_name_oid() -> Oid<'static> {
    OID_X509_EXT_SUBJECT_ALT_NAME
}

impl ValidationPolicy for ServerIdentityPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![subject_alt_name_oid()]
    }

    fn chain_meets_policy_requirements(
        &self,
        chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        // We only validate the leaf node in this policy.
        has_valid_identity_for_service(
            chain.leaf(),
            self.server_hostname.as_ref(),
            self.server_ip.as_ref(),
        )
    }
}

/// Validates that a given leaf certificate is valid for a service.
///
/// This function implements the logic for service validation as specified by
/// RFC 6125 (<https://tools.ietf.org/search/rfc6125>), which loosely speaking
/// defines the common algorithm used for validating that an X.509 certificate
/// is valid for a given service
///
/// The algorithm we're implementing is specified in RFC 6125 Section 6 if you want to
/// follow along at home.
fn has_valid_identity_for_service(
    leaf: &Certificate<'_>,
    server_hostname: Option<&PreparedServerHostname>,
    server_ip: Option<&IpAddress>,
) -> PolicyEvaluationResult {
    // We want to begin by checking the subjectAlternativeName fields. If there are any fields
    // in there that we could validate against (either IP or hostname) we will validate against
    // them, and then refuse to check the commonName field. If there are no SAN fields to
    // validate against, we'll check commonName.
    //
    // If the SAN field is invalid and we can't parse it, we fail.
    let subject_alt_names = leaf
        .tbs_certificate
        .subject_alternative_name()
        .map_err(|error| {
            PolicyFailureReason::new(format!(
                "error parsing SAN field, cert cannot be trusted: {}",
                error
            ))
        })?
        .map(|ext| ext.value.general_names.clone())
        .unwrap_or_default();

    let mut checked_match = false;

    for name in &subject_alt_names {
        checked_match = true;

        match name {
            GeneralName::DNSName(value) => {
                if match_hostname(server_hostname, value.as_bytes()) {
                    return Ok(());
                }
            }
            GeneralName::IPAddress(value) => {
                if let (Some(server_ip), Some(certificate_ip)) =
                    (server_ip, IpAddress::from_san_bytes(value))
                {
                    if match_ip_address(server_ip, &certificate_ip) {
                        return Ok(());
                    }
                }
            }
            _ => continue,
        }
    }

    if checked_match {
        // We had some subject alternative names, but none matched. We failed here.
        return Err(PolicyFailureReason::new(
            "none of the names in the SAN extension matched",
        ));
    }

    // In the absence of any matchable subjectAlternativeNames, we can fall back to checking
    // the common name. This is a deprecated practice, and in a future release we should
    // stop doing this.
    //
    // As distinguished names move from least significant to most significant, we actually
    // want the _last_ CN value.
    let Some(common_name) = leaf
        .subject()
        .iter_common_name()
        .last()
        .and_then(|cn| cn.as_str().ok())
    else {
        // No CN, no match.
        return Err(PolicyFailureReason::new(
            "no SAN extension and no common name",
        ));
    };

    // We have a common name. Let's check it against the provided hostname. We never check
    // the common name against the IP address.
    if match_hostname(server_hostname, common_name.as_bytes()) {
        Ok(())
    } else {
        Err(PolicyFailureReason::new(
            "common name does not match expected hostname",
        ))
    }
}

fn match_hostname(server_hostname: Option<&PreparedServerHostname>, dns_name: &[u8]) -> bool {
    let Some(server_hostname) = server_hostname else {
        // No server hostname was provided, so we cannot match.
        return false;
    };

    // Now we validate the cert hostname.
    let Some(analysed) = AnalysedCertificateHostname::new(dns_name) else {
        // This is a hostname we can't match, return false.
        return false;
    };

    analysed.valid_match_for_name(server_hostname)
}

fn match_ip_address(server_ip: &IpAddress, certificate_ip: &IpAddress) -> bool {
    // These match if the two underlying IP address structures match. Different protocol
    // families are never a match.
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
            return Some(Self::V4(v4));
        }
        if let Ok(v6) = s.parse::<Ipv6Addr>() {
            return Some(Self::V6(v6));
        }
        None
    }

    /// Creates an [`IpAddress`] from the raw bytes of a subjectAltName iPAddress field:
    /// 4 bytes for IPv4, 16 bytes for IPv6, anything else is not a usable address.
    fn from_san_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            4 => {
                let mut octets = [0u8; 4];
                octets.copy_from_slice(bytes);
                Some(Self::V4(Ipv4Addr::from(octets)))
            }
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(bytes);
                Some(Self::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    }
}

/// Creates a [`PreparedServerHostname`].
///
/// This consists of a non-NULL-terminated sequence of ASCII bytes and the index of the
/// first period in that hostname.
///
/// If the string this is called with contains non-ASCII code points, this constructor fails.
///
/// This constructor exists to avoid doing repeated loops over the string buffer.
/// In a naive implementation we'd loop at least four times: once to lowercase
/// the string, once to get a buffer pointer to a contiguous buffer, once
/// to confirm the string is ASCII, and once to find the first period for matching wildcards.
/// Here we can do that all in one loop.
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

            // We know we have only ASCII printables, we can safely unconditionally set the 6 bit to 1 to lowercase.
            value.push(byte | 0x20);
        }

        // Strip trailing period.
        if value.last() == Some(&ASCII_PERIOD) {
            value.pop();
        }

        // The index was recorded before the trailing period was stripped, so it may now point at
        // or past the end: a hostname of "." leaves an empty buffer still claiming a period at 0.
        // Splitting around an index that is no longer inside the buffer would panic, and a period
        // that is no longer present is not a label separator, so drop it.
        if first_period_index.is_some_and(|index| index >= value.len()) {
            first_period_index = None;
        }

        Some(Self {
            bytes: value,
            first_period_index,
        })
    }
}

/// Whether this character is a valid DNS character, which is the ASCII
/// letters, digits, the hyphen, and the period.
fn is_valid_dns_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == ASCII_PERIOD
}

/// Splits a byte slice in two around a given index. This index may be `None`, in which case the split
/// will occur around the end.
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
    a.iter()
        .zip(b.iter())
        .all(|(&x, &y)| x.eq_ignore_ascii_case(&y))
}

/// This type contains a certificate hostname that has been analysed and prepared for matching.
///
/// A certificate hostname that is valid for matching meets the following criteria:
///
/// 1. Contains only valid DNS characters, plus the ASCII asterisk.
/// 2. Contains zero or one ASCII asterisks.
/// 3. Any ASCII asterisk present must be in the first DNS label (i.e. before the first period).
/// 4. If the first label contains an ASCII asterisk, it must not also be an IDN A label.
///
/// Answering these questions potentially relies on multiple searches through the hostname. That's not
/// ideal: it'd be better to do a single search that both validates the domain name meets the criteria
/// and that also records information needed to validate that the name matches the one we're searching for.
/// That's what this type does.
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

        // First, strip a trailing period from this name.
        if base_name.last() == Some(&ASCII_PERIOD) {
            base_name = &base_name[..base_name.len() - 1];
        }

        // Ok, start looping.
        let mut first_period_index = None;
        let mut asterisk_index = None;

        for (index, &byte) in base_name.iter().enumerate() {
            match byte {
                ASCII_PERIOD if first_period_index.is_none() => {
                    // This is the first period we've seen, great. Future
                    // periods will be ignored.
                    first_period_index = Some(index);
                }
                b if is_valid_dns_character(b) => {
                    // Valid character, no notes.
                }
                ASCII_ASTERISK if asterisk_index.is_none() && first_period_index.is_none() => {
                    // Found an asterisk, it's the first one, and it precedes any periods.
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

        // Now we can finally initialize ourself.
        if let Some(asterisk_index) = asterisk_index {
            // One final check: if we found a wildcard, we need to confirm that the first label isn't an IDNA A label.
            let prefix_len = base_name.len().min(4);
            if case_insensitive_ascii_match(
                &base_name[..prefix_len],
                &ASCII_IDNA_IDENTIFIER[..prefix_len],
            ) {
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

    /// Whether this parsed name is a valid match for the one passed in.
    fn valid_match_for_name(&self, target: &PreparedServerHostname) -> bool {
        match self {
            // For non-wildcard names, we just do a straightforward comparison.
            AnalysedCertificateHostname::SingleName(base_name) => {
                case_insensitive_ascii_match(base_name, &target.bytes)
            }

            AnalysedCertificateHostname::Wildcard {
                base_name,
                asterisk_index,
                first_period_index,
            } => {
                // The wildcard can appear more-or-less anywhere in the first label. The wildcard
                // character itself can match any number of characters, though it must match at least
                // one.
                // The algorithm for this is simple: first, we split the two names on their first period to get their
                // first label and their subsequent components. Second, we check that the subcomponents match a straightforward
                // bytewise comparison: if that fails, we can avoid the expensive wildcard checking operation.
                // Third, we split the wildcard label on the wildcard character, and and confirm that
                // the characters *before* the wildcard are the prefix of the target first label, and that the
                // characters *after* the wildcard are the suffix of the target first label. This works well because
                // the empty string is a prefix and suffix of all strings.
                let (wildcard_label, remaining_components) =
                    split_around_index(base_name, *first_period_index);
                let (target_first_label, target_remaining_components) =
                    split_around_index(&target.bytes, target.first_period_index);

                if !case_insensitive_ascii_match(remaining_components, target_remaining_components)
                {
                    // Wildcard is irrelevant, the remaining components don't match.
                    return false;
                }

                if target_first_label.len() < wildcard_label.len() {
                    // The target label cannot possibly match the wildcard.
                    return false;
                }

                let (wildcard_prefix, wildcard_suffix) =
                    split_around_index(wildcard_label, Some(*asterisk_index));
                let target_before_wildcard = &target_first_label[..wildcard_prefix.len()];
                let target_after_wildcard =
                    &target_first_label[target_first_label.len() - wildcard_suffix.len()..];

                case_insensitive_ascii_match(target_before_wildcard, wildcard_prefix)
                    && case_insensitive_ascii_match(target_after_wildcard, wildcard_suffix)
            }
        }
    }
}
