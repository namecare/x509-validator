use crate::rfc5280::name_constraints_policy::NameConstraintsPolicy;

const ASCII_PERIOD: u8 = b'.';
const ASCII_ASTERISK: u8 = b'*';
const ASCII_HYPHEN: u8 = b'-';

const MAXIMUM_LABEL_LENGTH: usize = 63;
const MAXIMUM_NAME_LENGTH: usize = 253;

impl NameConstraintsPolicy {
    /// Validates that a dnsName matches a name constraint.
    ///
    /// From RFC 5280 §4.2.1.10:
    ///
    ///    DNS name restrictions are expressed as host.example.com.  Any DNS
    ///    name that can be constructed by simply adding zero or more labels to
    ///    the left-hand side of the name satisfies the name constraint.  For
    ///    example, www.host.example.com would satisfy the constraint but
    ///    host1.example.com would not.
    pub(crate) fn dns_name_matches_constraint(dns_name: &[u8], constraint: &[u8]) -> bool {
        if !is_valid_dns_name(dns_name, false) || !is_valid_dns_name(constraint, true) {
            return false;
        }

        // The empty constraint matches everything.
        if constraint.is_empty() {
            return true;
        }

        // Drop a trailing period from the constraint, if present.
        let mut constraint = constraint;
        if constraint.last() == Some(&ASCII_PERIOD) {
            constraint = &constraint[..constraint.len() - 1];
        }

        let mut dns_labels = ReverseDnsLabels::new(dns_name);
        let mut constraint_labels = ReverseDnsLabels::new(constraint);

        loop {
            let next_dns_label = dns_labels.next();
            let next_constraint_label = constraint_labels.next();

            match (next_dns_label, next_constraint_label) {
                (None, None) => return true,
                (Some(_), None) => return true,
                (None, Some(_)) => return false,
                (Some([]), _) => return false,
                (Some(_), Some([])) => {
                    // An empty constraint label (i.e. a leading period) must
                    // be the last one.
                    return !constraint_labels.has_more_labels();
                }
                (Some(dns_label), Some(constraint_label)) => {
                    if !case_insensitive_ascii_match(dns_label, constraint_label) {
                        return false;
                    }
                }
            }
        }
    }
}

/// Whether this is a valid DNS name for constraint matching purposes:
/// only ASCII letters/digits/hyphen/period, at most one wildcard as the
/// entire first label, at most 253 bytes total, at most 63 bytes per label,
/// no empty labels (except a leading empty label in a constraint, which
/// represents ".example.com"-style subdomain matching), no label starting
/// or ending with a hyphen, and the most significant label not entirely
/// numeric.
fn is_valid_dns_name(name: &[u8], is_constraint: bool) -> bool {
    if name.len() > MAXIMUM_NAME_LENGTH {
        return false;
    }

    let mut bytes = name;
    let mut label_count = 0usize;
    let mut is_wildcard = false;

    if bytes.first() == Some(&ASCII_ASTERISK) {
        bytes = &bytes[1..];
        match bytes.first() {
            Some(&ASCII_PERIOD) => {
                bytes = &bytes[1..];
            }
            _ => return false,
        }
        label_count += 1;
        is_wildcard = true;
    }

    while !bytes.is_empty() {
        let label: &[u8];
        if let Some(period_index) = bytes.iter().position(|&b| b == ASCII_PERIOD) {
            label = &bytes[..period_index];
            bytes = &bytes[period_index + 1..];
        } else {
            label = bytes;
            bytes = &[];
        }

        label_count += 1;

        if label.is_empty() && !(label_count == 1 && is_constraint) {
            return false;
        }

        if label.first() == Some(&ASCII_HYPHEN) || label.last() == Some(&ASCII_HYPHEN) {
            return false;
        }

        if label.len() > MAXIMUM_LABEL_LENGTH {
            return false;
        }

        match label_contents(label) {
            LabelContents::NonAscii => return false,
            LabelContents::AllAscii { non_numerics } => {
                if non_numerics == 0 && bytes.is_empty() {
                    // Last label is entirely numeric. Not allowed.
                    return false;
                }
            }
        }
    }

    // For wildcards, require at least two labels after the wildcard.
    if is_wildcard && label_count < 3 {
        return false;
    }

    true
}

enum LabelContents {
    AllAscii { non_numerics: usize },
    NonAscii,
}

fn label_contents(label: &[u8]) -> LabelContents {
    let mut non_numerics = 0;

    for &byte in label {
        match byte {
            b'0'..=b'9' => {}
            b'a'..=b'z' | b'A'..=b'Z' | b'-' | b'_' => non_numerics += 1,
            _ => return LabelContents::NonAscii,
        }
    }

    LabelContents::AllAscii { non_numerics }
}

fn case_insensitive_ascii_match(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    const MASK: u8 = !(1 << 5);
    a.iter().zip(b.iter()).all(|(&x, &y)| (x & MASK) == (y & MASK))
}

/// Iterates a DNS name's labels from right to left (most significant label
/// last, matching how name constraints anchor to the right-hand side of the
/// name).
struct ReverseDnsLabels<'a> {
    remaining: Option<&'a [u8]>,
}

impl<'a> ReverseDnsLabels<'a> {
    fn new(name: &'a [u8]) -> Self {
        Self { remaining: Some(name) }
    }

    fn has_more_labels(&self) -> bool {
        self.remaining.is_some()
    }
}

impl<'a> Iterator for ReverseDnsLabels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let base = self.remaining?;

        match base.iter().rposition(|&b| b == ASCII_PERIOD) {
            Some(period_index) => {
                let label = &base[period_index + 1..];
                self.remaining = Some(&base[..period_index]);
                Some(label)
            }
            None => {
                self.remaining = None;
                Some(base)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(dns_name: &str, constraint: &str) -> bool {
        NameConstraintsPolicy::dns_name_matches_constraint(dns_name.as_bytes(), constraint.as_bytes())
    }

    #[test]
    fn exact_match() {
        assert!(matches("example.com", "example.com"));
    }

    #[test]
    fn subdomain_satisfies_constraint() {
        assert!(matches("www.host.example.com", "host.example.com"));
    }

    #[test]
    fn sibling_label_does_not_satisfy_constraint() {
        assert!(!matches("host1.example.com", "host.example.com"));
    }

    #[test]
    fn different_domain_does_not_match() {
        assert!(!matches("www.evil.com", "example.com"));
    }

    #[test]
    fn empty_constraint_matches_everything() {
        assert!(matches("anything.example.org", ""));
    }

    #[test]
    fn leading_period_constraint_matches_subdomains_but_not_bare_domain() {
        assert!(matches("host.example.com", ".example.com"));
        assert!(!matches("example.com", ".example.com"));
    }

    #[test]
    fn constraint_with_trailing_period_matches() {
        assert!(matches("example.com", "example.com."));
    }

    #[test]
    fn case_insensitive_match() {
        assert!(matches("WWW.Example.COM", "example.com"));
    }

    #[test]
    fn empty_label_in_dns_name_is_invalid() {
        assert!(!matches("www..example.com", "example.com"));
    }

    #[test]
    fn label_starting_with_hyphen_is_invalid() {
        assert!(!matches("-www.example.com", "example.com"));
    }

    #[test]
    fn all_numeric_final_label_is_invalid() {
        assert!(!matches("www.example.123", "123"));
    }

    #[test]
    fn wildcard_constraint_requires_at_least_two_trailing_labels() {
        // "*.com" is not a valid constraint (wildcard + only one label after).
        assert!(!matches("foo.com", "*.com"));
    }
}
