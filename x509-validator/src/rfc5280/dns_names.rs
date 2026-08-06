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
pub(crate) mod fixtures {
    /// A conformance corpus of `(dns_name, constraint, expected_match)` rows,
    /// adapted from the webpki and Chromium name-matching conformance suites.
    ///
    /// The same corpus is reused by the URI constraint tests, which wrap each
    /// `dns_name` in a variety of URI shapes and assert the host part behaves
    /// identically.
    pub(crate) fn name_matching_fixtures() -> Vec<(String, String, bool)> {
        // 31 repetitions of "example" joined by "." plus ".com.au" is exactly
        // 254 bytes: (7 * 31) + 30 + 7, one byte over the 253-byte limit.
        let long_domain = {
            let mut s = vec!["example"; 31].join(".");
            s.push_str(".com.au");
            s
        };
        let label_63 = "a".repeat(63);
        let label_64 = "a".repeat(64);

        let borrowed: &[(&str, &str, bool)] = &[
            ("", "a", false),
            ("a", "a", true),
            ("b", "a", false),
            ("*.b.a", "c.b.a", false),
            ("*.b.a", "b.a", true),
            ("*.b.a", "b.a.", true),
            // Wildcard not in leftmost label
            ("d.c.b.a", "d.c.b.a", true),
            ("d.*.b.a", "d.c.b.a", false),
            ("d.c*.b.a", "d.c.b.a", false),
            ("d.c*.b.a", "d.cc.b.a", false),
            // Case sensitivity
            ("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", true),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", true),
            ("aBc", "Abc", true),
            // Digits
            ("a1", "a1", true),
            // A trailing dot indicates an absolute name, and absolute names can
            // match relative names, and vice-versa.
            ("example", "example", true),
            ("example.", "example.", false),
            ("example", "example.", true),
            ("example.", "example", false),
            ("example.com", "example.com", true),
            ("example.com.", "example.com.", false),
            ("example.com", "example.com.", true),
            ("example.com.", "example.com", false),
            ("example.com..", "example.com.", false),
            ("example.com..", "example.com", false),
            ("example.com...", "example.com.", false),
            // xn-- IDN prefix
            ("x*.b.a", "xa.b.a", false),
            ("x*.b.a", "xna.b.a", false),
            ("x*.b.a", "xn-a.b.a", false),
            ("x*.b.a", "xn--a.b.a", false),
            ("xn*.b.a", "xn--a.b.a", false),
            ("xn-*.b.a", "xn--a.b.a", false),
            ("xn--*.b.a", "xn--a.b.a", false),
            ("xn*.b.a", "xn--a.b.a", false),
            ("xn-*.b.a", "xn--a.b.a", false),
            ("xn--*.b.a", "xn--a.b.a", false),
            ("xn---*.b.a", "xn--a.b.a", false),
            // "*" cannot expand to nothing.
            ("c*.b.a", "c.b.a", false),
            // ---------------------------------------------------------------
            // The rest are adapted from the Chromium certificate name-matching
            // tests, with the parameter order flipped to match this crate's
            // signature and a few cases adjusted for intentional behavioural
            // differences.
            ("foo.com", "foo.com", true),
            ("f", "f", true),
            ("i", "h", false),
            ("*.foo.com", "bar.foo.com", false),
            ("*.test.fr", "www.test.fr", false),
            ("*.test.FR", "wwW.tESt.fr", false),
            (".uk", "f.uk", false),
            ("?.bar.foo.com", "w.bar.foo.com", false),
            ("(www|ftp).foo.com", "www.foo.com", false), // regex!
            ("www.foo.com\0", "www.foo.com", false),
            ("www.foo.com\0*.foo.com", "www.foo.com", false),
            ("ww.house.example", "www.house.example", false),
            ("www.test.org", "test.org", true),
            ("*.test.org", "test.org", true),
            ("*.org", "test.org", false),
            // '*' must be the only character in the wildcard label
            ("w*.bar.foo.com", ".bar.foo.com", false),
            ("ww*ww.bar.foo.com", ".bar.foo.com", false),
            ("ww*ww.bar.foo.com", ".bar.foo.com", false),
            ("w*w.bar.foo.com", ".bar.foo.com", false),
            ("w*w.bar.foo.c0m", ".bar.foo.com", false),
            ("wa*.bar.foo.com", ".bar.foo.com", false),
            ("*Ly.bar.foo.com", ".bar.foo.com", false),
            ("*.test.de", "www.test.co.jp", false),
            ("*.jp", "www.test.co.jp", false),
            ("www.test.co.uk", "www.test.co.jp", false),
            ("www.*.co.jp", "www.test.co.jp", false),
            ("www.bar.foo.com", "www.bar.foo.com", true),
            ("*.foo.com", "www.bar.foo.com", false),
            ("*.*.foo.com", "www.bar.foo.com", false),
            ("www.bath.org", "www.bath.org", true),
            // IDN tests
            ("xn--poema-9qae5a.com.br", "xn--poema-9qae5a.com.br", true),
            ("*.xn--poema-9qae5a.com.br", "www.xn--poema-9qae5a.com.br", false),
            ("*.xn--poema-9qae5a.com.br", "xn--poema-9qae5a.com.br", true),
            ("xn--poema-*.com.br", "xn--poema-9qae5a.com.br", false),
            ("xn--*-9qae5a.com.br", "xn--poema-9qae5a.com.br", false),
            ("*--poema-9qae5a.com.br", "xn--poema-9qae5a.com.br", false),
            // Adapted from the examples in RFC 6125 §6.4.3: *.example.com would
            // match foo.example.com but not bar.foo.example.com or example.com.
            ("*.example.com", "foo.example.com", false),
            ("*.example.com", "bar.foo.example.com", false),
            ("*.example.com", "example.com", true),
            ("baz*.example.net", "baz1.example.net", false),
            ("*baz.example.net", "foobaz.example.net", false),
            ("b*z.example.net", "buzz.example.net", false),
            // Wildcards should not be valid for public registry controlled
            // domains, and for unknown/unrecognised domains at least three
            // domain components must be present: there must always be at least
            // two labels after the wildcard label.
            ("*.test.example", ".test.example", true),
            ("*.example.co.uk", ".example.co.uk", true),
            ("*.example", ".example", false),
            // The result differs from Chromium's, because Chromium takes into
            // account the additional knowledge that "co.uk" is a TLD. We do not
            // consult a public suffix list.
            ("*.co.uk", ".co.uk", true),
            ("*.com", ".com", false),
            ("*.us", ".us", false),
            ("*", "foo", false),
            // IDN variants of wildcards and registry controlled domains.
            ("*.xn--poema-9qae5a.com.br", ".xn--poema-9qae5a.com.br", true),
            ("*.example.xn--mgbaam7a8h", ".example.xn--mgbaam7a8h", true),
            ("*.xn--mgbaam7a8h", ".xn--mgbaam7a8h", false),
            // Wildcards should be permissible for 'private' registry-controlled
            // domains. (We do not know whether a domain is a private
            // registry-controlled domain or not.)
            ("*.appspot.com", ".appspot.com", true),
            ("*.s3.amazonaws.com", ".s3.amazonaws.com", true),
            // Multiple wildcards are not valid.
            ("*.*.com", ".com", false),
            ("*.bar.*.com", ".com", false),
            // Absolute vs relative DNS name tests. Although not explicitly
            // specified in RFC 6125, absolute reference names (those ending in
            // a ".") should match either absolute or relative presented names.
            ("foo.com.", "foo.com", false),
            ("foo.com", "foo.com.", true),
            ("foo.com.", "foo.com.", false),
            ("f.", "f", false),
            ("f", "f.", true),
            ("f.", "f.", false),
            ("*.bar.foo.com.", ".bar.foo.com", false),
            ("*.bar.foo.com", ".bar.foo.com.", true),
            ("*.bar.foo.com.", ".bar.foo.com.", false),
            ("*.com.", "example.com", false),
            ("*.com", "example.com.", false),
            ("*.com.", "example.com.", false),
            ("*.", "foo.", false),
            ("*.", "foo", false),
            // The result differs from Chromium's because we don't know that
            // co.uk is a TLD.
            ("*.co.uk.", "foo.co.uk", false),
            ("*.co.uk.", "foo.co.uk.", false),
            // Empty constraint matches everything
            ("example.com", "", true),
            ("*.foo.example.com", "", true),
            // Longer constraint doesn't match.
            ("example.com", "foo.example.com", false),
            // No hyphens beginning or ending labels
            ("-.example.com", "example.com", false),
            ("foo.-bar.example.com", "example.com", false),
            ("foo-.example.com", "example.com", false),
            ("foo-bar.example.com", "example.com", true),
            ("foo.-example.com", "-example.com", false),
            ("foo.-bar.example.com", "foo.-bar.example.com", false),
            ("foo.bar-.example.com", "foo.bar-.example.com", false),
            ("foo-bar.example.com", "foo-bar.example.com", true),
            // All numeric labels
            ("1234567.example.com", "example.com", true),
            ("foo.1234567.example.com", "foo.1234567.example.com", true),
            ("foo.example.123", "foo.example.123", false),
            // Trailing period doesn't always match
            ("foo.com", "example.bar.", false),
            ("foo.com", "foo.www.", false),
        ];

        let mut fixtures: Vec<(String, String, bool)> = borrowed
            .iter()
            .map(|&(dns_name, constraint, expected)| {
                (dns_name.to_string(), constraint.to_string(), expected)
            })
            .collect();

        // Long domains: 254 bytes exceeds the 253-byte name limit, so neither
        // side is a valid name.
        fixtures.push((long_domain.clone(), ".example.com.au".to_string(), false));
        fixtures.push(("example.com.au".to_string(), long_domain, false));

        // Long labels: 63 bytes is the maximum, 64 is one too many.
        fixtures.push((format!("{label_63}.example.com"), "example.com".to_string(), true));
        fixtures.push((format!("{label_64}.example.com"), "example.com".to_string(), false));
        fixtures.push((
            format!("{label_63}.example.com"),
            format!("{label_63}.example.com"),
            true,
        ));
        fixtures.push((
            format!("{label_64}.example.com"),
            format!("{label_64}.example.com"),
            false,
        ));

        fixtures
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::name_matching_fixtures;
    use super::*;

    #[test]
    fn name_matches_reference_corpus() {
        for (dns_name, constraint, expected) in name_matching_fixtures() {
            let actual = NameConstraintsPolicy::dns_name_matches_constraint(
                dns_name.as_bytes(),
                constraint.as_bytes(),
            );
            assert_eq!(
                expected, actual,
                "expected dns name {dns_name:?} matching constraint {constraint:?} to be {expected}"
            );
        }
    }

    #[test]
    fn reverse_dns_labels_iterates_right_to_left() {
        fn reverse(name: &str) -> Vec<&[u8]> {
            ReverseDnsLabels::new(name.as_bytes()).collect()
        }

        assert_eq!(reverse("f."), vec![&b""[..], &b"f"[..]]);
        assert_eq!(
            reverse("www-3.example.com"),
            vec![&b"com"[..], &b"example"[..], &b"www-3"[..]]
        );
        assert_eq!(
            reverse("f....y."),
            vec![&b""[..], &b"y"[..], &b""[..], &b""[..], &b""[..], &b"f"[..]]
        );
        assert_eq!(
            reverse(".example.com"),
            vec![&b"com"[..], &b"example"[..], &b""[..]]
        );
    }

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
