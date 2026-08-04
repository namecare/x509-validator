use crate::rfc5280::name_constraints_policy::NameConstraintsPolicy;

impl NameConstraintsPolicy {
    /// Validates that a URI name matches a name constraint.
    ///
    /// From RFC 5280:
    ///
    ///    For URIs, the constraint applies to the host part of the name.  The
    ///    constraint MUST be specified as a fully qualified domain name and MAY
    ///    specify a host or a domain.  Examples would be "host.example.com" and
    ///    ".example.com".  When the constraint begins with a period, it MAY be
    ///    expanded with one or more labels.  That is, the constraint
    ///    ".example.com" is satisfied by both host.example.com and
    ///    my.host.example.com.  However, the constraint ".example.com" is not
    ///    satisfied by "example.com".  When the constraint does not begin with
    ///    a period, it specifies a host.  If a constraint is applied to the
    ///    uniformResourceIdentifier name form and a subsequent certificate
    ///    includes a subjectAltName extension with a uniformResourceIdentifier
    ///    that does not include an authority component with a host name
    ///    specified as a fully qualified domain name (e.g., if the URI either
    ///    does not include an authority component or includes an authority
    ///    component in which the host name is specified as an IP address), then
    ///    the application MUST reject the certificate.
    pub(crate) fn uri_name_matches_constraint(uri_name: &[u8], constraint: &[u8]) -> bool {
        let Some(host) = extract_host(uri_name) else {
            return false;
        };

        if is_ip_address(&host) {
            // IP addresses are forbidden if there is a constraint.
            return false;
        }

        Self::dns_name_matches_constraint(host.as_bytes(), constraint)
    }
}

/// Extracts the host from a URI's authority component, if present.
///
/// The authority component has the form `[userinfo@]host[:port]`. The host
/// alone is what RFC 5280 constrains — a `userinfo@` prefix (e.g. the
/// `user` in `https://user@example.com/`) must be stripped before
/// comparison, otherwise a certificate could smuggle an arbitrary
/// attacker-controlled string in front of `@` to make the presented name
/// look like it matches a constraint it doesn't actually satisfy, or to
/// bypass an excluded-subtree check by disguising the real host.
fn extract_host(uri: &[u8]) -> Option<String> {
    let uri = std::str::from_utf8(uri).ok()?;

    // Find the scheme separator "://".
    let after_scheme = uri.split_once("://").map(|(_, rest)| rest)?;

    // The authority component runs up to the next '/', '?', or '#'.
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];

    if authority.is_empty() {
        return None;
    }

    // Strip a userinfo prefix: everything up to and including the last '@'
    // in the authority. Using the *last* '@' matches how URI parsers treat
    // '@' as the userinfo/host separator even if userinfo itself contains
    // '@' (which is technically illegal unless percent-encoded, but we
    // don't want to be tricked by it either way).
    let host_and_port = match authority.rfind('@') {
        Some(at_index) => &authority[at_index + 1..],
        None => authority,
    };

    if host_and_port.is_empty() {
        return None;
    }

    // Strip a bracketed IPv6 literal's port suffix, or a plain host[:port].
    let host = if host_and_port.starts_with('[') {
        let end = host_and_port.find(']')?;
        &host_and_port[1..end]
    } else {
        match host_and_port.rfind(':') {
            Some(colon_index) => &host_and_port[..colon_index],
            None => host_and_port,
        }
    };

    if host.is_empty() {
        return None;
    }

    Some(host.to_ascii_lowercase())
}

fn is_ip_address(host: &str) -> bool {
    host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(uri: &str, constraint: &str) -> bool {
        NameConstraintsPolicy::uri_name_matches_constraint(uri.as_bytes(), constraint.as_bytes())
    }

    #[test]
    fn matching_host_is_accepted() {
        assert!(matches("https://host.example.com/path", "host.example.com"));
    }

    #[test]
    fn subdomain_constraint_is_accepted() {
        assert!(matches("https://my.host.example.com/path", ".example.com"));
    }

    #[test]
    fn bare_domain_does_not_satisfy_leading_period_constraint() {
        assert!(!matches("https://example.com/path", ".example.com"));
    }

    #[test]
    fn userinfo_prefix_is_stripped_before_matching() {
        // The real host is example.com, not user@example.com — a naive
        // implementation that fails to strip userinfo would either fail to
        // match a legitimate host, or worse, be tricked into matching a
        // constraint via a crafted userinfo string.
        assert!(matches("https://user@example.com/", "example.com"));
    }

    #[test]
    fn userinfo_with_embedded_at_is_stripped_up_to_last_at() {
        assert!(matches("https://a@b@example.com/", "example.com"));
    }

    #[test]
    fn port_is_stripped_before_matching() {
        assert!(matches("https://example.com:8443/", "example.com"));
    }

    #[test]
    fn userinfo_and_port_are_both_stripped() {
        assert!(matches("https://user:pass@example.com:8443/", "example.com"));
    }

    #[test]
    fn ipv4_host_is_rejected_when_constrained() {
        assert!(!matches("https://192.0.2.1/", "example.com"));
    }

    #[test]
    fn bracketed_ipv6_host_is_rejected_when_constrained() {
        assert!(!matches("https://[2001:db8::1]/", "example.com"));
    }

    #[test]
    fn bracketed_ipv6_host_with_port_is_still_recognised_as_ip() {
        assert!(!matches("https://[2001:db8::1]:8443/", "example.com"));
    }

    #[test]
    fn uri_without_authority_component_is_rejected() {
        assert!(!matches("mailto:user@example.com", "example.com"));
    }

    #[test]
    fn non_matching_host_is_rejected() {
        assert!(!matches("https://evil.com/", "example.com"));
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        assert!(matches("https://HOST.EXAMPLE.COM/", "host.example.com"));
    }
}
