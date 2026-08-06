use crate::rfc5280::name_constraints_policy::NameConstraintsPolicy;

impl NameConstraintsPolicy {
    /// Validates that an IP address matches a constraint.
    ///
    /// The rules for IP address constraints are fairly simple. The constraint contains both a subnet
    /// and a subnet mask, while the `ip_address` will contain just the bytes of the address. A constraint
    /// matches if the address is part of the subnet defined by the mask.
    ///
    /// Additionally, RFC 5280 requires that the constraint be equivalent to a subnet defined using CIDR notation.
    /// This implies that we do not tolerate arbitrary masks.
    pub(crate) fn ip_address_matches_constraint(ip_address: &[u8], constraint: &[u8]) -> bool {
        match (ip_address.len(), constraint.len()) {
            // IPv4
            (4, 8) => address_is_in_subnet(ip_address, constraint),
            // IPv6
            (16, 32) => address_is_in_subnet(ip_address, constraint),
            // No match or an invalid format.
            _ => false,
        }
    }
}

fn is_valid_cidr_mask(mask: &[u8]) -> bool {
    // Quick check: is the first byte zero? If it is, we can skip the rest: it matches nothing,
    // either by way of being invalid or by being all zeros.
    if mask.first() == Some(&0) {
        return false;
    }

    // A valid CIDR mask is a sequence of leading 1s, followed by a sequence of 0s.
    // Look for the first index that isn't all 1s.
    let Some(first_interesting_index) = mask.iter().position(|&b| b != 0xff) else {
        // Huh, the mask is all 1s. Fine.
        return true;
    };

    let byte = mask[first_interesting_index];

    // Count the leading 1s.
    let leading_one_count = (!byte).leading_zeros();

    // Shift off that many bits. All the bits left must be zero.
    if leading_one_count < 8 && (byte.wrapping_shl(leading_one_count)) != 0 {
        return false;
    }

    // All remaining bytes must be zero.
    mask[first_interesting_index + 1..].iter().all(|&b| b == 0)
}

fn address_is_in_subnet(address: &[u8], subnet: &[u8]) -> bool {
    debug_assert_eq!(subnet.len(), address.len() * 2);

    let (base, mask) = subnet.split_at(subnet.len() / 2);

    if !is_valid_cidr_mask(mask) {
        return false;
    }

    for i in 0..address.len() {
        if (address[i] & mask[i]) != (base[i] & mask[i]) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Raw 4-byte encoding of a dotted-quad IPv4 address.
    fn a4(addr: &str) -> Vec<u8> {
        addr.parse::<Ipv4Addr>().unwrap().octets().to_vec()
    }

    /// Raw 16-byte encoding of an IPv6 address.
    fn a6(addr: &str) -> Vec<u8> {
        addr.parse::<Ipv6Addr>().unwrap().octets().to_vec()
    }

    /// IPv4 constraint: 4 subnet bytes followed by 4 mask bytes.
    fn c4(subnet: &str, mask: &str) -> Vec<u8> {
        let mut out = a4(subnet);
        out.extend_from_slice(&a4(mask));
        out
    }

    /// IPv6 constraint: 16 subnet bytes followed by 16 mask bytes.
    fn c6(subnet: &str, mask: &str) -> Vec<u8> {
        let mut out = a6(subnet);
        out.extend_from_slice(&a6(mask));
        out
    }

    /// A constraint of `count` 0xff bytes, used to probe length validation.
    fn ones(count: usize) -> Vec<u8> {
        vec![0xff; count]
    }

    #[test]
    fn constraint_corpus() {
        let fixtures: Vec<(Vec<u8>, Vec<u8>, bool)> = vec![
            // Straightforward IPv4 CIDR masks.
            (a4("17.250.78.1"), c4("17.0.0.0", "255.0.0.0"), true),
            (a4("17.250.78.1"), c4("17.250.0.66", "255.255.0.0"), true),
            (a4("17.250.78.1"), c4("17.250.78.0", "255.255.255.0"), true),
            (a4("17.250.78.1"), c4("17.250.78.1", "255.255.255.255"), true),
            (a4("18.250.78.1"), c4("17.0.0.0", "255.0.0.0"), false),
            (a4("17.250.78.1"), c4("17.250.78.2", "255.255.255.255"), false),
            // Masks with zero bytes in positions that break contiguity.
            (a4("17.250.78.1"), c4("17.250.78.1", "0.0.0.255"), false),
            (a4("17.250.78.1"), c4("17.250.78.1", "0.0.255.255"), false),
            (a4("17.250.78.1"), c4("17.250.78.1", "0.255.255.255"), false),
            (a4("17.250.78.1"), c4("17.250.78.1", "255.0.255.0"), false),
            (a4("17.250.78.1"), c4("17.250.78.1", "255.255.0.255"), false),
            // Valid CIDR masks that are not byte aligned.
            (a4("17.250.78.1"), c4("17.0.0.0", "128.0.0.0"), true),
            (a4("17.255.78.1"), c4("17.254.0.0", "255.254.0.0"), true),
            (a4("17.255.78.1"), c4("17.254.0.0", "255.255.0.0"), false),
            // Non-contiguous bit patterns inside a byte.
            (a4("17.250.78.1"), c4("17.250.78.1", "255.255.62.0"), false),
            (a4("17.250.78.1"), c4("17.250.78.1", "255.239.255.255"), false),
            // An all-zero mask matches nothing.
            (a4("17.250.78.1"), c4("0.0.0.0", "0.0.0.0"), false),
            // Address and constraint from different families never match.
            (a4("17.250.78.1"), c6("8000::", "8000::"), false),
            (a6("fe80::"), c4("254.128.0.0", "255.128.0.0"), false),
            // Straightforward IPv6 CIDR masks.
            (a6("fe80::8d:f7d:79c5:5719"), c6("fe80::", "ffff:ffff:ffff:ffff::"), true),
            (
                a6("fe80::8d:f7d:79c5:5719"),
                c6("fe80::8d:0:0:0", "ffff:ffff:ffff:ffff:ffff::"),
                true,
            ),
            (
                a6("fe80::8d:f7d:79c5:5719"),
                c6("fe80::8d:f7d:0:0", "ffff:ffff:ffff:ffff:ffff:ffff::"),
                true,
            ),
            (
                a6("fe80::8d:f7d:79c5:5719"),
                c6("fe80::8d:f7d:79c5:0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:0"),
                true,
            ),
            (
                a6("fe80::8d:f7d:79c5:5719"),
                c6("fe80::8d:f7d:79c5:5719", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                true,
            ),
            (a6("fe80::8d:f7d:79c5:5719"), c6("fe81::", "ffff:ffff:ffff:ffff::"), false),
            (
                a6("fe80::8d:f7d:79d5:5719"),
                c6("fe80::8d:f7d:79c5:5719", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                false,
            ),
            // IPv6 masks with zero groups in positions that break contiguity.
            (a6("fe80::8d:f7d:79c5:5719"), c6("fe80::8d:f7d:79c5:5719", "::ffff"), false),
            (
                a6("fe80::8d:f7d:79c5:5719"),
                c6("fe80::8d:f7d:79c5:5719", "::ffff:ffff"),
                false,
            ),
            (
                a6("fe80::8d:f7d:79c5:5719"),
                c6("fe80::8d:f7d:79c5:5719", "ffff::ffff"),
                false,
            ),
            (
                a6("fe80::8d:f7d:79c5:5719"),
                c6("fe80::8d:f7d:79c5:5719", "ffff:0:0:ffff::ffff"),
                false,
            ),
            // Valid IPv6 CIDR masks that are not byte aligned.
            (a6("fe80::8d:f7d:79c5:5719"), c6("fe80::8d:f7d:79c5:5719", "8000::"), true),
            (a6("fe80::8d:f7d:79c5:5719"), c6("fe80::8d:f7d:79c5:5719", "fffe::"), true),
            (
                a6("fe80::8d:f7d:79c5:5719"),
                c6("fe81::8d:f7d:79c5:5719", "ffff:ffff::"),
                false,
            ),
            // Non-contiguous IPv6 bit patterns.
            (
                a6("fe80::8d:f7d:79c5:5719"),
                c6("fe81::8d:f7d:79c5:5719", "ffff:ffff:c9c9::"),
                false,
            ),
            (
                a6("fe80::8d:f7d:79c5:5719"),
                c6("fe81::8d:f7d:79c5:5719", "ffff:ffff:feff:ffff:ffff:ffff:ffff:ffff"),
                false,
            ),
            // An all-zero IPv6 mask matches nothing.
            (a6("fe80::8d:f7d:79c5:5719"), c6("::", "::"), false),
            // A constraint must be exactly twice the address length.
            (a4("17.250.78.1"), ones(1), false),
            (a4("17.250.78.1"), ones(7), false),
            (a4("17.250.78.1"), ones(9), false),
            (a6("fe80::8d:f7d:79c5:5719"), ones(1), false),
            (a6("fe80::8d:f7d:79c5:5719"), ones(31), false),
            (a6("fe80::8d:f7d:79c5:5719"), ones(33), false),
        ];

        assert_eq!(fixtures.len(), 42, "corpus must cover every row of the conformance table");
        for (address, constraint, expected) in &fixtures {
            let actual = NameConstraintsPolicy::ip_address_matches_constraint(address, constraint);
            assert_eq!(
                actual, *expected,
                "expected address {address:02x?} matching constraint {constraint:02x?} to be {expected}, but it was {actual}"
            );
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Vec<u8> {
        vec![a, b, c, d]
    }

    fn v4_constraint(base: [u8; 4], mask: [u8; 4]) -> Vec<u8> {
        let mut out = base.to_vec();
        out.extend_from_slice(&mask);
        out
    }

    #[test]
    fn address_within_subnet_matches() {
        let address = v4(192, 168, 1, 42);
        let constraint = v4_constraint([192, 168, 1, 0], [255, 255, 255, 0]);
        assert!(NameConstraintsPolicy::ip_address_matches_constraint(&address, &constraint));
    }

    #[test]
    fn address_outside_subnet_does_not_match() {
        let address = v4(192, 168, 2, 42);
        let constraint = v4_constraint([192, 168, 1, 0], [255, 255, 255, 0]);
        assert!(!NameConstraintsPolicy::ip_address_matches_constraint(&address, &constraint));
    }

    #[test]
    fn exact_host_mask_requires_exact_match() {
        let address = v4(10, 0, 0, 1);
        let constraint = v4_constraint([10, 0, 0, 1], [255, 255, 255, 255]);
        assert!(NameConstraintsPolicy::ip_address_matches_constraint(&address, &constraint));

        let other = v4(10, 0, 0, 2);
        assert!(!NameConstraintsPolicy::ip_address_matches_constraint(&other, &constraint));
    }

    #[test]
    fn all_zero_mask_matches_nothing() {
        let address = v4(10, 0, 0, 1);
        let constraint = v4_constraint([0, 0, 0, 0], [0, 0, 0, 0]);
        assert!(!NameConstraintsPolicy::ip_address_matches_constraint(&address, &constraint));
    }

    #[test]
    fn non_cidr_mask_is_rejected() {
        // 255.0.255.0 is not a valid CIDR mask (not a contiguous run of 1 bits).
        let address = v4(10, 0, 0, 1);
        let constraint = v4_constraint([10, 0, 0, 0], [255, 0, 255, 0]);
        assert!(!NameConstraintsPolicy::ip_address_matches_constraint(&address, &constraint));
    }

    #[test]
    fn mismatched_lengths_do_not_match() {
        let address = v4(10, 0, 0, 1);
        // IPv6-sized constraint against an IPv4 address.
        let constraint = vec![0u8; 32];
        assert!(!NameConstraintsPolicy::ip_address_matches_constraint(&address, &constraint));
    }

    #[test]
    fn ipv6_subnet_match() {
        let mut address = vec![0u8; 16];
        address[0] = 0x20;
        address[1] = 0x01;
        address[15] = 0x01;

        let mut base = vec![0u8; 16];
        base[0] = 0x20;
        base[1] = 0x01;

        let mut mask = vec![0u8; 16];
        mask[0] = 0xff;
        mask[1] = 0xff;

        let mut constraint = base;
        constraint.extend_from_slice(&mask);

        assert!(NameConstraintsPolicy::ip_address_matches_constraint(&address, &constraint));
    }
}
