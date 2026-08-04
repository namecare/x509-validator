use crate::rfc5280::name_constraints_policy::NameConstraintsPolicy;

impl NameConstraintsPolicy {
    /// Validates that an IP address matches a constraint.
    ///
    /// A constraint carries both a subnet base and a subnet mask
    /// concatenated together (base first, then mask, each the same length
    /// as the address family: 4+4 bytes for IPv4, 16+16 bytes for IPv6). It
    /// matches an address if the address falls within the subnet defined by
    /// the mask.
    ///
    /// RFC 5280 additionally requires the mask be equivalent to one
    /// expressible in CIDR notation — i.e. a run of set bits followed by a
    /// run of clear bits, with no other pattern tolerated.
    pub(crate) fn ip_address_matches_constraint(ip_address: &[u8], constraint: &[u8]) -> bool {
        match (ip_address.len(), constraint.len()) {
            (4, 8) => address_is_in_subnet(ip_address, constraint),
            (16, 32) => address_is_in_subnet(ip_address, constraint),
            _ => false,
        }
    }
}

fn is_valid_cidr_mask(mask: &[u8]) -> bool {
    // If the first byte is zero, the mask matches nothing usable, either
    // because it's invalid or because it's all zeros.
    if mask.first() == Some(&0) {
        return false;
    }

    let Some(first_interesting_index) = mask.iter().position(|&b| b != 0xff) else {
        // Mask is all 1s. Fine.
        return true;
    };

    let byte = mask[first_interesting_index];

    // Count leading 1 bits in this byte.
    let leading_one_count = (!byte).leading_zeros();

    // Shifting off that many bits must leave zero.
    if leading_one_count < 8 && (byte.wrapping_shl(leading_one_count)) != 0 {
        return false;
    }

    // Every remaining byte must be zero.
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
