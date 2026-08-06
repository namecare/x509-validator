use rcgen::{DistinguishedName, DnType, GeneralSubtree, NameConstraints};

pub fn dns_subtree(name: &str) -> GeneralSubtree {
    GeneralSubtree::DnsName(name.to_string())
}

/// An iPAddress subtree covering the given IPv4 base/mask pair.
pub fn ipv4_subtree(base: [u8; 4], mask: [u8; 4]) -> GeneralSubtree {
    GeneralSubtree::IpAddress(rcgen::CidrSubnet::V4(base, mask))
}

/// A directoryName subtree carrying a single commonName attribute.
pub fn directory_name_subtree(common_name: &str) -> GeneralSubtree {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    GeneralSubtree::DirectoryName(dn)
}

pub fn name_constraints(permitted: Vec<GeneralSubtree>, excluded: Vec<GeneralSubtree>) -> NameConstraints {
    NameConstraints {
        permitted_subtrees: permitted,
        excluded_subtrees: excluded,
    }
}
