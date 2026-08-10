// ---------------------------------------------------------------------------
// Hand-encoded nameConstraints extensions.
//
// The certificate generator's `GeneralSubtree` type only models a subset of
// the GeneralName choices in RFC 5280 §4.2.1.6 — notably it cannot express
// `uniformResourceIdentifier`, nor any of the choices this crate treats as
// unsupported (otherName, x400Address, ediPartyName, registeredID). Those
// subtree kinds are built here as raw DER instead, and attached with a
// custom extension carrying the nameConstraints OID.
// ---------------------------------------------------------------------------

/// id-ce-nameConstraints, RFC 5280 §4.2.1.10: 2.5.29.30.
const NAME_CONSTRAINTS_OID: &[u64] = &[2, 5, 29, 30];

/// id-ce-subjectAltName, RFC 5280 §4.2.1.6: 2.5.29.17.
const SUBJECT_ALT_NAME_OID: &[u64] = &[2, 5, 29, 17];

/// A DER TLV: `tag`, a definite-form length, then `contents`.
pub(crate) fn der_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
    out.extend_from_slice(contents);
    out
}

/// One GeneralName, as the context-specific primitive `[tag] contents`.
///
/// The GeneralName CHOICE tags are assigned in RFC 5280 §4.2.1.6:
/// otherName \[0\], rfc822Name \[1\], dNSName \[2\], x400Address \[3\],
/// directoryName \[4\], ediPartyName \[5\], uniformResourceIdentifier \[6\],
/// iPAddress \[7\], registeredID \[8\].
#[derive(Clone)]
pub struct RawGeneralName(Vec<u8>);

impl RawGeneralName {
    fn primitive(tag_number: u8, contents: &[u8]) -> Self {
        Self(der_tlv(0x80 | tag_number, contents))
    }

    /// uniformResourceIdentifier \[6\], an IA5String.
    pub fn uri(value: &str) -> Self {
        Self::primitive(6, value.as_bytes())
    }

    /// dNSName \[2\], an IA5String.
    pub fn dns(value: &str) -> Self {
        Self::primitive(2, value.as_bytes())
    }

    /// iPAddress \[7\], a raw octet string. For a constraint this is the
    /// base address followed by the mask; for a name it is the address
    /// alone.
    pub fn ip(value: &[u8]) -> Self {
        Self::primitive(7, value)
    }

    /// rfc822Name \[1\] — a kind this crate does not know how to match.
    pub fn rfc822(value: &str) -> Self {
        Self::primitive(1, value.as_bytes())
    }

    /// registeredID \[8\], carrying the OID 1.2.1.1.
    pub fn registered_id() -> Self {
        Self::primitive(8, &[0x2a, 0x01, 0x01])
    }

    /// otherName \[0\]: a constructed SEQUENCE of a type OID and a value.
    pub fn other_name() -> Self {
        let mut contents = Vec::new();
        contents.extend_from_slice(&der_tlv(0x06, &[0x2a, 0x01, 0x01])); // OID 1.2.1.1
        contents.extend_from_slice(&der_tlv(0xa0, &der_tlv(0x05, &[]))); // [0] NULL
        Self(der_tlv(0xa0, &contents))
    }

    /// x400Address \[3\], a constructed value this crate cannot interpret.
    pub fn x400_address() -> Self {
        Self(der_tlv(0xa3, &der_tlv(0x05, &[])))
    }

    /// ediPartyName \[5\], a constructed value this crate cannot interpret.
    pub fn edi_party_name() -> Self {
        Self(der_tlv(0xa5, &der_tlv(0x05, &[])))
    }
}

/// A GeneralSubtree wrapping one GeneralName, with `minimum`/`maximum`
/// omitted as RFC 5280 §4.2.1.10 requires.
fn general_subtree(name: &RawGeneralName) -> Vec<u8> {
    der_tlv(0x30, &name.0)
}

/// A nameConstraints extension built from raw GeneralNames, encoded as
/// `SEQUENCE { [0] permittedSubtrees OPTIONAL, [1] excludedSubtrees OPTIONAL }`.
pub fn raw_name_constraints_extension(
    permitted: &[RawGeneralName],
    excluded: &[RawGeneralName],
) -> rcgen::CustomExtension {
    let mut body = Vec::new();

    if !permitted.is_empty() {
        let subtrees: Vec<u8> = permitted
            .iter()
            .flat_map(general_subtree)
            .collect();
        body.extend_from_slice(&der_tlv(0xa0, &subtrees));
    }
    if !excluded.is_empty() {
        let subtrees: Vec<u8> = excluded
            .iter()
            .flat_map(general_subtree)
            .collect();
        body.extend_from_slice(&der_tlv(0xa1, &subtrees));
    }

    let mut extension =
        rcgen::CustomExtension::from_oid_content(NAME_CONSTRAINTS_OID, der_tlv(0x30, &body));
    extension.set_criticality(true);
    extension
}

/// A subjectAltName extension built from raw GeneralNames, for name forms
/// the generator's own `SanType` cannot express.
pub fn raw_subject_alt_name_extension(names: &[RawGeneralName]) -> rcgen::CustomExtension {
    let contents: Vec<u8> = names
        .iter()
        .flat_map(|n| n.0.clone())
        .collect();
    let mut extension =
        rcgen::CustomExtension::from_oid_content(SUBJECT_ALT_NAME_OID, der_tlv(0x30, &contents));
    extension.set_criticality(true);
    extension
}

/// A nameConstraints extension whose contents are undecodable gibberish.
pub fn broken_name_constraints_extension() -> rcgen::CustomExtension {
    let mut extension = rcgen::CustomExtension::from_oid_content(
        NAME_CONSTRAINTS_OID,
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
    );
    extension.set_criticality(true);
    extension
}

/// A subjectAltName extension whose contents are undecodable gibberish.
pub fn broken_subject_alt_name_extension() -> rcgen::CustomExtension {
    let mut extension = rcgen::CustomExtension::from_oid_content(
        SUBJECT_ALT_NAME_OID,
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
    );
    extension.set_criticality(true);
    extension
}

/// A critical extension with an OID no policy in this crate claims.
pub fn weird_critical_extension() -> rcgen::CustomExtension {
    let mut extension =
        rcgen::CustomExtension::from_oid_content(&[1, 2, 3, 4, 5], vec![1, 2, 3, 4, 5]);
    extension.set_criticality(true);
    extension
}
