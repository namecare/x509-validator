use std::sync::OnceLock;

use x509_validator::{Certificate, FromDer};

/// Apple's receipt-signing chain: leaf → WWDR G6 → Apple Root CA - G3.
pub mod apple {
    use super::*;

    pub const LEAF_DER: &[u8] = include_bytes!("../data/apple/receipt_signing_leaf.der");
    pub const INTERMEDIATE_DER: &[u8] = include_bytes!("../data/apple/wwdr_g6_intermediate.der");
    pub const ROOT_DER: &[u8] = include_bytes!("../data/apple/apple_root_ca_g3.der");

    /// The `signedDate` of the payload these certificates signed, in seconds
    /// (2025-09-22T22:26:05Z). Expiry is checked against this rather than the
    /// wall clock, both so runs are reproducible and because it is the
    /// instant a receipt validator would actually use. The leaf expires in
    /// October 2027; pinning here keeps the benchmark working past that.
    pub const SIGNED_DATE: i64 = 1_758_579_965;

    pub struct Chain {
        pub leaf: Certificate<'static>,
        pub intermediate: Certificate<'static>,
        pub root: Certificate<'static>,
    }

    static CHAIN: OnceLock<Chain> = OnceLock::new();

    /// The parsed chain, parsed once on first call.
    pub fn chain() -> &'static Chain {
        CHAIN.get_or_init(|| Chain {
            leaf: parse_static(LEAF_DER),
            intermediate: parse_static(INTERMEDIATE_DER),
            root: parse_static(ROOT_DER),
        })
    }

    /// Parses DER that is already `'static`, so no leaking is needed.
    fn parse_static(der: &'static [u8]) -> Certificate<'static> {
        Certificate::from_der(der)
            .expect("vendored Apple certificate parses")
            .1
    }
}
