//! The certificate set the parity benchmarks validate against.

use std::sync::OnceLock;

use time::{Duration, OffsetDateTime};
use x509_validator::Certificate;

use crate::parse::cert;
use crate::rcgen::{KeyPair, PKCS_ECDSA_P384_SHA384};
use crate::{CaSpec, LeafSpec, Ski};

/// The instant every validity window is anchored to, and the time expiry
/// checks are pinned to. Fixed rather than "now" so a benchmark run is not
/// affected by the wall clock.
pub const REFERENCE_TIME: i64 = 1_700_000_000; // 2023-11-14T22:13:20Z

fn reference() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(REFERENCE_TIME).expect("valid reference time")
}

fn days(n: i64) -> Duration {
    Duration::days(n)
}

/// A P-384 key pair, the curve the fixture specification puts CAs on.
fn ca_key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("generate P-384 key pair")
}

/// A three-certificate chain whose keys are all on one curve.
///
/// The backend comparison validates one of these per curve. Holding the shape
/// fixed — leaf → intermediate → root, two signature verifications — and
/// varying only the curve is what makes the two rows a fair test: any
/// difference between them is the curve, not the amount of work.
pub struct CurveChain {
    pub root: Certificate<'static>,
    pub intermediate: Certificate<'static>,
    pub leaf: Certificate<'static>,
}

static P256_CHAIN: OnceLock<CurveChain> = OnceLock::new();

/// An all-P-256 chain, built once on first call.
///
/// Every key here is P-256, so both verifications a validation performs take
/// the curve backends optimize hardest. It is the counterpart to the vendored
/// Apple chain, which verifies entirely against P-384 issuer keys: together
/// the two bracket what a backend costs on the fast and slow curve, on chains
/// of identical shape.
pub fn p256_chain() -> &'static CurveChain {
    P256_CHAIN.get_or_init(build_p256_chain)
}

fn build_p256_chain() -> CurveChain {
    let now = reference();

    // `generate` defaults to P-256, the same call the P-256 intermediate in
    // the parity set uses.
    let p256 = || KeyPair::generate().expect("generate P-256 key pair");

    let root = CaSpec::new("Benchmark P-256 Root CA")
        .key_pair(p256())
        .validity(now - days(365), now + days(3650))
        .self_signed();

    let intermediate = CaSpec::new("Benchmark P-256 Intermediate CA")
        .key_pair(p256())
        .validity(now - days(365), now + days(5 * 365))
        .path_len(Some(0))
        .include_aki(true)
        .signed_by(&root);

    let leaf = LeafSpec::new("p256.example")
        .dns_sans(&["p256.example"])
        .validity(now - days(365), now + days(365))
        .include_aki(true)
        .signed_by(&intermediate);

    CurveChain {
        root: cert(root.der),
        intermediate: cert(intermediate.der),
        leaf: cert(leaf),
    }
}

pub struct Parity {
    pub ca1: Certificate<'static>,
    pub ca1_cross_signed_by_ca2: Certificate<'static>,
    pub ca1_with_alternative_private_key: Certificate<'static>,
    pub ca2: Certificate<'static>,
    pub ca2_cross_signed_by_ca1: Certificate<'static>,
    pub intermediate1: Certificate<'static>,
    pub intermediate1_without_ski_aki: Certificate<'static>,
    pub intermediate1_with_incorrect_ski_aki: Certificate<'static>,
    pub localhost_leaf: Certificate<'static>,
    pub isolated_self_signed: Certificate<'static>,
    pub isolated_self_signed_weird_critical: Certificate<'static>,
}

static PARITY: OnceLock<Parity> = OnceLock::new();

/// The parity fixture set, built once on first call.
///
/// Certificate generation is expensive and must never land inside a timed
/// region, so this is built once and reused across every benchmark.
pub fn parity() -> &'static Parity {
    PARITY.get_or_init(build)
}

fn build() -> Parity {
    let now = reference();

    // Roots: valid from a year ago to ten years out.
    let ca1 = CaSpec::new("Benchmark Test CA 1")
        .key_pair(ca_key())
        .validity(now - days(365), now + days(3650))
        .self_signed();

    let ca2 = CaSpec::new("Benchmark Test CA 2")
        .key_pair(ca_key())
        .validity(now - days(365), now + days(3650))
        .self_signed();

    // Cross-signed roots: same identity and key, a different signature, and a
    // shorter window than the self-signed pair.
    let ca1_cross = CaSpec::new("Benchmark Test CA 1")
        .key_pair(ca1.copy_of_key_pair())
        .validity(now - days(365), now + days(365))
        .include_aki(true)
        .signed_by(&ca2);

    let ca2_cross = CaSpec::new("Benchmark Test CA 2")
        .key_pair(ca2.copy_of_key_pair())
        .validity(now - days(365), now + days(365))
        .include_aki(true)
        .signed_by(&ca1);

    // Same subject name as ca1 but a different key, so it names the right
    // issuer while failing to verify anything ca1 actually signed.
    let ca1_alternative = CaSpec::new("Benchmark Test CA 1")
        .key_pair(ca_key())
        .validity(now - days(365), now + days(3650))
        .self_signed();

    // Intermediates: P-256, path length 1, five-year window.
    let intermediate_key = KeyPair::generate().expect("generate P-256 key pair");
    let intermediate1 = CaSpec::new("Benchmark Test Intermediate CA 1")
        .key_pair(intermediate_key)
        .validity(now - days(365), now + days(5 * 365))
        .path_len(Some(1))
        .include_aki(true)
        .signed_by(&ca1);

    let intermediate1_without_ski_aki = CaSpec::new("Benchmark Test Intermediate CA 1")
        .key_pair(intermediate1.copy_of_key_pair())
        .validity(now - days(365), now + days(5 * 365))
        .path_len(Some(1))
        .ski(Ski::Absent)
        .include_aki(false)
        .signed_by(&ca1);

    // An AKI naming ca2 while actually issued by ca1 — the mismatch RFC 5280
    // does not forbid and chain building has to tolerate.
    let intermediate1_with_incorrect_ski_aki = CaSpec::new("Benchmark Test Intermediate CA 1")
        .key_pair(intermediate1.copy_of_key_pair())
        .validity(now - days(365), now + days(5 * 365))
        .path_len(Some(1))
        .ski(Ski::Exactly(ca2.key_identifier()))
        .include_aki(true)
        .signed_by(&ca2);

    let localhost_leaf = LeafSpec::new("localhost")
        .dns_sans(&["localhost"])
        .validity(now - days(365), now + days(365))
        .include_aki(true)
        .signed_by(&intermediate1);

    let isolated_self_signed = LeafSpec::new("Isolated Self-Signed Cert")
        .validity(now - days(365), now + days(365))
        .self_signed();

    let isolated_self_signed_weird_critical = LeafSpec::new("Isolated Self-Signed Cert")
        .validity(now - days(365), now + days(365))
        .critical_extension(&[1, 2, 3, 4, 5], vec![1, 2, 3, 4, 5])
        .self_signed();

    Parity {
        ca1: cert(ca1.der),
        ca1_cross_signed_by_ca2: cert(ca1_cross.der),
        ca1_with_alternative_private_key: cert(ca1_alternative.der),
        ca2: cert(ca2.der),
        ca2_cross_signed_by_ca1: cert(ca2_cross.der),
        intermediate1: cert(intermediate1.der),
        intermediate1_without_ski_aki: cert(intermediate1_without_ski_aki.der),
        intermediate1_with_incorrect_ski_aki: cert(intermediate1_with_incorrect_ski_aki.der),
        localhost_leaf: cert(localhost_leaf),
        isolated_self_signed: cert(isolated_self_signed),
        isolated_self_signed_weird_critical: cert(isolated_self_signed_weird_critical),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_set_is_built_once_and_chains_correctly() {
        let a = parity();
        let b = parity();
        assert!(core::ptr::eq(a, b), "fixtures must be built exactly once");

        // The leaf chains to intermediate1, which chains to ca1.
        assert_eq!(
            a.localhost_leaf.issuer().as_raw(),
            a.intermediate1.subject().as_raw()
        );
        assert_eq!(a.intermediate1.issuer().as_raw(), a.ca1.subject().as_raw());
    }

    #[test]
    fn p256_chain_links_up_and_is_entirely_p256() {
        let c = p256_chain();
        assert!(core::ptr::eq(c, p256_chain()), "built exactly once");

        assert_eq!(c.leaf.issuer().as_raw(), c.intermediate.subject().as_raw());
        assert_eq!(c.intermediate.issuer().as_raw(), c.root.subject().as_raw());

        // The point of this fixture is the curve, so assert it rather than
        // trusting `KeyPair::generate`'s default to stay P-256. A P-384 key
        // slipping in here would silently turn the "fast curve" row into a
        // second copy of the slow one.
        //
        // The id-ecPublicKey SPKI carries the curve as the `parameters` OID;
        // prime256v1 is 1.2.840.10045.3.1.7, whose DER encoding ends in the
        // bytes below.
        const PRIME256V1_OID_DER: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        for (name, cert) in [
            ("root", &c.root),
            ("intermediate", &c.intermediate),
            ("leaf", &c.leaf),
        ] {
            let spki = cert.public_key().raw;
            assert!(
                spki.windows(PRIME256V1_OID_DER.len())
                    .any(|w| w == PRIME256V1_OID_DER),
                "{name} must be on P-256",
            );
        }
    }

    #[test]
    fn reference_time_falls_inside_every_validity_window() {
        let p = parity();
        for cert in [
            &p.ca1,
            &p.ca1_cross_signed_by_ca2,
            &p.ca1_with_alternative_private_key,
            &p.ca2,
            &p.ca2_cross_signed_by_ca1,
            &p.intermediate1,
            &p.intermediate1_without_ski_aki,
            &p.intermediate1_with_incorrect_ski_aki,
            &p.localhost_leaf,
            &p.isolated_self_signed,
            &p.isolated_self_signed_weird_critical,
        ] {
            let validity = cert.tbs_certificate.validity();
            assert!(
                REFERENCE_TIME >= validity.not_before.timestamp(),
                "not yet valid at reference time"
            );
            assert!(
                REFERENCE_TIME <= validity.not_after.timestamp(),
                "expired at reference time"
            );
        }
    }
}
