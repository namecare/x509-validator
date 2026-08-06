//! Verification progress and failure events emitted while a chain is being
//! built.
//!
//! A [`VerificationDiagnostic`] is a tagged union: one variant per event the
//! chain builder can report, each carrying exactly the certificates, OIDs and
//! policy failure reasons involved. The public surface is deliberately opaque
//! — callers construct diagnostics through the constructor functions and
//! consume them through the two rendering forms:
//!
//! * [`Display`] renders a single line, suitable for a log statement. It is
//!   guaranteed never to contain a newline.
//! * [`VerificationDiagnostic::multiline_description`] renders the same
//!   information spread over several lines, for a human reading a terminal.
//!
//! Certificates are always rendered through
//! [`format_certificate`](crate::certificate_display::format_certificate),
//! never through their derived `Debug`, which would dump the raw DER bytes.

use crate::certificate_display::format_certificate;
use crate::policy::PolicyFailureReason;
use std::fmt;
use x509_validator_core::der_parser::Oid;
use x509_validator_core::Certificate;

/// A single event observed while building and validating a certificate chain.
pub struct VerificationDiagnostic<'a> {
    storage: Storage<'a>,
}

/// The payloads are boxed so that every variant is one pointer wide; the
/// certificate-carrying payloads differ substantially in size, and an unboxed
/// union would make every diagnostic as large as its biggest variant.
enum Storage<'a> {
    LeafCertificateHasUnhandledCriticalExtension(Box<LeafCertificateHasUnhandledCriticalExtensions<'a>>),
    LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy(Box<LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy<'a>>),
    ChainFailsToMeetPolicy(Box<ChainFailsToMeetPolicy<'a>>),
    IssuerHasUnhandledCriticalExtension(Box<IssuerHasUnhandledCriticalExtension<'a>>),
    IssuerHasNotSignedCertificate(Box<IssuerHasNotSignedCertificate<'a>>),
    SearchingForIssuerOfPartialChain(Box<SearchingForIssuerOfPartialChain<'a>>),
    FoundCandidateIssuersOfPartialChainInRootStore(Box<FoundCandidateIssuersOfPartialChainInRootStore<'a>>),
    FoundCandidateIssuersOfPartialChainInIntermediateStore(Box<FoundCandidateIssuersOfPartialChainInIntermediateStore<'a>>),
    FoundValidCertificateChain(Box<FoundValidCertificateChain<'a>>),
    CouldNotValidateLeafCertificate(Box<CouldNotValidateLeafCertificate<'a>>),
    IssuerIsAlreadyInTheChain(Box<IssuerIsAlreadyInTheChain<'a>>),
}

struct LeafCertificateHasUnhandledCriticalExtensions<'a> {
    leaf_certificate: Certificate<'a>,
    handled_critical_extensions: Vec<Oid<'static>>,
}

struct LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy<'a> {
    leaf_certificate: Certificate<'a>,
    failure_reason: PolicyFailureReason,
}

struct ChainFailsToMeetPolicy<'a> {
    chain: Vec<Certificate<'a>>,
    failure_reason: PolicyFailureReason,
}

struct IssuerHasUnhandledCriticalExtension<'a> {
    issuer: Certificate<'a>,
    partial_chain: Vec<Certificate<'a>>,
    handled_critical_extensions: Vec<Oid<'static>>,
}

struct IssuerHasNotSignedCertificate<'a> {
    issuer: Certificate<'a>,
    partial_chain: Vec<Certificate<'a>>,
}

struct SearchingForIssuerOfPartialChain<'a> {
    partial_chain: Vec<Certificate<'a>>,
}

struct FoundCandidateIssuersOfPartialChainInRootStore<'a> {
    partial_chain: Vec<Certificate<'a>>,
    issuers_in_root_store: Vec<Certificate<'a>>,
}

struct FoundCandidateIssuersOfPartialChainInIntermediateStore<'a> {
    partial_chain: Vec<Certificate<'a>>,
    issuers_in_intermediate_store: Vec<Certificate<'a>>,
}

struct FoundValidCertificateChain<'a> {
    valid_certificate_chain: Vec<Certificate<'a>>,
}

struct CouldNotValidateLeafCertificate<'a> {
    leaf: Certificate<'a>,
}

struct IssuerIsAlreadyInTheChain<'a> {
    partial_chain: Vec<Certificate<'a>>,
    issuer: Certificate<'a>,
}

// MARK: Constructors

impl<'a> VerificationDiagnostic<'a> {
    /// The leaf carries at least one critical extension the policy does not
    /// declare it understands. The unhandled set is derived at render time
    /// from `handled_critical_extensions`.
    pub fn leaf_certificate_has_unhandled_critical_extension(
        leaf_certificate: Certificate<'a>,
        handled_critical_extensions: Vec<Oid<'static>>,
    ) -> Self {
        Self {
            storage: Storage::LeafCertificateHasUnhandledCriticalExtension(Box::new(
                LeafCertificateHasUnhandledCriticalExtensions {
                    leaf_certificate,
                    handled_critical_extensions,
                },
            )),
        }
    }

    pub fn leaf_certificate_is_in_the_root_store_but_does_not_meet_policy(
        leaf_certificate: Certificate<'a>,
        failure_reason: PolicyFailureReason,
    ) -> Self {
        Self {
            storage: Storage::LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy(Box::new(
                LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy {
                    leaf_certificate,
                    failure_reason,
                },
            )),
        }
    }

    pub fn chain_fails_to_meet_policy(chain: Vec<Certificate<'a>>, failure_reason: PolicyFailureReason) -> Self {
        Self {
            storage: Storage::ChainFailsToMeetPolicy(Box::new(ChainFailsToMeetPolicy { chain, failure_reason })),
        }
    }

    /// A candidate issuer of the chain tip carries at least one critical
    /// extension the policy does not declare it understands. As with the leaf
    /// variant, the unhandled set is derived at render time.
    pub fn issuer_has_unhandled_critical_extension(
        issuer: Certificate<'a>,
        partial_chain: Vec<Certificate<'a>>,
        handled_critical_extensions: Vec<Oid<'static>>,
    ) -> Self {
        Self {
            storage: Storage::IssuerHasUnhandledCriticalExtension(Box::new(IssuerHasUnhandledCriticalExtension {
                issuer,
                partial_chain,
                handled_critical_extensions,
            })),
        }
    }

    pub fn issuer_has_not_signed_certificate(issuer: Certificate<'a>, partial_chain: Vec<Certificate<'a>>) -> Self {
        Self {
            storage: Storage::IssuerHasNotSignedCertificate(Box::new(IssuerHasNotSignedCertificate {
                issuer,
                partial_chain,
            })),
        }
    }

    pub fn searching_for_issuer_of_partial_chain(partial_chain: Vec<Certificate<'a>>) -> Self {
        Self {
            storage: Storage::SearchingForIssuerOfPartialChain(Box::new(SearchingForIssuerOfPartialChain {
                partial_chain,
            })),
        }
    }

    pub fn found_candidate_issuers_of_partial_chain_in_root_store(
        partial_chain: Vec<Certificate<'a>>,
        issuers_in_root_store: Vec<Certificate<'a>>,
    ) -> Self {
        Self {
            storage: Storage::FoundCandidateIssuersOfPartialChainInRootStore(Box::new(
                FoundCandidateIssuersOfPartialChainInRootStore {
                    partial_chain,
                    issuers_in_root_store,
                },
            )),
        }
    }

    pub fn found_candidate_issuers_of_partial_chain_in_intermediate_store(
        partial_chain: Vec<Certificate<'a>>,
        issuers_in_intermediate_store: Vec<Certificate<'a>>,
    ) -> Self {
        Self {
            storage: Storage::FoundCandidateIssuersOfPartialChainInIntermediateStore(Box::new(
                FoundCandidateIssuersOfPartialChainInIntermediateStore {
                    partial_chain,
                    issuers_in_intermediate_store,
                },
            )),
        }
    }

    pub fn found_valid_certificate_chain(valid_certificate_chain: Vec<Certificate<'a>>) -> Self {
        Self {
            storage: Storage::FoundValidCertificateChain(Box::new(FoundValidCertificateChain {
                valid_certificate_chain,
            })),
        }
    }

    pub fn could_not_validate_leaf_certificate(leaf: Certificate<'a>) -> Self {
        Self {
            storage: Storage::CouldNotValidateLeafCertificate(Box::new(CouldNotValidateLeafCertificate { leaf })),
        }
    }

    pub fn issuer_is_already_in_the_chain(partial_chain: Vec<Certificate<'a>>, issuer: Certificate<'a>) -> Self {
        Self {
            storage: Storage::IssuerIsAlreadyInTheChain(Box::new(IssuerIsAlreadyInTheChain {
                partial_chain,
                issuer,
            })),
        }
    }
}

// MARK: Rendering helpers

/// The critical extension OIDs of `cert` that are not in
/// `handled_critical_extensions`, in the order they appear in the
/// certificate. Computed on demand rather than at construction time, so that
/// emitting a diagnostic costs nothing when nobody renders it.
fn unhandled_critical_extensions(cert: &Certificate<'_>, handled_critical_extensions: &[Oid<'static>]) -> Vec<String> {
    cert.tbs_certificate
        .iter_extensions()
        .filter(|ext| ext.critical && !handled_critical_extensions.contains(&ext.oid))
        .map(|ext| ext.oid.to_id_string())
        .collect()
}

/// Renders each certificate on its own entry, joined by `separator`.
fn join_certificates(certificates: &[Certificate<'_>], separator: &str) -> String {
    certificates.iter().map(format_certificate).collect::<Vec<_>>().join(separator)
}

// MARK: Single-line description

impl fmt::Display for VerificationDiagnostic<'_> {
    /// A human readable, single-line description. This never contains a
    /// newline, whatever the payload: the whole point of this form is that a
    /// diagnostic occupies exactly one line in a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.storage {
            Storage::LeafCertificateHasUnhandledCriticalExtension(d) => write!(
                f,
                "The leaf certificate has critical extensions that the policy does not understand and therefore \
                 can't enforce. Unhandled extensions: [{}] Leaf certificate: {}",
                unhandled_critical_extensions(&d.leaf_certificate, &d.handled_critical_extensions).join(", "),
                format_certificate(&d.leaf_certificate),
            ),
            Storage::LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy(d) => write!(
                f,
                "Leaf certificate is in the root store of the verifier but it does by itself not meet the policy. \
                 Reason: {} Leaf Certificate: {}",
                d.failure_reason,
                format_certificate(&d.leaf_certificate),
            ),
            Storage::ChainFailsToMeetPolicy(d) => write!(
                f,
                "A certificate chain to a certificate in the root store was found but it does not meet the policy. \
                 Reason: {} Chain (from leaf to root): [{}]",
                d.failure_reason,
                join_certificates(&d.chain, ", "),
            ),
            Storage::IssuerHasUnhandledCriticalExtension(d) => write!(
                f,
                "A candidate issuer of a certificate in the (partial) chain has critical extensions that the policy \
                 does not understand and therefore can't enforce. Unhandled extensions: [{}] Chain (from leaf to \
                 candidate issuer that has critical extensions the policy doesn't enforce): [{}, {}]",
                unhandled_critical_extensions(&d.issuer, &d.handled_critical_extensions)
                    .iter()
                    .map(|oid| format!("- {oid}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                join_certificates(&d.partial_chain, ", "),
                format_certificate(&d.issuer),
            ),
            Storage::IssuerHasNotSignedCertificate(d) => write!(
                f,
                "A candidate issuer of a certificate in the (partial) chain has not signed the previous certificate \
                 in the chain. Chain (from leaf to candidate issuer that has not signed the certificate before it): \
                 [{}, {}]",
                join_certificates(&d.partial_chain, ", "),
                format_certificate(&d.issuer),
            ),
            Storage::SearchingForIssuerOfPartialChain(d) => write!(
                f,
                "Searching for issuers of partial candidate chain. Chain (from leaf to tip): [{}]",
                join_certificates(&d.partial_chain, ", "),
            ),
            Storage::FoundCandidateIssuersOfPartialChainInRootStore(d) => write!(
                f,
                "Found candidate issuers in the root store of the partial chain. Chain (from leaf to tip): [{}] \
                 Candidate issuers in the root store: [{}]",
                join_certificates(&d.partial_chain, ", "),
                join_certificates(&d.issuers_in_root_store, ", "),
            ),
            Storage::FoundCandidateIssuersOfPartialChainInIntermediateStore(d) => write!(
                f,
                "Found candidate issuers in the intermediate store of the partial chain. Chain (from leaf to tip): \
                 [{}] Candidate issuers in the intermediate store: [{}]",
                join_certificates(&d.partial_chain, ", "),
                join_certificates(&d.issuers_in_intermediate_store, ", "),
            ),
            Storage::FoundValidCertificateChain(d) => write!(
                f,
                "Validation completed successfully. Verified certificate chain (from leaf to root): [{}]",
                join_certificates(&d.valid_certificate_chain, ", "),
            ),
            Storage::CouldNotValidateLeafCertificate(d) => {
                write!(f, "Could not validate leaf certificate: {}", format_certificate(&d.leaf))
            }
            Storage::IssuerIsAlreadyInTheChain(d) => write!(
                f,
                "Candidate issuer is already in partial chain and is therefore skipped because it would always \
                 produce a chain that could have been shorter. Partial chain (from leaf to tip): [{}] Candidate \
                 issuer which is already in the chain above: {}",
                join_certificates(&d.partial_chain, ", "),
                format_certificate(&d.issuer),
            ),
        }
    }
}

impl fmt::Debug for VerificationDiagnostic<'_> {
    /// The single-line description, quoted and escaped so it can be embedded
    /// in a structural dump without breaking it apart.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_string())
    }
}

// MARK: Multi-line description

impl VerificationDiagnostic<'_> {
    /// A human readable description spread over multiple lines for better
    /// readability. Carries the same information as the [`Display`] form.
    pub fn multiline_description(&self) -> String {
        match &self.storage {
            Storage::LeafCertificateHasUnhandledCriticalExtension(d) => format!(
                "The leaf certificate has critical extensions that the policy does not understand and therefore \
                 can't enforce.\n\nUnhandled extensions:\n{}\n\nLeaf certificate:\n{}",
                unhandled_critical_extensions(&d.leaf_certificate, &d.handled_critical_extensions).join("\n"),
                format_certificate(&d.leaf_certificate),
            ),
            Storage::LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy(d) => format!(
                "Leaf certificate is in the root store of the verifier but it does by itself not meet the \
                 policy.\n\nReason:\n{}\n\nLeaf Certificate:\n{}",
                d.failure_reason,
                format_certificate(&d.leaf_certificate),
            ),
            Storage::ChainFailsToMeetPolicy(d) => format!(
                "A certificate chain to a certificate in the root store was found but it does not meet the \
                 policy.\n\nReason:\n{}\n\nChain (from leaf to root):\n{}",
                d.failure_reason,
                join_certificates(&d.chain, "\n"),
            ),
            Storage::IssuerHasUnhandledCriticalExtension(d) => format!(
                "A candidate issuer of a certificate in the (partial) chain has critical extensions that the policy \
                 does not understand and therefore can't enforce.\n\nUnhandled extensions:\n{}\n\nChain (from leaf \
                 to candidate issuer that has critical extensions the policy doesn't enforce):\n{}\n{}",
                unhandled_critical_extensions(&d.issuer, &d.handled_critical_extensions)
                    .iter()
                    .map(|oid| format!("- {oid}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                join_certificates(&d.partial_chain, "\n"),
                format_certificate(&d.issuer),
            ),
            Storage::IssuerHasNotSignedCertificate(d) => format!(
                "A candidate issuer of a certificate in the (partial) chain has not signed the previous certificate \
                 in the chain.\n\nChain (from leaf to candidate issuer that has not signed the certificate before \
                 it):\n{}\n{}",
                join_certificates(&d.partial_chain, "\n"),
                format_certificate(&d.issuer),
            ),
            Storage::SearchingForIssuerOfPartialChain(d) => format!(
                "Searching for issuers of partial candidate chain.\nChain (from leaf to tip):\n{}",
                join_certificates(&d.partial_chain, "\n"),
            ),
            Storage::FoundCandidateIssuersOfPartialChainInRootStore(d) => format!(
                "Found candidate issuers in the root store of the partial chain.\nChain (from leaf to \
                 tip):\n{}\nCandidate issuers in the root store:\n{}",
                join_certificates(&d.partial_chain, "\n"),
                join_certificates(&d.issuers_in_root_store, "\n"),
            ),
            Storage::FoundCandidateIssuersOfPartialChainInIntermediateStore(d) => format!(
                "Found candidate issuers in the intermediate store of the partial chain.\nChain (from leaf to \
                 tip):\n{}\nCandidate issuers in the intermediate store:\n{}",
                join_certificates(&d.partial_chain, "\n"),
                join_certificates(&d.issuers_in_intermediate_store, "\n"),
            ),
            Storage::FoundValidCertificateChain(d) => format!(
                "Validation completed successfully.\nVerified certificate chain (from leaf to root):\n{}",
                join_certificates(&d.valid_certificate_chain, "\n"),
            ),
            Storage::CouldNotValidateLeafCertificate(d) => {
                format!("Could not validate leaf certificate:\n{}", format_certificate(&d.leaf))
            }
            Storage::IssuerIsAlreadyInTheChain(d) => format!(
                "Candidate issuer is already in partial chain and is therefore skipped because it would always \
                 produce a chain that could have been shorter.\nPartial chain (from leaf to tip):\n{}\nCandidate \
                 issuer which is already in the chain above:\n{}",
                join_certificates(&d.partial_chain, "\n"),
                format_certificate(&d.issuer),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{issue_ca, issue_leaf, self_signed_ca_with};
    use x509_validator_core::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS;
    use x509_validator_core::FromDer;

    fn leak(der: Vec<u8>) -> &'static [u8] {
        Box::leak(der.into_boxed_slice())
    }

    fn parse(der: &'static [u8]) -> Certificate<'static> {
        Certificate::from_der(der).expect("parse certificate").1
    }

    /// A root, an intermediate issued by it, and a leaf issued by the
    /// intermediate — enough material to populate every variant.
    fn sample_chain() -> (Certificate<'static>, Certificate<'static>, Certificate<'static>) {
        let root = self_signed_ca_with("Diagnostic Root", |_| {});
        let intermediate = issue_ca("Diagnostic Intermediate", &root, None, |_| {});
        let leaf_der = leak(issue_leaf("diagnostic-leaf", &["www.example.com"], &intermediate));
        let intermediate_der = leak(intermediate.der.clone());
        let root_der = leak(root.der.clone());
        (parse(leaf_der), parse(intermediate_der), parse(root_der))
    }

    /// A self-signed CA carrying an unrecognized critical extension with OID
    /// 1.2.3.4.5, alongside the critical basicConstraints rcgen always adds.
    fn certificate_with_unknown_critical_extension() -> Certificate<'static> {
        let ca = self_signed_ca_with("Unknown Critical Ext", |params: &mut rcgen::CertificateParams| {
            let mut ext = rcgen::CustomExtension::from_oid_content(&[1, 2, 3, 4, 5], b"unrecognized".to_vec());
            ext.set_criticality(true);
            params.custom_extensions.push(ext);
        });
        parse(leak(ca.der.clone()))
    }

    /// Every variant, constructed over the same sample material. The
    /// invariant tests below iterate this table so a newly added variant is
    /// covered by construction.
    fn all_variants() -> Vec<VerificationDiagnostic<'static>> {
        let (leaf, intermediate, root) = sample_chain();
        let handled = vec![OID_X509_EXT_BASIC_CONSTRAINTS];
        let odd = certificate_with_unknown_critical_extension();

        vec![
            VerificationDiagnostic::leaf_certificate_has_unhandled_critical_extension(odd.clone(), handled.clone()),
            VerificationDiagnostic::leaf_certificate_is_in_the_root_store_but_does_not_meet_policy(
                leaf.clone(),
                PolicyFailureReason::new("leaf is not a valid trust anchor by itself"),
            ),
            VerificationDiagnostic::chain_fails_to_meet_policy(
                vec![leaf.clone(), intermediate.clone(), root.clone()],
                PolicyFailureReason::new("chain does not meet policy"),
            ),
            VerificationDiagnostic::issuer_has_unhandled_critical_extension(
                odd,
                vec![leaf.clone()],
                handled,
            ),
            VerificationDiagnostic::issuer_has_not_signed_certificate(root.clone(), vec![leaf.clone()]),
            VerificationDiagnostic::searching_for_issuer_of_partial_chain(vec![leaf.clone(), intermediate.clone()]),
            VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_root_store(
                vec![leaf.clone(), intermediate.clone()],
                vec![root.clone()],
            ),
            VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_intermediate_store(
                vec![leaf.clone()],
                vec![intermediate.clone()],
            ),
            VerificationDiagnostic::found_valid_certificate_chain(vec![leaf.clone(), intermediate.clone(), root.clone()]),
            VerificationDiagnostic::could_not_validate_leaf_certificate(leaf.clone()),
            VerificationDiagnostic::issuer_is_already_in_the_chain(vec![leaf, intermediate], root),
        ]
    }

    #[test]
    fn table_covers_every_variant() {
        assert_eq!(all_variants().len(), 11);
    }

    #[test]
    fn every_variant_renders_non_empty_single_and_multiline_forms() {
        for diagnostic in all_variants() {
            let single = diagnostic.to_string();
            let multi = diagnostic.multiline_description();
            assert!(!single.is_empty());
            assert!(!multi.is_empty());
            // Both forms must render certificates through the summary
            // formatter rather than dumping DER.
            assert!(!single.contains("X509Certificate"), "{single}");
            assert!(!multi.contains("X509Certificate"), "{multi}");
        }
    }

    #[test]
    fn single_line_description_never_contains_a_newline() {
        for diagnostic in all_variants() {
            let rendered = format!("{diagnostic}");
            assert!(!rendered.contains('\n'), "single-line description contains a newline: {rendered}");
        }
    }

    #[test]
    fn debug_is_the_quoted_single_line_description() {
        for diagnostic in all_variants() {
            assert_eq!(format!("{diagnostic:?}"), format!("{:?}", diagnostic.to_string()));
        }
    }

    #[test]
    fn multiline_description_contains_newlines_for_list_variants() {
        for diagnostic in all_variants() {
            let rendered = diagnostic.multiline_description();
            assert!(rendered.contains('\n'), "multiline description has no newline: {rendered}");
        }
    }

    #[test]
    fn chain_variants_put_each_certificate_on_its_own_line() {
        let (leaf, intermediate, root) = sample_chain();
        let diagnostic = VerificationDiagnostic::found_valid_certificate_chain(vec![leaf, intermediate, root]);

        let rendered = diagnostic.multiline_description();
        assert!(rendered.contains("Verified certificate chain (from leaf to root):\n"), "{rendered}");
        assert_eq!(rendered.matches("Certificate(version:").count(), 3, "{rendered}");
        // Three certificates, each on its own line.
        let certificate_lines = rendered.lines().filter(|line| line.starts_with("Certificate(version:")).count();
        assert_eq!(certificate_lines, 3, "{rendered}");
    }

    #[test]
    fn single_line_chain_variant_separates_certificates_with_commas() {
        let (leaf, intermediate, root) = sample_chain();
        let diagnostic = VerificationDiagnostic::chain_fails_to_meet_policy(
            vec![leaf, intermediate, root],
            PolicyFailureReason::new("expired"),
        );

        let rendered = diagnostic.to_string();
        assert!(rendered.contains("Reason: expired"), "{rendered}");
        assert!(rendered.contains("Chain (from leaf to root): ["), "{rendered}");
        assert_eq!(rendered.matches("Certificate(version:").count(), 3, "{rendered}");
    }

    #[test]
    fn leaf_unhandled_critical_extension_renders_only_the_unhandled_oids() {
        let cert = certificate_with_unknown_critical_extension();
        let diagnostic = VerificationDiagnostic::leaf_certificate_has_unhandled_critical_extension(
            cert,
            vec![OID_X509_EXT_BASIC_CONSTRAINTS],
        );

        let single = diagnostic.to_string();
        let multi = diagnostic.multiline_description();
        // The unrecognized extension is reported...
        assert!(single.contains("Unhandled extensions: [1.2.3.4.5]"), "{single}");
        assert!(multi.contains("Unhandled extensions:\n1.2.3.4.5\n"), "{multi}");
        // ...and the critical extension the policy does handle is not listed
        // as unhandled. It still appears in the certificate summary by name,
        // so check the unhandled list specifically.
        let unhandled = single.split("Unhandled extensions: [").nth(1).and_then(|rest| rest.split(']').next()).unwrap();
        assert_eq!(unhandled, "1.2.3.4.5");
    }

    #[test]
    fn leaf_with_only_handled_critical_extensions_reports_an_empty_unhandled_list() {
        let ca = self_signed_ca_with("All Handled", |_| {});
        let cert = parse(leak(ca.der.clone()));
        let diagnostic = VerificationDiagnostic::leaf_certificate_has_unhandled_critical_extension(
            cert,
            vec![OID_X509_EXT_BASIC_CONSTRAINTS],
        );

        let rendered = diagnostic.to_string();
        assert!(rendered.contains("Unhandled extensions: []"), "{rendered}");
    }

    #[test]
    fn issuer_unhandled_critical_extension_renders_only_the_unhandled_oids() {
        let (leaf, _, _) = sample_chain();
        let issuer = certificate_with_unknown_critical_extension();
        let diagnostic = VerificationDiagnostic::issuer_has_unhandled_critical_extension(
            issuer,
            vec![leaf],
            vec![OID_X509_EXT_BASIC_CONSTRAINTS],
        );

        let single = diagnostic.to_string();
        let multi = diagnostic.multiline_description();
        assert!(single.contains("Unhandled extensions: [- 1.2.3.4.5]"), "{single}");
        assert!(multi.contains("Unhandled extensions:\n- 1.2.3.4.5\n"), "{multi}");
        // basicConstraints is handled and must not be listed as unhandled.
        let unhandled = single.split("Unhandled extensions: [").nth(1).and_then(|rest| rest.split(']').next()).unwrap();
        assert_eq!(unhandled, "- 1.2.3.4.5");
    }

    #[test]
    fn issuer_unhandled_critical_extension_with_handling_policy_lists_nothing() {
        let (leaf, intermediate, _) = sample_chain();
        let diagnostic = VerificationDiagnostic::issuer_has_unhandled_critical_extension(
            intermediate,
            vec![leaf],
            vec![OID_X509_EXT_BASIC_CONSTRAINTS],
        );

        let rendered = diagnostic.to_string();
        assert!(rendered.contains("Unhandled extensions: []"), "{rendered}");
    }

    #[test]
    fn issuer_variants_append_the_issuer_after_the_partial_chain() {
        let (leaf, intermediate, root) = sample_chain();
        let diagnostic = VerificationDiagnostic::issuer_has_not_signed_certificate(root, vec![leaf, intermediate]);

        let single = diagnostic.to_string();
        assert!(single.starts_with("A candidate issuer of a certificate in the (partial) chain has not signed"), "{single}");
        // Two chain certificates plus the issuer.
        assert_eq!(single.matches("Certificate(version:").count(), 3, "{single}");
        assert!(single.contains("CN=Diagnostic Root"), "{single}");
    }

    #[test]
    fn already_in_chain_variant_names_the_repeated_issuer() {
        let (leaf, intermediate, root) = sample_chain();
        let diagnostic = VerificationDiagnostic::issuer_is_already_in_the_chain(vec![leaf, intermediate], root);

        let single = diagnostic.to_string();
        assert!(single.contains("Candidate issuer is already in partial chain and is therefore skipped"), "{single}");
        assert!(single.contains("Candidate issuer which is already in the chain above: "), "{single}");

        let multi = diagnostic.multiline_description();
        assert!(multi.contains("Partial chain (from leaf to tip):\n"), "{multi}");
        assert!(multi.contains("Candidate issuer which is already in the chain above:\n"), "{multi}");
    }

    #[test]
    fn could_not_validate_leaf_certificate_carries_the_leaf() {
        let (leaf, _, _) = sample_chain();
        let diagnostic = VerificationDiagnostic::could_not_validate_leaf_certificate(leaf);

        let single = diagnostic.to_string();
        assert!(single.starts_with("Could not validate leaf certificate: Certificate(version:"), "{single}");
        assert!(single.contains("CN=diagnostic-leaf"), "{single}");

        let multi = diagnostic.multiline_description();
        assert!(multi.starts_with("Could not validate leaf certificate:\nCertificate(version:"), "{multi}");
    }

    #[test]
    fn candidate_issuer_store_variants_name_their_store() {
        let (leaf, intermediate, root) = sample_chain();

        let from_roots = VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_root_store(
            vec![leaf.clone(), intermediate.clone()],
            vec![root],
        );
        assert!(from_roots.to_string().contains("Candidate issuers in the root store: ["));

        let from_intermediates = VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_intermediate_store(
            vec![leaf],
            vec![intermediate],
        );
        assert!(from_intermediates
            .to_string()
            .contains("Candidate issuers in the intermediate store: ["));
    }

    #[test]
    fn searching_for_issuer_renders_the_partial_chain() {
        let (leaf, intermediate, _) = sample_chain();
        let diagnostic = VerificationDiagnostic::searching_for_issuer_of_partial_chain(vec![leaf, intermediate]);

        let single = diagnostic.to_string();
        assert!(single.starts_with("Searching for issuers of partial candidate chain. Chain (from leaf to tip): ["), "{single}");
        assert_eq!(single.matches("Certificate(version:").count(), 2, "{single}");
    }

    #[test]
    fn leaf_in_root_store_variant_renders_the_policy_reason() {
        let (leaf, _, _) = sample_chain();
        let diagnostic = VerificationDiagnostic::leaf_certificate_is_in_the_root_store_but_does_not_meet_policy(
            leaf,
            PolicyFailureReason::new("no server auth EKU"),
        );

        let single = diagnostic.to_string();
        assert!(single.contains("Reason: no server auth EKU Leaf Certificate: Certificate(version:"), "{single}");

        let multi = diagnostic.multiline_description();
        assert!(multi.contains("Reason:\nno server auth EKU\n"), "{multi}");
    }
}
