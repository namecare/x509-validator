use crate::certificate_display::format_certificate;
use crate::policy::PolicyFailureReason;
use std::fmt;
use x509_validator_core::der_parser::Oid;
use x509_validator_core::Certificate;

pub struct VerificationDiagnostic<'a> {
    storage: Storage<'a>,
}

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

fn unhandled_critical_extensions(cert: &Certificate<'_>, handled_critical_extensions: &[Oid<'static>]) -> Vec<String> {
    cert.tbs_certificate
        .iter_extensions()
        .filter(|ext| ext.critical && !handled_critical_extensions.contains(&ext.oid))
        .map(|ext| ext.oid.to_id_string())
        .collect()
}

fn join_certificates(certificates: &[Certificate<'_>], separator: &str) -> String {
    certificates.iter().map(format_certificate).collect::<Vec<_>>().join(separator)
}

// MARK: Single-line description

impl fmt::Display for VerificationDiagnostic<'_> {
    /// Produces a human readable description of this [`VerificationDiagnostic`] that is potentially expensive to compute.
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
                "Leaf certificate is in the root store of the validator but it does by itself not meet the policy. \
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // this just adds quotes around the string and escapes any characters not suitable for displaying in a structural display.
        write!(f, "{:?}", self.to_string())
    }
}

// MARK: Multi-line description

impl VerificationDiagnostic<'_> {
    /// Produces a human readable description of this [`VerificationDiagnostic`] over multiple lines for better readability
    /// but includes otherwise the same information as the [`Display`](fmt::Display) form.
    pub fn multiline_description(&self) -> String {
        match &self.storage {
            Storage::LeafCertificateHasUnhandledCriticalExtension(d) => format!(
                "The leaf certificate has critical extensions that the policy does not understand and therefore \
                 can't enforce.\n\nUnhandled extensions:\n{}\n\nLeaf certificate:\n{}",
                unhandled_critical_extensions(&d.leaf_certificate, &d.handled_critical_extensions).join("\n"),
                format_certificate(&d.leaf_certificate),
            ),
            Storage::LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy(d) => format!(
                "Leaf certificate is in the root store of the validator but it does by itself not meet the \
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

