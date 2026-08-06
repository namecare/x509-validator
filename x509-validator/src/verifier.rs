use crate::crypto::CryptoProvider;
use crate::diagnostic::VerificationDiagnostic;
use crate::policy::{PolicyFailureReason, VerifierPolicy};
use crate::store::{subject_key, CertificateStore};
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use x509_validator_core::validated_chain::ValidatedCertificateChain;
use x509_validator_core::Certificate;
use x509_validator_core::extensions::ParsedExtension;
use x509_validator_core::oid_registry::{OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER};
use x509_validator_core::FromDer;

/// Parses each DER-encoded certificate in `der` and collects the results
/// into a `CertificateStore`. Fails on the first certificate that doesn't
/// parse, since a malformed intermediate makes the rest of the supplied set
/// untrustworthy as a chain-building input.
fn parse_certificate_store<'a>(der: &'a [Vec<u8>]) -> Result<CertificateStore<'a>, PolicyFailureReason> {
    let mut store = CertificateStore::new();
    for bytes in der {
        let (_, certificate) = Certificate::from_der(bytes).map_err(|_| PolicyFailureReason::new("failed to parse certificate DER"))?;
        store.append(certificate);
    }
    Ok(store)
}

/// The `subjectKeyIdentifier`/`authorityKeyIdentifier` key-identifier bytes
/// for a certificate, if the corresponding extension is present and parses.
/// `x509-parser`'s `TbsCertificate` has no dedicated accessor for either
/// (unlike `basic_constraints`/`name_constraints`/`subject_alternative_name`),
/// so both go through `get_extension_unique` + `ParsedExtension` matching.
fn subject_key_identifier<'a>(cert: &Certificate<'a>) -> Option<&'a [u8]> {
    let ext = cert.tbs_certificate.get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER).ok()??;
    match ext.parsed_extension() {
        ParsedExtension::SubjectKeyIdentifier(key_id) => Some(key_id.0),
        _ => None,
    }
}

fn authority_key_identifier<'a>(cert: &Certificate<'a>) -> Option<&'a [u8]> {
    let ext = cert.tbs_certificate.get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER).ok()??;
    match ext.parsed_extension() {
        ParsedExtension::AuthorityKeyIdentifier(aki) => aki.key_identifier.as_ref().map(|id| id.0),
        _ => None,
    }
}

pub struct BaseVerifier<'a, P> {
    root_certificates: CertificateStore<'a>,
    crypto: &'a CryptoProvider,
    policy: P,
}

impl<'a, P> BaseVerifier<'a, P>
where
    P: VerifierPolicy,
{
    pub fn with_policy_and_backend(root_certificates: CertificateStore<'a>, policy: P, crypto: &'a CryptoProvider) -> Self {
        Self {
            root_certificates,
            crypto,
            policy,
        }
    }

    /// Builds and validates a certificate chain from `leaf` up to a trusted
    /// root, using a depth-first search over candidate issuers drawn from
    /// the root store and `intermediates`. Returns the first chain that
    /// satisfies `self.policy`, or every accumulated policy failure if no
    /// chain satisfies it.
    pub fn validate(&mut self, leaf: &Certificate<'a>, intermediates: &'a [Vec<u8>]) -> ChainValidationResultOwned<'a> {
        let store = match parse_certificate_store(intermediates) {
            Ok(store) => store,
            Err(reason) => return ChainValidationResultOwned::CouldNotValidate(vec![reason]),
        };
        self.validate_with_diagnostics(leaf, &store, &mut |_: VerificationDiagnostic| {})
    }

    /// Same as `validate`, but calls `diagnostic_callback` with progress and
    /// failure events during chain building, useful for debugging and
    /// detailed error reporting.
    pub fn validate_with_diagnostics(
        &mut self,
        leaf: &Certificate<'a>,
        intermediates: &CertificateStore<'a>,
        diagnostic_callback: &mut dyn FnMut(VerificationDiagnostic),
    ) -> ChainValidationResultOwned<'a> {
        if has_unhandled_critical_extensions(leaf, &self.policy) {
            diagnostic_callback(VerificationDiagnostic::leaf_certificate_has_unhandled_critical_extension(
                leaf.clone(),
                self.policy.verifying_critical_extensions(),
            ));
            return ChainValidationResultOwned::CouldNotValidate(vec![PolicyFailureReason::new(
                "leaf certificate has unhandled critical extension",
            )]);
        }

        let mut policy_failures = Vec::new();

        let leaf_key = subject_key(leaf);
        if self.root_certificates.find_by_subject(&leaf_key).iter().any(|c| c == leaf) {
            let chain = UnverifiedCertificateChain::new(vec![leaf.clone()]);
            match self.policy.chain_meets_policy_requirements(&chain) {
                Ok(()) => {
                    diagnostic_callback(VerificationDiagnostic::found_valid_certificate_chain(vec![leaf.clone()]));
                    return ChainValidationResultOwned::ValidCertificate(ValidatedCertificateChain::new_unchecked(vec![leaf.clone()]));
                }
                Err(reason) => {
                    diagnostic_callback(
                        VerificationDiagnostic::leaf_certificate_is_in_the_root_store_but_does_not_meet_policy(leaf.clone(), reason.clone()),
                    );
                    policy_failures.push(reason);
                }
            }
        }

        let mut stack: Vec<Vec<Certificate<'a>>> = vec![vec![leaf.clone()]];

        while let Some(partial_chain) = stack.pop() {
            diagnostic_callback(VerificationDiagnostic::searching_for_issuer_of_partial_chain(partial_chain.clone()));

            let tip = partial_chain.last().unwrap();
            let issuer_key = issuer_key_of(tip);

            let mut root_candidates = self.root_certificates.find_by_subject(&issuer_key).to_vec();
            sort_by_suitability_for_issuing(&mut root_candidates, tip);
            if !root_candidates.is_empty() {
                diagnostic_callback(VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_root_store(
                    partial_chain.clone(),
                    root_candidates.clone(),
                ));
            }
            for candidate in &root_candidates {
                if should_skip_adding_certificate(candidate, &partial_chain, self.crypto, &self.policy, diagnostic_callback) {
                    continue;
                }
                let mut chain_certs = partial_chain.clone();
                chain_certs.push(candidate.clone());
                let chain = UnverifiedCertificateChain::new(chain_certs.clone());
                match self.policy.chain_meets_policy_requirements(&chain) {
                    Ok(()) => {
                        diagnostic_callback(VerificationDiagnostic::found_valid_certificate_chain(chain_certs.clone()));
                        return ChainValidationResultOwned::ValidCertificate(ValidatedCertificateChain::new_unchecked(chain_certs));
                    }
                    Err(reason) => {
                        diagnostic_callback(VerificationDiagnostic::chain_fails_to_meet_policy(chain_certs, reason.clone()));
                        policy_failures.push(reason);
                    }
                }
            }

            let mut intermediate_candidates = intermediates.find_by_subject(&issuer_key).to_vec();
            sort_by_suitability_for_issuing(&mut intermediate_candidates, tip);
            if !intermediate_candidates.is_empty() {
                diagnostic_callback(
                    VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_intermediate_store(
                        partial_chain.clone(),
                        intermediate_candidates.clone(),
                    ),
                );
            }
            for candidate in intermediate_candidates.into_iter().rev() {
                if should_skip_adding_certificate(&candidate, &partial_chain, self.crypto, &self.policy, diagnostic_callback) {
                    continue;
                }
                let mut next = partial_chain.clone();
                next.push(candidate);
                stack.push(next);
            }
        }

        diagnostic_callback(VerificationDiagnostic::could_not_validate_leaf_certificate(leaf.clone()));
        ChainValidationResultOwned::CouldNotValidate(policy_failures)
    }
}

/// Outcome of `BaseVerifier::validate`/`validate_with_diagnostics`: either a
/// validated chain, or every policy failure accumulated across the DFS
/// (unlike `x509_validator_core::ChainValidationResult`, which reports a
/// single `PolicyFailure` alongside the unverified chain that produced it).
pub enum ChainValidationResultOwned<'a> {
    ValidCertificate(ValidatedCertificateChain<'a>),
    CouldNotValidate(Vec<PolicyFailureReason>),
}

/// True if `cert` carries a critical extension whose OID is not among the
/// ones `policy` declares it understands and enforces
/// (`VerifierPolicy::verifying_critical_extensions`). Per RFC 5280 section
/// 4.2, a certificate consumer must reject a certificate that contains a
/// critical extension it does not recognize.
fn has_unhandled_critical_extensions(cert: &Certificate, policy: &impl VerifierPolicy) -> bool {
    let handled = policy.verifying_critical_extensions();
    cert.tbs_certificate.iter_extensions().any(|ext| ext.critical && !handled.contains(&ext.oid))
}

/// Canonical lookup key for the *issuer* name of a certificate (as opposed
/// to `subject_key`, which keys by the certificate's own subject). Both use
/// the same canonical-DER byte representation so entries stored by subject
/// can be found by an issuer-name lookup.
fn issuer_key_of(cert: &Certificate) -> Vec<u8> {
    cert.issuer().as_raw().to_vec()
}

/// Orders candidate issuers by how well-suited they are to have issued
/// `subject`, most-suitable first.
///
/// Ordering rule: a candidate whose `subject_key_identifier` matches
/// `subject`'s `authority_key_identifier().key_identifier` is a strong,
/// RFC 5280 §4.2.1.1-recommended signal that this is the intended issuer
/// (especially useful when a subject name has multiple issuing certificates
/// in the store, e.g. during root/intermediate rollover).
///
/// The ranking is three-way, not two-way, as RFC 4158 §3.5.3 describes: a
/// *missing* `subjectKeyIdentifier` and a *mismatching* one are not
/// equivalent. RFC 5280 §4.2.1.2 leaves the extension optional, so a
/// candidate that omits it supplies no evidence either way and remains
/// plausible; a candidate that carries one which differs from the subject's
/// AKI supplies positive evidence that it is the wrong issuer, and so is
/// tried last.
///
/// Within a rank, candidates keep their original (store insertion) order —
/// this is a stable sort, and beyond the AKI/SKI signal the algorithm has no
/// further basis to prefer one candidate over another, so preserving
/// insertion order is the least surprising choice and keeps iteration
/// deterministic for a given store.
fn sort_by_suitability_for_issuing<'a>(candidates: &mut [Certificate<'a>], subject: &Certificate<'a>) {
    let subject_aki = authority_key_identifier(subject);

    // 0: SKI matches the subject's AKI. 1: no SKI, so no evidence.
    // 2: SKI present but different, i.e. evidence of the wrong issuer.
    let rank = |candidate: &Certificate<'a>| -> u8 {
        match (subject_aki, subject_key_identifier(candidate)) {
            (Some(aki), Some(ski)) if aki == ski => 0,
            (_, None) => 1,
            (None, Some(_)) => 1,
            (Some(_), Some(_)) => 2,
        }
    };

    candidates.sort_by_key(rank);
}

/// True if `candidate` should not be added to `partial_chain`: it carries an
/// unhandled critical extension, it is already present in the chain by
/// identity (see `same_certificate_identity`), or its signature over the
/// current chain tip does not verify.
///
/// `policy` is threaded through explicitly (rather than only being
/// available at the leaf check) because "unhandled" is meaningless without
/// knowing which critical extensions the policy declares it understands —
/// the same policy object passed to `validate` is used here so per-candidate
/// critical-extension policing is consistent with the leaf check.
fn should_skip_adding_certificate<'a>(
    candidate: &Certificate<'a>,
    partial_chain: &[Certificate<'a>],
    crypto: &CryptoProvider,
    policy: &impl VerifierPolicy,
    diagnostic_callback: &mut dyn FnMut(VerificationDiagnostic<'a>),
) -> bool {
    if has_unhandled_critical_extensions(candidate, policy) {
        diagnostic_callback(VerificationDiagnostic::issuer_has_unhandled_critical_extension(
            candidate.clone(),
            partial_chain.to_vec(),
            policy.verifying_critical_extensions(),
        ));
        return true;
    }

    if partial_chain.iter().any(|existing| same_certificate_identity(existing, candidate)) {
        diagnostic_callback(VerificationDiagnostic::issuer_is_already_in_the_chain(
            partial_chain.to_vec(),
            candidate.clone(),
        ));
        return true;
    }

    let tip = partial_chain.last().unwrap();
    let signature_verifies = crypto
        .verify_signature(
            &tip.signature_algorithm,
            candidate.public_key(),
            tip.tbs_certificate.as_ref(),
            tip.signature_value.as_ref(),
        )
        .is_ok();

    if !signature_verifies {
        diagnostic_callback(VerificationDiagnostic::issuer_has_not_signed_certificate(
            candidate.clone(),
            partial_chain.to_vec(),
        ));
    }

    !signature_verifies
}

/// Identity used for loop prevention during chain building: subject name +
/// public key + subject alternative names. Deliberately NOT full DER
/// equality — two distinct DER encodings can represent semantically-equal
/// certificates, and (more importantly) this stops the DFS from looping
/// forever on a structurally distinct but logically-repeated certificate
/// (e.g. a cross-signed or reissued cert with the same subject/key/SANs but
/// different signature bytes).
fn same_certificate_identity(a: &Certificate, b: &Certificate) -> bool {
    if a.subject() != b.subject() {
        return false;
    }
    if a.public_key() != b.public_key() {
        return false;
    }
    certificate_sans(a) == certificate_sans(b)
}

fn certificate_sans<'a>(c: &Certificate<'a>) -> Vec<x509_validator_core::extensions::GeneralName<'a>> {
    c.tbs_certificate
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| ext.value.general_names.clone())
        .unwrap_or_default()
}
