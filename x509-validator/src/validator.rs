use std::fmt;
use crate::crypto::SignatureVerifier;
use crate::diagnostic::VerificationDiagnostic;
use crate::store::CertificateStore;
use crate::unverified_chain::UnverifiedCertificateChain;
use crate::validated_chain::ValidatedCertificateChain;
use crate::{Certificate, CertificateExt};
use crate::{PolicyFailureReason, ValidationPolicy};

/// Validates an X.509 certificate chain against a set of root certificates and
/// a [`ValidationPolicy`], using the crypto backend selected by this crate's
/// feature flags.
///
/// ```ignore
/// let validator = x509_validator::Validator::with_policy(roots, policy);
/// ```
pub struct Validator<'a, P> {
    /// The trusted root certificates used to anchor chain validation.
    root_certificates: CertificateStore<'a>,
    crypto: &'a dyn SignatureVerifier,
    /// The policy applied to candidate chains during validation.
    policy: P,
}

impl<'a, P> Validator<'a, P>
where
    P: ValidationPolicy,
{
    /// Creates a validator with the given root certificates, policy and backend.
    ///
    /// - Parameters:
    ///   - root_certificates: The trusted root certificates.
    ///   - policy: The verification policy.
    pub fn with_policy_and_backend(root_certificates: CertificateStore<'a>, policy: P, crypto: &'a dyn SignatureVerifier) -> Self {
        Self {
            root_certificates,
            crypto,
            policy,
        }
    }

    /// Creates a validator with the given root certificates and policy, using
    /// the crypto backend selected by this crate's feature flags.
    ///
    /// - Parameters:
    ///   - root_certificates: The trusted root certificates.
    ///   - policy: The verification policy.
    ///
    /// # Panics
    ///
    /// Validation panics unless exactly one backend feature is enabled, since
    /// no single default backend can be determined otherwise; see
    /// [`crate::crypto::default_provider`].
    pub fn with_policy(root_certificates: CertificateStore<'a>, policy: P) -> Self {
        Self::with_policy_and_backend(root_certificates, policy, crate::crypto::default_provider())
    }

    /// Validates a leaf certificate by building chains through intermediate certificates to the root store.
    ///
    /// - Parameters:
    ///   - leaf: The leaf certificate to validate.
    ///   - intermediates: A store of intermediate certificates that may form part of the chain.
    ///   - diagnostic_callback: A closure invoked with diagnostic events during validation.
    /// - Returns: A [`ChainValidationResult`] indicating whether the certificate is valid.
    pub fn validate_with_diagnostics(
        &self,
        leaf: &Certificate<'a>,
        intermediates: &CertificateStore<'a>,
        diagnostic_callback: &mut dyn FnMut(VerificationDiagnostic),
    ) -> ChainValidationResult<'a> {
        // First check: does this leaf certificate contain critical extensions that are not satisfied by the policy?
        // If so, reject the chain.
        if has_unhandled_critical_extensions(leaf, &self.policy) {
            diagnostic_callback(VerificationDiagnostic::leaf_certificate_has_unhandled_critical_extension(
                leaf.clone(),
                self.policy.verifying_critical_extensions(),
            ));
            return Err(vec![PolicyFailure::new(
                UnverifiedCertificateChain::new(vec![leaf.clone()]),
                PolicyFailureReason::new("leaf certificate has unhandled critical extension"),
            )]);
        }

        let mut policy_failures = Vec::new();

        // Second check: is this leaf _already in_ the certificate store? If it is, we can just trust it directly.
        //
        // Note that this requires an _exact match_: if there isn't an exact match, we'll fall back to chain building,
        // which may let us chain through another variant of this certificate and build a valid chain. This is a very
        // deliberate choice: certificates that assert the same combination of (subject, public key, SAN) but different
        // extensions or policies should not be tolerated by this check, and will be ignored.
        let leaf_key = leaf.subject_key();
        if self.root_certificates.find_by_subject(&leaf_key).iter().any(|c| c == leaf) {
            let chain = UnverifiedCertificateChain::new(vec![leaf.clone()]);
            match self.policy.chain_meets_policy_requirements(&chain) {
                Ok(()) => {
                    // We're good!
                    diagnostic_callback(VerificationDiagnostic::found_valid_certificate_chain(vec![leaf.clone()]));
                    return Ok(ValidatedCertificateChain::new_unchecked(vec![leaf.clone()]));
                }
                Err(reason) => {
                    diagnostic_callback(
                        VerificationDiagnostic::leaf_certificate_is_in_the_root_store_but_does_not_meet_policy(leaf.clone(), reason.clone()),
                    );
                    policy_failures.push(PolicyFailure::new(chain, reason));
                }
            }
        }

        let mut stack: Vec<Vec<Certificate<'a>>> = vec![vec![leaf.clone()]];

        // This is essentially a DFS of the certificate tree. We attempt to iteratively build up possible chains.
        while let Some(partial_chain) = stack.pop() {
            diagnostic_callback(VerificationDiagnostic::searching_for_issuer_of_partial_chain(partial_chain.clone()));

            let tip = partial_chain.last().unwrap();
            let issuer_key = tip.issuer_key();

            // We want to search for parents. Our preferred parent comes from the root store, as this will potentially
            // produce smaller chains.
            let mut root_candidates = self.root_certificates.find_by_subject(&issuer_key).to_vec();
            // We then want to sort by suitability.
            sort_by_suitability_for_issuing(&mut root_candidates, tip);
            if !root_candidates.is_empty() {
                diagnostic_callback(VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_root_store(
                    partial_chain.clone(),
                    root_candidates.clone(),
                ));
            }
            // Each of these is now potentially a valid unverified chain.
            for candidate in &root_candidates {
                if should_skip_adding_certificate(candidate, &partial_chain, self.crypto, &self.policy, diagnostic_callback) {
                    continue;
                }
                let mut chain_certs = partial_chain.clone();
                chain_certs.push(candidate.clone());
                let chain = UnverifiedCertificateChain::new(chain_certs.clone());
                match self.policy.chain_meets_policy_requirements(&chain) {
                    Ok(()) => {
                        // We're good!
                        diagnostic_callback(VerificationDiagnostic::found_valid_certificate_chain(chain_certs.clone()));
                        return Ok(ValidatedCertificateChain::new_unchecked(chain_certs));
                    }
                    Err(reason) => {
                        diagnostic_callback(VerificationDiagnostic::chain_fails_to_meet_policy(chain_certs, reason.clone()));
                        policy_failures.push(PolicyFailure::new(chain, reason));
                    }
                }
            }

            let mut intermediate_candidates = intermediates.find_by_subject(&issuer_key).to_vec();
            // We then want to sort by suitability.
            sort_by_suitability_for_issuing(&mut intermediate_candidates, tip);
            if !intermediate_candidates.is_empty() {
                diagnostic_callback(
                    VerificationDiagnostic::found_candidate_issuers_of_partial_chain_in_intermediate_store(
                        partial_chain.clone(),
                        intermediate_candidates.clone(),
                    ),
                );
            }
            // we need to reverse the order of the already sorted intermediates because
            // we will push them on to the `stack` which in turn will
            // consume them in the reverse order that they have been pushed onto the stack
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
        Err(policy_failures)
    }
}

fn has_unhandled_critical_extensions(
    cert: &Certificate<'_>,
    policy: &impl ValidationPolicy,
) -> bool {
    let handled = policy.verifying_critical_extensions();
    cert.tbs_certificate.iter_extensions().any(|ext| ext.critical && !handled.contains(&ext.oid))
}

fn sort_by_suitability_for_issuing<'a>(candidates: &mut [Certificate<'a>], subject: &Certificate<'a>) {
    // First, an early exit. If the subject doesn't have an AKI extension, we don't need
    // to do anything.
    let subject_aki = subject.authority_key_identifier();

    // Medium preference if we have no SKI. The SKI is present: if the two match, this is
    // higher preference; if they don't match, it's lower.
    let rank = |candidate: &Certificate<'a>| -> u8 {
        match (subject_aki, candidate.subject_key_identifier()) {
            (Some(aki), Some(ski)) if aki == ski => 0,
            (_, None) => 1,
            (None, Some(_)) => 1,
            (Some(_), Some(_)) => 2,
        }
    };

    candidates.sort_by_key(rank);
}

fn should_skip_adding_certificate<'a>(
    candidate: &Certificate<'a>,
    partial_chain: &[Certificate<'a>],
    crypto: &dyn SignatureVerifier,
    policy: &impl ValidationPolicy,
    diagnostic_callback: &mut dyn FnMut(VerificationDiagnostic<'a>),
) -> bool {
    // We want to confirm that the certificate has no unhandled critical extensions. If it does, we can't build the chain.
    if has_unhandled_critical_extensions(candidate, policy) {
        diagnostic_callback(VerificationDiagnostic::issuer_has_unhandled_critical_extension(
            candidate.clone(),
            partial_chain.to_vec(),
            policy.verifying_critical_extensions(),
        ));
        return true;
    }

    // We don't want to re-add the same certificate to the chain: that will always produce a chain that
    // could have been shorter.
    if partial_chain.iter().any(|existing| existing.has_same_identity_as(candidate)) {
        diagnostic_callback(VerificationDiagnostic::issuer_is_already_in_the_chain(
            partial_chain.to_vec(),
            candidate.clone(),
        ));
        return true;
    }

    // We check the signature here: if the signature isn't valid, don't try to apply policy.
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


/// The result of validating a certificate chain.
///
/// The error case carries every chain that was built and rejected, each with
/// the reason it was rejected, in the order the implementation considered them.
pub type ChainValidationResult<'a> = Result<ValidatedCertificateChain<'a>, Vec<PolicyFailure<'a>>>;

/// A chain that was built but rejected by policy, and why.
#[derive(Clone)]
pub struct PolicyFailure<'a> {
    pub chain: UnverifiedCertificateChain<'a>,
    pub policy_failure_reason: PolicyFailureReason,
}

impl<'a> PolicyFailure<'a> {
    pub fn new(chain: UnverifiedCertificateChain<'a>, policy_failure_reason: PolicyFailureReason) -> Self {
        Self {
            chain,
            policy_failure_reason,
        }
    }
}

impl fmt::Display for PolicyFailure<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.policy_failure_reason)
    }
}

impl fmt::Debug for PolicyFailure<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (chain of {})", self.policy_failure_reason, self.chain.len())
    }
}
