use crate::crypto::CryptoProvider;
use crate::diagnostic::VerificationDiagnostic;
use crate::policy::{PolicyFailureReason, VerifierPolicy};
use crate::store::{subject_key, CertificateStore};
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use x509_validator_core::validated_chain::ValidatedCertificateChain;
use x509_validator_core::Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry::{OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER};
use x509_parser::prelude::FromDer;

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
/// RFC 5280-recommended signal that this is the intended issuer (especially
/// useful when a subject name has multiple issuing certificates in the
/// store, e.g. during root/intermediate rollover). Such candidates sort
/// before any candidate with no matching SKI/AKI pair. Candidates are
/// otherwise left in their original (store insertion) order — this is a
/// stable sort, and beyond the AKI/SKI signal the algorithm has no further
/// basis to prefer one candidate over another, so preserving insertion
/// order is the least surprising choice and keeps iteration deterministic
/// for a given store.
fn sort_by_suitability_for_issuing<'a>(candidates: &mut [Certificate<'a>], subject: &Certificate<'a>) {
    let subject_aki = authority_key_identifier(subject);

    let matches_aki = |candidate: &Certificate<'a>| -> bool {
        match (subject_aki, subject_key_identifier(candidate)) {
            (Some(aki), Some(ski)) => aki == ski,
            _ => false,
        }
    };

    // Stable sort: candidates matching AKI/SKI come first, tie-broken by
    // original (store) order.
    candidates.sort_by_key(|c| !matches_aki(c));
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

fn certificate_sans<'a>(c: &Certificate<'a>) -> Vec<x509_parser::extensions::GeneralName<'a>> {
    c.tbs_certificate
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| ext.value.general_names.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyFailureReason, VerifierPolicy};
    use crate::crypto::{CryptoError, Digest, KeyProvider, PublicKey};
    use crate::test_support::{issue_ca, issue_leaf, self_signed_ca_with};
    use x509_parser::prelude::FromDer;
    use x509_parser::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

    fn parse(der: &'static [u8]) -> Certificate<'static> {
        Certificate::from_der(der).unwrap().1
    }

    fn leak(der: Vec<u8>) -> &'static [u8] {
        Box::leak(der.into_boxed_slice())
    }

    // ---- Fake CryptoProvider wiring ----

    #[derive(Debug)]
    struct AlwaysValidKey;
    impl PublicKey for AlwaysValidKey {
        fn is_valid(&self, _signature: &[u8], _message: &[u8]) -> Result<(), CryptoError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct AlwaysValidKeyProvider;
    impl KeyProvider for AlwaysValidKeyProvider {
        fn public_key(&self, _algorithm: &AlgorithmIdentifier, _public_key: &SubjectPublicKeyInfo) -> Result<Box<dyn PublicKey>, CryptoError> {
            Ok(Box::new(AlwaysValidKey))
        }
    }

    #[derive(Debug)]
    struct FakeDigest;
    impl Digest for FakeDigest {
        fn hash(&self, _data: &[u8]) -> Vec<u8> {
            vec![0; 32]
        }
    }

    static ALWAYS_VALID_KEY_PROVIDER: AlwaysValidKeyProvider = AlwaysValidKeyProvider;
    static FAKE_DIGEST: FakeDigest = FakeDigest;

    fn always_valid_crypto() -> CryptoProvider {
        CryptoProvider {
            key_provider: &ALWAYS_VALID_KEY_PROVIDER,
            sha256: &FAKE_DIGEST,
        }
    }

    // ---- Fake VerifierPolicy ----

    struct AlwaysMeetsPolicy;
    impl VerifierPolicy for AlwaysMeetsPolicy {
        fn verifying_critical_extensions(&self) -> Vec<x509_parser::der_parser::Oid<'static>> {
            // rcgen always marks basicConstraints critical, so a fake
            // policy that claims no extensions would reject every
            // rcgen-generated CA/root as "unhandled critical extension".
            vec![x509_parser::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS]
        }
        fn chain_meets_policy_requirements(&mut self, _chain: &UnverifiedCertificateChain) -> crate::policy::PolicyEvaluationResult {
            Ok(())
        }
    }

    #[test]
    fn trivial_chain_succeeds_leaf_intermediate_root() {
        let root = self_signed_ca_with("root", |_| {});
        let intermediate = issue_ca("intermediate", &root, None, |_| {});
        let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
        let intermediate_der = leak(intermediate.der.clone());
        let root_der = leak(root.der.clone());

        let leaf = parse(leaf_der);
        let roots = CertificateStore::from_iter(vec![parse(root_der)]);
        let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        match result {
            ChainValidationResultOwned::ValidCertificate(chain) => {
                let certs: Vec<&Certificate> = chain.iter().collect();
                assert_eq!(certs.len(), 3);
            }
            ChainValidationResultOwned::CouldNotValidate(reasons) => {
                panic!("expected valid chain, got failures: {reasons:?}")
            }
        }
    }

    #[test]
    fn missing_issuer_fails() {
        let orphan = self_signed_ca_with("orphan", |_| {});
        let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &orphan));
        // Deliberately don't put `orphan` in either store, so the leaf's
        // issuer can never be found.
        let leaf = parse(leaf_der);
        let roots: CertificateStore = CertificateStore::new();
        let intermediates: CertificateStore = CertificateStore::new();
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert!(matches!(result, ChainValidationResultOwned::CouldNotValidate(_)));
    }

    #[test]
    fn leaf_directly_in_root_store_is_accepted_immediately() {
        let root = self_signed_ca_with("leaf-is-root", |_| {});
        let root_der = leak(root.der.clone());
        let leaf = parse(root_der);
        let roots = CertificateStore::from_iter(vec![parse(root_der)]);
        let intermediates: CertificateStore = CertificateStore::new();
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        match result {
            ChainValidationResultOwned::ValidCertificate(chain) => {
                let certs: Vec<&Certificate> = chain.iter().collect();
                assert_eq!(certs.len(), 1);
            }
            ChainValidationResultOwned::CouldNotValidate(reasons) => {
                panic!("expected immediate root acceptance, got failures: {reasons:?}")
            }
        }
    }

    #[test]
    fn candidate_with_non_verifying_signature_is_skipped() {
        struct RejectAllKey;
        impl PublicKey for RejectAllKey {
            fn is_valid(&self, _signature: &[u8], _message: &[u8]) -> Result<(), CryptoError> {
                Err(CryptoError::VerificationFailed)
            }
        }
        #[derive(Debug)]
        struct RejectAllProvider;
        impl std::fmt::Debug for RejectAllKey {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "RejectAllKey")
            }
        }
        impl KeyProvider for RejectAllProvider {
            fn public_key(&self, _algorithm: &AlgorithmIdentifier, _public_key: &SubjectPublicKeyInfo) -> Result<Box<dyn PublicKey>, CryptoError> {
                Ok(Box::new(RejectAllKey))
            }
        }
        static REJECT_ALL: RejectAllProvider = RejectAllProvider;

        let root = self_signed_ca_with("root", |_| {});
        let intermediate = issue_ca("intermediate", &root, None, |_| {});
        let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
        let intermediate_der = leak(intermediate.der.clone());
        let root_der = leak(root.der.clone());

        let leaf = parse(leaf_der);
        let roots = CertificateStore::from_iter(vec![parse(root_der)]);
        let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
        let crypto = CryptoProvider {
            key_provider: &REJECT_ALL,
            sha256: &FAKE_DIGEST,
        };
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert!(matches!(result, ChainValidationResultOwned::CouldNotValidate(_)));
    }

    #[test]
    fn candidate_with_unhandled_critical_extension_is_skipped() {
        // A root carrying an unrecognized critical extension must be
        // skipped as a candidate issuer, so a leaf whose only path runs
        // through it fails to validate.
        let root = self_signed_ca_with("root", |params: &mut rcgen::CertificateParams| {
            params.custom_extensions.push(rcgen::CustomExtension::from_oid_content(
                &[1, 2, 3, 4, 5],
                b"unrecognized".to_vec(),
            ));
            let mut ext = params.custom_extensions.last().unwrap().clone();
            ext.set_criticality(true);
            *params.custom_extensions.last_mut().unwrap() = ext;
        });
        let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &root));
        let root_der = leak(root.der.clone());

        let leaf = parse(leaf_der);
        let roots = CertificateStore::from_iter(vec![parse(root_der)]);
        let intermediates: CertificateStore = CertificateStore::new();
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert!(matches!(result, ChainValidationResultOwned::CouldNotValidate(_)));
    }

    #[test]
    fn policy_failure_on_first_root_candidate_continues_search() {
        // Two roots share the same subject name "root"; only the second
        // one (by insertion order, since no AKI/SKI is set to reorder them)
        // satisfies the policy. Confirms policy failures accumulate and the
        // DFS keeps trying further candidates rather than stopping at the
        // first failure.
        struct RequireRootKeyPolicy {
            right_root_spki: Vec<u8>,
        }
        impl VerifierPolicy for RequireRootKeyPolicy {
            fn verifying_critical_extensions(&self) -> Vec<x509_parser::der_parser::Oid<'static>> {
                vec![x509_parser::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS]
            }
            fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> crate::policy::PolicyEvaluationResult {
                let root = &chain[chain.len() - 1];
                if root.public_key().subject_public_key.as_ref() == self.right_root_spki.as_slice() {
                    Ok(())
                } else {
                    Err(PolicyFailureReason::new("wrong root key"))
                }
            }
        }

        let wrong_root = self_signed_ca_with("root", |_| {});
        let right_root = self_signed_ca_with("root", |_| {});
        let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &right_root));
        let wrong_root_der = leak(wrong_root.der.clone());
        let right_root_der = leak(right_root.der.clone());

        let leaf = parse(leaf_der);
        let right_root_cert = parse(right_root_der);
        let right_root_spki = right_root_cert.public_key().subject_public_key.as_ref().to_vec();
        let roots = CertificateStore::from_iter(vec![parse(wrong_root_der), right_root_cert]);
        let intermediates: CertificateStore = CertificateStore::new();
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, RequireRootKeyPolicy { right_root_spki: right_root_spki.clone() }, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        match result {
            ChainValidationResultOwned::ValidCertificate(chain) => {
                assert_eq!(chain.root().public_key().subject_public_key.as_ref(), right_root_spki.as_slice());
            }
            ChainValidationResultOwned::CouldNotValidate(reasons) => {
                panic!("expected eventual success, got: {reasons:?}")
            }
        }
    }
}