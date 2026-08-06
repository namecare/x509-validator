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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyFailureReason, VerifierPolicy};
    use crate::crypto::{CryptoError, Digest, KeyProvider, PublicKey};
    use x509_validator_testkit::{
        issue_ca, issue_ca_with_key, issue_ca_with_key_and_name, issue_ca_with_key_ids, issue_leaf, issue_leaf_with,
        issue_leaf_with_aki, self_signed_ca_with, self_signed_ca_with_key_ids, signing_identity,
        weird_critical_extension, Ski,
    };
    use x509_validator_testkit::rcgen::KeyPair;
    use std::sync::Mutex;
    use x509_validator_core::FromDer;
    use x509_validator_core::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

    fn parse(der: &'static [u8]) -> Certificate<'static> {
        Certificate::from_der(der).unwrap().1
    }

    /// Asserts that `result` is a valid chain whose certificates are exactly
    /// `expected`, in leaf-to-root order. Comparison is on the full DER of
    /// each certificate, so this catches a chain containing the right number
    /// of certificates in the wrong order just as readily as a wrong one.
    fn assert_chain_is(result: ChainValidationResultOwned<'_>, expected: &[&Certificate<'_>]) {
        match result {
            ChainValidationResultOwned::ValidCertificate(chain) => {
                let actual: Vec<&[u8]> = chain.iter().map(|c| c.as_ref()).collect();
                let expected: Vec<&[u8]> = expected.iter().map(|c| c.as_ref()).collect();
                assert_eq!(actual, expected, "chain contents or order differ from expectation");
            }
            ChainValidationResultOwned::CouldNotValidate(reasons) => {
                panic!("expected a valid chain, got failures: {reasons:?}")
            }
        }
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

    // ---- Discriminating CryptoProvider ----
    //
    // `always_valid_crypto` treats every candidate issuer as having signed
    // every certificate, which makes any assertion about *which* issuer the
    // search accepts vacuous: RFC 5280 §6.1.3(a)(1) requires the candidate's
    // public key to actually verify the signature on the certificate below
    // it, and a no-op verifier never enforces that.
    //
    // The provider below enforces it without doing asymmetric crypto. Every
    // certificate generated for a test is registered with the DER-encoded
    // `SubjectPublicKeyInfo` of the key that genuinely signed it, keyed by
    // the certificate's own `tbsCertificate` bytes — which are exactly the
    // `message` the verifier passes down. Verification then reduces to
    // "is the candidate's SPKI the SPKI that signed this?", which
    // discriminates precisely the way a real signature check does for these
    // fixtures, and fails for exactly the same candidates.

    /// Pairs of (`tbsCertificate` DER, DER-encoded `SubjectPublicKeyInfo` of
    /// the key that signed it).
    type SignerRegistry = Mutex<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Maps a certificate's `tbsCertificate` DER to the DER-encoded
    /// `SubjectPublicKeyInfo` of the key that signed it.
    fn signer_registry() -> &'static SignerRegistry {
        static REGISTRY: std::sync::OnceLock<SignerRegistry> = std::sync::OnceLock::new();
        REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
    }

    /// Registers `der` as having been signed by `signer`, then leaks and
    /// returns it so it can be parsed with a `'static` lifetime. Every
    /// fixture in a test using [`discriminating_crypto`] must go through
    /// this, or its signature will be treated as unverifiable.
    fn leak_signed_by(der: Vec<u8>, signer: &x509_validator_testkit::Ca) -> &'static [u8] {
        let leaked = leak(der);
        let cert = parse(leaked);
        signer_registry()
            .lock()
            .unwrap()
            .push((cert.tbs_certificate.as_ref().to_vec(), signer.public_key_der()));
        leaked
    }

    #[derive(Debug)]
    struct RegisteredSignerKey {
        spki_der: Vec<u8>,
    }

    impl PublicKey for RegisteredSignerKey {
        fn is_valid(&self, _signature: &[u8], message: &[u8]) -> Result<(), CryptoError> {
            let registry = signer_registry().lock().unwrap();
            let signed_by_this_key = registry
                .iter()
                .any(|(tbs, signer_spki)| tbs == message && *signer_spki == self.spki_der);
            if signed_by_this_key {
                Ok(())
            } else {
                Err(CryptoError::VerificationFailed)
            }
        }
    }

    #[derive(Debug)]
    struct DiscriminatingKeyProvider;
    impl KeyProvider for DiscriminatingKeyProvider {
        fn public_key(&self, _algorithm: &AlgorithmIdentifier, public_key: &SubjectPublicKeyInfo) -> Result<Box<dyn PublicKey>, CryptoError> {
            Ok(Box::new(RegisteredSignerKey {
                spki_der: public_key.raw.to_vec(),
            }))
        }
    }

    static DISCRIMINATING_KEY_PROVIDER: DiscriminatingKeyProvider = DiscriminatingKeyProvider;

    fn discriminating_crypto() -> CryptoProvider {
        CryptoProvider {
            key_provider: &DISCRIMINATING_KEY_PROVIDER,
            sha256: &FAKE_DIGEST,
        }
    }

    // ---- Fake VerifierPolicy ----

    struct AlwaysMeetsPolicy;
    impl VerifierPolicy for AlwaysMeetsPolicy {
        fn verifying_critical_extensions(&self) -> Vec<x509_validator_core::der_parser::Oid<'static>> {
            // rcgen always marks basicConstraints critical, so a fake
            // policy that claims no extensions would reject every
            // rcgen-generated CA/root as "unhandled critical extension".
            vec![x509_validator_core::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS]
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
        // The chain is exactly leaf, intermediate, root — leaf-to-root order,
        // as RFC 5280 §6.1 orders a certification path from the subject
        // outward to the trust anchor.
        assert_chain_is(result, &[&leaf, &parse(intermediate_der), &parse(root_der)]);
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
        let root = self_signed_ca_with("root", |params: &mut x509_validator_testkit::rcgen::CertificateParams| {
            params.custom_extensions.push(x509_validator_testkit::rcgen::CustomExtension::from_oid_content(
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
            fn verifying_critical_extensions(&self) -> Vec<x509_validator_core::der_parser::Oid<'static>> {
                vec![x509_validator_core::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS]
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

    #[test]
    fn candidate_without_subject_key_identifier_is_preferred_over_one_whose_ski_mismatches() {
        // RFC 5280 §4.2.1.1 makes the authorityKeyIdentifier a hint for
        // selecting among issuers sharing a subject name, and RFC 4158 §3.5.3
        // ranks that hint three ways rather than two: a candidate whose
        // subjectKeyIdentifier equals the subject's AKI is the best match; a
        // candidate carrying *no* subjectKeyIdentifier is merely uninformative
        // (§4.2.1.2 leaves the extension optional for certificates that are
        // not CAs, and legacy CAs omit it too); a candidate that *does* carry
        // a subjectKeyIdentifier which differs from the AKI is positive
        // evidence of the wrong issuer, so it must sort last.
        //
        // Both roots below share the subject name "root" and share one key
        // pair, so either can validly sign the leaf and neither is skipped for
        // a bad signature. The mismatching-SKI root is inserted first, so only
        // a three-way ranking puts the no-SKI root ahead of it.
        struct RecordingPolicy {
            root_skis: Mutex<Vec<Option<Vec<u8>>>>,
        }
        impl VerifierPolicy for RecordingPolicy {
            fn verifying_critical_extensions(&self) -> Vec<x509_validator_core::der_parser::Oid<'static>> {
                vec![x509_validator_core::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS]
            }
            fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> crate::policy::PolicyEvaluationResult {
                let root = &chain[chain.len() - 1];
                self.root_skis
                    .lock()
                    .unwrap()
                    .push(subject_key_identifier(root).map(<[u8]>::to_vec));
                // Never satisfied, so every candidate is visited in order.
                Err(PolicyFailureReason::new("recording only"))
            }
        }

        let shared_key = KeyPair::generate().expect("generate key pair");
        // A key identifier no certificate here actually carries, used as the
        // leaf's AKI so that neither root can match it.
        let unmatched_key_id = vec![0xAA; 20];

        // The signing identity fixes the AKI that the issued leaf will carry.
        let signer = signing_identity("root", shared_key, Some(unmatched_key_id.clone()));
        let leaf_der = leak(issue_leaf_with_aki("leaf", &["www.example.com"], &signer, true));

        let mismatching_ski_root = self_signed_ca_with_key_ids("root", Some(signer.copy_of_key_pair()), Ski::Exactly(vec![0xBB; 20]));
        let no_ski_root = self_signed_ca_with_key_ids("root", Some(signer.copy_of_key_pair()), Ski::Absent);

        let mismatching_der = leak(mismatching_ski_root.der.clone());
        let no_ski_der = leak(no_ski_root.der.clone());

        let leaf = parse(leaf_der);
        let mismatching_cert = parse(mismatching_der);
        let no_ski_cert = parse(no_ski_der);

        // Guard against a vacuous test: confirm the fixtures really carry the
        // key identifiers the ranking is supposed to react to.
        assert_eq!(
            authority_key_identifier(&leaf),
            Some(unmatched_key_id.as_slice()),
            "leaf must carry an authorityKeyIdentifier matching neither root"
        );
        assert_eq!(
            subject_key_identifier(&mismatching_cert),
            Some([0xBB; 20].as_slice()),
            "first root must carry a non-matching subjectKeyIdentifier"
        );
        assert_eq!(
            subject_key_identifier(&no_ski_cert),
            None,
            "second root must carry no subjectKeyIdentifier at all"
        );
        assert_eq!(
            subject_key(&mismatching_cert),
            subject_key(&no_ski_cert),
            "both roots must share a subject name so both are candidates"
        );

        // Insertion order deliberately puts the mismatching-SKI root first.
        let roots = CertificateStore::from_iter(vec![mismatching_cert, no_ski_cert]);
        let intermediates: CertificateStore = CertificateStore::new();
        let crypto = always_valid_crypto();
        let policy = RecordingPolicy { root_skis: Mutex::new(Vec::new()) };
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, policy, &crypto);

        let _ = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});

        let visited = verifier.policy.root_skis.lock().unwrap().clone();
        assert_eq!(visited.len(), 2, "both roots should have been offered to the policy");
        assert_eq!(visited[0], None, "the root with no subjectKeyIdentifier must be tried first");
        assert_eq!(visited[1], Some(vec![0xBB; 20]), "the root with a mismatching subjectKeyIdentifier must be tried last");
    }

    #[test]
    fn missing_intermediate_fails_to_build() {
        // The root is trusted, but the certificate linking the leaf to it is
        // supplied nowhere, so no certification path exists.
        let root = self_signed_ca_with("root", |_| {});
        let intermediate = issue_ca("intermediate", &root, None, |_| {});
        let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
        let root_der = leak(root.der.clone());

        let leaf = parse(leaf_der);
        let roots = CertificateStore::from_iter(vec![parse(root_der)]);
        let intermediates: CertificateStore = CertificateStore::new();
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        match result {
            ChainValidationResultOwned::CouldNotValidate(reasons) => {
                // Nothing was ever offered to the policy, so there is no
                // policy failure to report — only the absence of a path.
                assert!(reasons.is_empty(), "expected no policy failures, got: {reasons:?}");
            }
            ChainValidationResultOwned::ValidCertificate(_) => panic!("built a chain with no intermediate available"),
        }
    }

    #[test]
    fn missing_root_fails_to_build() {
        // The intermediate is available, so the search can climb one link,
        // but the trust anchor it terminates at is not trusted.
        let root = self_signed_ca_with("root", |_| {});
        let intermediate = issue_ca("intermediate", &root, None, |_| {});
        let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
        let intermediate_der = leak(intermediate.der.clone());

        let leaf = parse(leaf_der);
        let roots: CertificateStore = CertificateStore::new();
        let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        match result {
            ChainValidationResultOwned::CouldNotValidate(reasons) => {
                assert!(reasons.is_empty(), "expected no policy failures, got: {reasons:?}");
            }
            ChainValidationResultOwned::ValidCertificate(_) => panic!("built a chain terminating at an untrusted root"),
        }
    }

    #[test]
    fn extra_roots_are_ignored() {
        // An unrelated trust anchor sharing no subject name with anything in
        // the path must neither be selected nor disturb the search.
        let root = self_signed_ca_with("root", |_| {});
        let unrelated_root = self_signed_ca_with("unrelated-root", |_| {});
        let intermediate = issue_ca("intermediate", &root, None, |_| {});
        let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
        let intermediate_der = leak(intermediate.der.clone());
        let root_der = leak(root.der.clone());
        let unrelated_root_der = leak(unrelated_root.der.clone());

        let leaf = parse(leaf_der);
        let roots = CertificateStore::from_iter(vec![parse(root_der), parse(unrelated_root_der)]);
        let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert_chain_is(result, &[&leaf, &parse(intermediate_der), &parse(root_der)]);
    }

    #[test]
    fn roots_also_present_in_the_intermediate_store_are_not_a_problem() {
        // Callers routinely hand the same bundle to both stores. The roots
        // appearing a second time as intermediate candidates must not produce
        // a duplicated or longer path.
        let root = self_signed_ca_with("root", |_| {});
        let unrelated_root = self_signed_ca_with("unrelated-root", |_| {});
        let intermediate = issue_ca("intermediate", &root, None, |_| {});
        let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
        let intermediate_der = leak(intermediate.der.clone());
        let root_der = leak(root.der.clone());
        let unrelated_root_der = leak(unrelated_root.der.clone());

        let leaf = parse(leaf_der);
        let roots = CertificateStore::from_iter(vec![parse(root_der), parse(unrelated_root_der)]);
        let intermediates = CertificateStore::from_iter(vec![
            parse(intermediate_der),
            parse(root_der),
            parse(unrelated_root_der),
        ]);
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert_chain_is(result, &[&leaf, &parse(intermediate_der), &parse(root_der)]);
    }

    #[test]
    fn self_signed_certificate_is_rejected_when_not_in_the_trust_store() {
        // A self-signed certificate is its own issuer, but being its own
        // issuer confers no trust: RFC 5280 §6.1 requires the path to
        // terminate at a configured trust anchor.
        let trusted_root = self_signed_ca_with("root", |_| {});
        let intermediate = issue_ca("intermediate", &trusted_root, None, |_| {});
        let isolated = self_signed_ca_with("isolated-self-signed", |_| {});

        let isolated_der = leak(isolated.der.clone());
        let intermediate_der = leak(intermediate.der.clone());
        let trusted_root_der = leak(trusted_root.der.clone());

        let leaf = parse(isolated_der);
        let roots = CertificateStore::from_iter(vec![parse(trusted_root_der)]);
        let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert!(
            matches!(result, ChainValidationResultOwned::CouldNotValidate(_)),
            "a self-signed certificate outside the trust store must not validate"
        );
    }

    #[test]
    fn self_signed_certificate_is_trusted_when_in_the_trust_store() {
        // The same certificate as above, now configured as a trust anchor:
        // the path is the anchor alone, length one.
        let trusted_root = self_signed_ca_with("root", |_| {});
        let intermediate = issue_ca("intermediate", &trusted_root, None, |_| {});
        let isolated = self_signed_ca_with("isolated-self-signed", |_| {});

        let isolated_der = leak(isolated.der.clone());
        let intermediate_der = leak(intermediate.der.clone());
        let trusted_root_der = leak(trusted_root.der.clone());

        let leaf = parse(isolated_der);
        let roots = CertificateStore::from_iter(vec![parse(trusted_root_der), parse(isolated_der)]);
        let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert_chain_is(result, &[&leaf]);
    }

    #[test]
    fn trust_roots_can_be_non_self_signed_leaves() {
        // Nothing requires a trust anchor to be a CA or to be self-signed.
        // A non-CA leaf placed directly in the trust store validates as a
        // path of length one, without any search.
        let root = self_signed_ca_with("root", |_| {});
        let intermediate = issue_ca("intermediate", &root, None, |_| {});
        let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
        let intermediate_der = leak(intermediate.der.clone());

        let leaf = parse(leaf_der);
        let roots = CertificateStore::from_iter(vec![parse(leaf_der)]);
        let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert_chain_is(result, &[&leaf]);
    }

    #[test]
    fn trust_roots_can_be_non_self_signed_intermediates() {
        // Trusting an intermediate directly terminates the path there: the
        // chain stops at the anchor and never reaches the certificate that
        // issued it.
        let root = self_signed_ca_with("root", |_| {});
        let intermediate = issue_ca("intermediate", &root, None, |_| {});
        let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
        let intermediate_der = leak(intermediate.der.clone());

        let leaf = parse(leaf_der);
        let roots = CertificateStore::from_iter(vec![parse(intermediate_der)]);
        let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert_chain_is(result, &[&leaf, &parse(intermediate_der)]);
    }

    #[test]
    fn critical_extensions_are_policed_on_leaf_certificates() {
        // RFC 5280 §4.2: a certificate consumer must reject a certificate
        // carrying a critical extension it does not recognize. The policy
        // here declares only basicConstraints, so the leaf's extra critical
        // extension is unhandled and the leaf is rejected outright — even
        // though it is itself in the trust store and would otherwise be
        // accepted as a path of length one.
        let trusted_root = self_signed_ca_with("root", |_| {});
        let intermediate = issue_ca("intermediate", &trusted_root, None, |_| {});
        let weird = self_signed_ca_with("weird-critical-extension", |params: &mut x509_validator_testkit::rcgen::CertificateParams| {
            params.custom_extensions.push(weird_critical_extension());
        });

        let weird_der = leak(weird.der.clone());
        let intermediate_der = leak(intermediate.der.clone());
        let trusted_root_der = leak(trusted_root.der.clone());

        let leaf = parse(weird_der);
        // Guard against a vacuous test: the leaf really must carry a critical
        // extension the policy does not list.
        let handled = AlwaysMeetsPolicy.verifying_critical_extensions();
        assert!(
            leaf.tbs_certificate
                .iter_extensions()
                .any(|ext| ext.critical && !handled.contains(&ext.oid)),
            "leaf must carry a critical extension outside the policy's handled set"
        );

        let roots = CertificateStore::from_iter(vec![parse(trusted_root_der), parse(weird_der)]);
        let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert!(
            matches!(result, ChainValidationResultOwned::CouldNotValidate(_)),
            "a leaf with an unhandled critical extension must not validate"
        );
    }

    #[test]
    fn roots_with_a_matching_subject_key_identifier_are_preferred() {
        // Two trust anchors share one subject name and one key pair, so
        // either terminates a valid path and neither can be eliminated by a
        // signature check. They differ only in that one carries a
        // subjectKeyIdentifier equal to the intermediate's
        // authorityKeyIdentifier and the other carries none at all.
        //
        // RFC 5280 §4.2.1.1 offers the AKI precisely as the means of
        // selecting among issuers that share a name, and RFC 4158 §3.5.3
        // ranks a matching key identifier above an absent one. The no-SKI
        // anchor is inserted first, so only that ranking — rather than store
        // insertion order — can put the matching anchor in the built chain.
        let root_key = KeyPair::generate().expect("generate key pair");
        let matching_root = self_signed_ca_with_key_ids("root", Some(root_key), Ski::Derived);
        let no_ski_root = self_signed_ca_with_key_ids("root", Some(matching_root.copy_of_key_pair()), Ski::Absent);

        let intermediate = issue_ca_with_key_ids("intermediate", &matching_root, None, Ski::Derived, true);
        let leaf_der = leak(issue_leaf("leaf", &["www.example.com"], &intermediate));
        let intermediate_der = leak(intermediate.der.clone());
        let matching_der = leak(matching_root.der.clone());
        let no_ski_der = leak(no_ski_root.der.clone());

        let leaf = parse(leaf_der);
        let matching_cert = parse(matching_der);
        let no_ski_cert = parse(no_ski_der);
        let intermediate_cert = parse(intermediate_der);

        // Guard against a vacuous test: the ranking signal must really exist.
        assert_eq!(
            authority_key_identifier(&intermediate_cert),
            subject_key_identifier(&matching_cert),
            "the intermediate's AKI must equal the matching root's SKI"
        );
        assert_eq!(subject_key_identifier(&no_ski_cert), None, "the other root must carry no SKI");
        assert_eq!(
            subject_key(&matching_cert),
            subject_key(&no_ski_cert),
            "both roots must share a subject name so both are candidates"
        );

        // Insertion order deliberately puts the unranked root first.
        let roots = CertificateStore::from_iter(vec![no_ski_cert, matching_cert]);
        let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der)]);
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert_chain_is(result, &[&leaf, &parse(intermediate_der), &parse(matching_der)]);
    }

    #[test]
    fn intermediates_whose_subject_key_identifier_matches_the_subject_aki_are_preferred() {
        // A single subject name, "intermediate", is served by two
        // certificates in the intermediate store: one carrying a
        // subjectKeyIdentifier equal to the leaf's authorityKeyIdentifier,
        // one carrying none. Both share a key pair and both are validly
        // issued by the same root, so both complete a chain and the search
        // cannot discriminate on signatures — only the RFC 4158 §3.5.3
        // ranking of the RFC 5280 §4.2.1.1 key-identifier hint decides.
        //
        // Two candidates under one subject name is also what makes the
        // ranking observable at all: candidates are pushed onto a LIFO
        // search stack, so the best-ranked candidate must be pushed last to
        // be popped first. With a single candidate per name the push order
        // is unobservable.
        let root = self_signed_ca_with("root", |_| {});

        let intermediate_key = KeyPair::generate().expect("generate key pair");
        let matching_intermediate = issue_ca_with_key("intermediate", &root, intermediate_key, Ski::Derived, true, |_| {});
        let no_ski_intermediate = issue_ca_with_key(
            "intermediate",
            &root,
            matching_intermediate.copy_of_key_pair(),
            Ski::Absent,
            true,
            |_| {},
        );

        let leaf_der = leak(issue_leaf_with_aki("leaf", &["www.example.com"], &matching_intermediate, true));
        let matching_der = leak(matching_intermediate.der.clone());
        let no_ski_der = leak(no_ski_intermediate.der.clone());
        let root_der = leak(root.der.clone());

        let leaf = parse(leaf_der);
        let matching_cert = parse(matching_der);
        let no_ski_cert = parse(no_ski_der);

        // Guard against a vacuous test.
        assert_eq!(
            authority_key_identifier(&leaf),
            subject_key_identifier(&matching_cert),
            "the leaf's AKI must equal the preferred intermediate's SKI"
        );
        assert_eq!(subject_key_identifier(&no_ski_cert), None, "the other intermediate must carry no SKI");
        assert_eq!(
            subject_key(&matching_cert),
            subject_key(&no_ski_cert),
            "both intermediates must share a subject name so both are candidates"
        );

        let roots = CertificateStore::from_iter(vec![parse(root_der)]);
        // Insertion order deliberately puts the unranked intermediate first.
        let intermediates = CertificateStore::from_iter(vec![no_ski_cert, matching_cert]);
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert_chain_is(result, &[&leaf, &parse(matching_der), &parse(root_der)]);
    }

    #[test]
    fn cross_signed_root_is_supported() {
        // Only ca2 is trusted. The path to it runs leaf -> intermediate ->
        // ca1-as-cross-signed-by-ca2 -> ca2: the intermediate names ca1 as
        // its issuer, and the certificate satisfying that name in the
        // intermediate store is the cross-signed one, whose own issuer name
        // is ca2. RFC 4158 §2.4.2 describes exactly this shape.
        let ca1 = self_signed_ca_with("ca1", |_| {});
        let ca2 = self_signed_ca_with("ca2", |_| {});
        let ca1_cross_signed = ca1.cross_signed_by(&ca2);
        let intermediate = issue_ca("intermediate", &ca1, None, |_| {});

        let leaf_der = leak_signed_by(issue_leaf("leaf", &["www.example.com"], &intermediate), &intermediate);
        let intermediate_der = leak_signed_by(intermediate.der.clone(), &ca1);
        let cross_signed_der = leak_signed_by(ca1_cross_signed.der.clone(), &ca2);
        let ca2_der = leak_signed_by(ca2.der.clone(), &ca2);

        let leaf = parse(leaf_der);
        let roots = CertificateStore::from_iter(vec![parse(ca2_der)]);
        let intermediates = CertificateStore::from_iter(vec![parse(intermediate_der), parse(cross_signed_der)]);
        let crypto = discriminating_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert_chain_is(
            result,
            &[&leaf, &parse(intermediate_der), &parse(cross_signed_der), &parse(ca2_der)],
        );
    }

    #[test]
    fn shorter_path_is_built_when_cross_signed_roots_offer_both() {
        // Both ca1 and ca2 are trusted, and both cross-signed certificates
        // are available as intermediates, so two paths terminate at a trust
        // anchor: the three-certificate one through ca1 directly, and the
        // four-certificate one through ca1-cross-signed-by-ca2.
        //
        // RFC 4158 §3.2 prefers the shorter path, and the search reaches it
        // first because trust anchors are considered ahead of intermediates
        // at each step. The extra cross-signed certificates must not divert
        // it.
        let ca1 = self_signed_ca_with("ca1", |_| {});
        let ca2 = self_signed_ca_with("ca2", |_| {});
        let ca1_cross_signed = ca1.cross_signed_by(&ca2);
        let ca2_cross_signed = ca2.cross_signed_by(&ca1);
        let intermediate = issue_ca("intermediate", &ca1, None, |_| {});

        let leaf_der = leak_signed_by(issue_leaf("leaf", &["www.example.com"], &intermediate), &intermediate);
        let intermediate_der = leak_signed_by(intermediate.der.clone(), &ca1);
        let ca1_cross_der = leak_signed_by(ca1_cross_signed.der.clone(), &ca2);
        let ca2_cross_der = leak_signed_by(ca2_cross_signed.der.clone(), &ca1);
        let ca1_der = leak_signed_by(ca1.der.clone(), &ca1);
        let ca2_der = leak_signed_by(ca2.der.clone(), &ca2);

        let leaf = parse(leaf_der);
        let roots = CertificateStore::from_iter(vec![parse(ca1_der), parse(ca2_der)]);
        let intermediates = CertificateStore::from_iter(vec![
            parse(intermediate_der),
            parse(ca2_cross_der),
            parse(ca1_cross_der),
        ]);
        let crypto = discriminating_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert_chain_is(result, &[&leaf, &parse(intermediate_der), &parse(ca1_der)]);
    }

    #[test]
    fn roots_that_did_not_sign_the_certificate_below_them_are_rejected() {
        // The trust store holds a certificate for ca1's subject name that
        // carries a *different* key than the one that actually signed the
        // intermediate. RFC 5280 §6.1.3(a)(1) requires the signature on each
        // certificate to verify under the public key of the certificate
        // above it, so that anchor must be rejected despite matching by
        // name, and the search must fall through to the longer path that
        // terminates at ca2.
        let ca1 = self_signed_ca_with("ca1", |_| {});
        let ca2 = self_signed_ca_with("ca2", |_| {});
        let ca1_cross_signed = ca1.cross_signed_by(&ca2);
        let ca2_cross_signed = ca2.cross_signed_by(&ca1);
        let intermediate = issue_ca("intermediate", &ca1, None, |_| {});

        // A second certificate for ca1's name and a different key pair,
        // issued by ca1 itself. It never signed the intermediate.
        let ca1_with_other_key = issue_ca_with_key_and_name(
            "ca1",
            &ca1,
            KeyPair::generate().expect("generate key pair"),
            None,
            Ski::Derived,
            false,
            |_| {},
        );

        let leaf_der = leak_signed_by(issue_leaf("leaf", &["www.example.com"], &intermediate), &intermediate);
        let intermediate_der = leak_signed_by(intermediate.der.clone(), &ca1);
        let ca1_cross_der = leak_signed_by(ca1_cross_signed.der.clone(), &ca2);
        let ca2_cross_der = leak_signed_by(ca2_cross_signed.der.clone(), &ca1);
        let ca1_other_der = leak_signed_by(ca1_with_other_key.der.clone(), &ca1);
        let ca2_der = leak_signed_by(ca2.der.clone(), &ca2);

        let leaf = parse(leaf_der);
        let ca1_other_cert = parse(ca1_other_der);

        // Guard against a vacuous test: the impostor anchor must match the
        // intermediate's issuer name, and must carry a different key from
        // the one that signed the intermediate.
        assert_eq!(
            subject_key(&ca1_other_cert),
            issuer_key_of(&parse(intermediate_der)),
            "the impostor anchor must be found by the intermediate's issuer name"
        );
        assert_ne!(
            ca1_other_cert.public_key().raw,
            parse(ca1_cross_der).public_key().raw,
            "the impostor anchor must carry a different key than the real ca1"
        );

        // ca1 itself is deliberately absent from the trust store; only the
        // impostor bearing its name and ca2 are trusted.
        let roots = CertificateStore::from_iter(vec![ca1_other_cert, parse(ca2_der)]);
        let intermediates = CertificateStore::from_iter(vec![
            parse(ca1_cross_der),
            parse(ca2_cross_der),
            parse(intermediate_der),
        ]);
        let crypto = discriminating_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert_chain_is(
            result,
            &[&leaf, &parse(intermediate_der), &parse(ca1_cross_der), &parse(ca2_der)],
        );
    }

    #[test]
    fn policy_failures_let_the_search_find_a_longer_path() {
        // The same PKI as the shorter-path test, but with a policy that
        // rejects any chain containing ca1. The short path is found first
        // and fails the policy; the search must not stop there but continue
        // through the cross-signed certificate to the longer path
        // terminating at ca2, which the policy accepts.
        struct ForbidCertificatePolicy {
            forbidden_der: Vec<u8>,
        }
        impl VerifierPolicy for ForbidCertificatePolicy {
            fn verifying_critical_extensions(&self) -> Vec<x509_validator_core::der_parser::Oid<'static>> {
                vec![x509_validator_core::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS]
            }
            fn chain_meets_policy_requirements(&mut self, chain: &UnverifiedCertificateChain) -> crate::policy::PolicyEvaluationResult {
                for index in 0..chain.len() {
                    if chain[index].as_ref() == self.forbidden_der.as_slice() {
                        return Err(PolicyFailureReason::new("chain must not contain forbidden certificate"));
                    }
                }
                Ok(())
            }
        }

        let ca1 = self_signed_ca_with("ca1", |_| {});
        let ca2 = self_signed_ca_with("ca2", |_| {});
        let ca1_cross_signed = ca1.cross_signed_by(&ca2);
        let ca2_cross_signed = ca2.cross_signed_by(&ca1);
        let intermediate = issue_ca("intermediate", &ca1, None, |_| {});

        let leaf_der = leak_signed_by(issue_leaf("leaf", &["www.example.com"], &intermediate), &intermediate);
        let intermediate_der = leak_signed_by(intermediate.der.clone(), &ca1);
        let ca1_cross_der = leak_signed_by(ca1_cross_signed.der.clone(), &ca2);
        let ca2_cross_der = leak_signed_by(ca2_cross_signed.der.clone(), &ca1);
        let ca1_der = leak_signed_by(ca1.der.clone(), &ca1);
        let ca2_der = leak_signed_by(ca2.der.clone(), &ca2);

        let leaf = parse(leaf_der);
        let roots = CertificateStore::from_iter(vec![parse(ca1_der), parse(ca2_der)]);
        let intermediates = CertificateStore::from_iter(vec![
            parse(intermediate_der),
            parse(ca2_cross_der),
            parse(ca1_cross_der),
        ]);
        let crypto = discriminating_crypto();
        let policy = ForbidCertificatePolicy {
            forbidden_der: ca1_der.to_vec(),
        };
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, policy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert_chain_is(
            result,
            &[&leaf, &parse(intermediate_der), &parse(ca1_cross_der), &parse(ca2_der)],
        );
    }

    #[test]
    fn pathological_pki_with_mutually_cross_signed_intermediates_can_still_build() {
        // A deliberately hostile PKI. Two intermediate subject names, "T"
        // and "X", each served by several certificates, cross-sign each
        // other: certificates named T are issued by X and vice versa. RFC
        // 5280 §4.1.2.4 links a certificate to its issuer by name alone, so
        // by name this graph contains a cycle, and a depth-first search that
        // did not recognise a repeated certificate would revisit T and X
        // forever.
        //
        // The only thing that terminates the search is the loop detection
        // that refuses to add a certificate already present in the partial
        // chain. To force the detection to actually fire — rather than a
        // signature check quietly pruning the cycle — the T certificates are
        // arranged to be distinguishable from one another in each of the
        // ways the identity comparison considers, so the search must
        // genuinely re-offer already-visited certificates and reject them:
        //
        //   t1, t2: same subject name "T", same key pair, but t1 carries a
        //           subjectAltName that t2 does not.
        //   t3:     same subject name "T", a different key pair.
        //   x1, x2: same subject name "X", same key pair, distinguished by
        //           x2's subjectAltName.
        //
        // The leaf's AKI matches t3's SKI, and both X certificates carry the
        // same AKI, which fixes the order in which candidates are tried and
        // drives the search into the cycle rather than around it.
        let root = self_signed_ca_with("root", |_| {});

        let t1_t2_key = KeyPair::generate().expect("generate key pair");
        let t3_key = KeyPair::generate().expect("generate key pair");
        let x_key = KeyPair::generate().expect("generate key pair");

        // t3's key identifier, used as the AKI of the leaf and of both X
        // certificates. It is computed before t3 exists, from t3's key.
        let t3_key_id = {
            let probe = self_signed_ca_with_key_ids("probe", Some(KeyPair::from_pem(&t3_key.serialize_pem()).unwrap()), Ski::Derived);
            probe.key_identifier()
        };

        // Signing identities for the two intermediate names, so certificates
        // can be issued "as" T and "as" X before any certificate for either
        // name exists — the only way to close the cycle.
        let sign_as_t_with_t1_t2_key = signing_identity("T", KeyPair::from_pem(&t1_t2_key.serialize_pem()).unwrap(), Some(t3_key_id.clone()));
        let sign_as_t_with_t3_key = signing_identity("T", KeyPair::from_pem(&t3_key.serialize_pem()).unwrap(), Some(t3_key_id.clone()));
        let sign_as_x = signing_identity("X", KeyPair::from_pem(&x_key.serialize_pem()).unwrap(), None);

        // t1 is issued by the root and carries the SKI of the *wrong* key,
        // which RFC 5280 §4.2.1.2 does not forbid and chain building must
        // tolerate. It is the only T that leads out of the cycle.
        let t1 = issue_ca_with_key_and_name(
            "T",
            &root,
            KeyPair::from_pem(&t1_t2_key.serialize_pem()).unwrap(),
            None,
            Ski::Exactly(vec![0xC1; 20]),
            true,
            |params| {
                params.subject_alt_names = vec![x509_validator_testkit::rcgen::SanType::DnsName(x509_validator_testkit::rcgen::string::Ia5String::try_from("example.com").unwrap())];
            },
        );
        // t2 shares t1's key and name but has no SAN and no SKI.
        let t2 = issue_ca_with_key_and_name(
            "T",
            &sign_as_x,
            KeyPair::from_pem(&t1_t2_key.serialize_pem()).unwrap(),
            None,
            Ski::Absent,
            false,
            |_| {},
        );
        // t3 uses a different key and carries the SKI the leaf points at.
        let t3 = issue_ca_with_key_and_name(
            "T",
            &sign_as_x,
            KeyPair::from_pem(&t3_key.serialize_pem()).unwrap(),
            Some(1),
            Ski::Derived,
            false,
            |_| {},
        );
        // x1 and x2 are both issued "as T" with the t1/t2 key, share the X
        // key, and differ only by x2's subjectAltName.
        let x1 = issue_ca_with_key_and_name(
            "X",
            &sign_as_t_with_t1_t2_key,
            KeyPair::from_pem(&x_key.serialize_pem()).unwrap(),
            None,
            Ski::Absent,
            true,
            |_| {},
        );
        let x2 = issue_ca_with_key_and_name(
            "X",
            &sign_as_t_with_t1_t2_key,
            KeyPair::from_pem(&x_key.serialize_pem()).unwrap(),
            None,
            Ski::Absent,
            true,
            |params| {
                params.subject_alt_names = vec![x509_validator_testkit::rcgen::SanType::DnsName(x509_validator_testkit::rcgen::string::Ia5String::try_from("foo.example.com").unwrap())];
            },
        );
        let insane_leaf_der = issue_leaf_with("insane-leaf", &[], &sign_as_t_with_t3_key, |params| {
            params.use_authority_key_identifier_extension = true;
        });

        // Signatures: t1 by the root; t2 and t3 by the X key; x1 and x2 by
        // the t1/t2 key; the leaf by the t3 key.
        let root_der = leak_signed_by(root.der.clone(), &root);
        let t1_der = leak_signed_by(t1.der.clone(), &root);
        let t2_der = leak_signed_by(t2.der.clone(), &sign_as_x);
        let t3_der = leak_signed_by(t3.der.clone(), &sign_as_x);
        let x1_der = leak_signed_by(x1.der.clone(), &sign_as_t_with_t1_t2_key);
        let x2_der = leak_signed_by(x2.der.clone(), &sign_as_t_with_t1_t2_key);
        let leaf_der = leak_signed_by(insane_leaf_der, &sign_as_t_with_t3_key);

        let leaf = parse(leaf_der);

        // Guard against a vacuous test: the graph must really contain a
        // cycle by issuer name, otherwise loop detection is never exercised.
        assert_eq!(
            issuer_key_of(&parse(t2_der)),
            subject_key(&parse(x1_der)),
            "T certificates must name X as their issuer"
        );
        assert_eq!(
            issuer_key_of(&parse(x1_der)),
            subject_key(&parse(t2_der)),
            "X certificates must name T as their issuer, closing the cycle"
        );
        assert_eq!(
            authority_key_identifier(&leaf),
            subject_key_identifier(&parse(t3_der)),
            "the leaf's AKI must select t3 first"
        );

        let roots = CertificateStore::from_iter(vec![parse(root_der)]);
        let intermediates = CertificateStore::from_iter(vec![
            parse(t1_der),
            parse(t2_der),
            parse(t3_der),
            parse(x2_der),
            parse(x1_der),
        ]);
        let crypto = discriminating_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        // Bound the search explicitly. Without loop detection this PKI has
        // no finite traversal at all, so an unbounded run would hang rather
        // than fail. Counting diagnostic events and panicking past a
        // generous ceiling turns "the search never terminates" into an
        // ordinary, quickly-reported test failure. A correct search emits
        // well under this many events; the ceiling only has to be finite.
        const MAX_SEARCH_EVENTS: usize = 500;
        let mut events = 0usize;
        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {
            events += 1;
            assert!(
                events <= MAX_SEARCH_EVENTS,
                "chain building did not terminate: exceeded {MAX_SEARCH_EVENTS} search events, \
                 so a certificate already in the partial chain is being revisited"
            );
        });

        assert_chain_is(
            result,
            &[
                &leaf,
                &parse(t3_der),
                &parse(x2_der),
                &parse(t2_der),
                &parse(x1_der),
                &parse(t1_der),
                &parse(root_der),
            ],
        );
    }
}
