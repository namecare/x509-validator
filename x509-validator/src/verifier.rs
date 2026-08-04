use crate::crypto::CryptoProvider;
use crate::diagnostic::VerificationDiagnostic;
use crate::policy::{PolicyFailureReason, VerifierPolicy};
use crate::store::CertificateStore;
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use x509_validator_core::validated_chain::ValidatedCertificateChain;
use x509_validator_core::{
    CertificateView, ChainValidationResult, ExtensionsView, NameView,
    PublicKeyInfoView,
};

fn subject_key<C: CertificateView>(certificate: &C) -> Vec<u8> {
    certificate.subject().canonical_der().to_vec()
}

/// Parses each DER-encoded certificate in `der` via `C::from_der` and
/// collects the results into a `CertificateStore`. Fails on the first
/// certificate that doesn't parse, since a malformed intermediate makes the
/// rest of the supplied set untrustworthy as a chain-building input.
fn parse_certificate_store<C: CertificateView + Clone>(der: &[Vec<u8>]) -> Result<CertificateStore<C>, PolicyFailureReason> {
    let mut store = CertificateStore::new();
    for bytes in der {
        let certificate = C::from_der(bytes)
            .map_err(|_| PolicyFailureReason::new("failed to parse certificate DER"))?;
        store.append(certificate);
    }
    Ok(store)
}

pub struct BaseVerifier<'a, C: CertificateView, P> {
    root_certificates: CertificateStore<C>,
    crypto: &'a CryptoProvider,
    policy: P,
}

impl<'a, C, P> BaseVerifier<'a, C, P>
where
    C: CertificateView + Clone + PartialEq,
    P: VerifierPolicy<C>,
{
    pub fn with_policy_and_backend(
        root_certificates: CertificateStore<C>,
        policy: P,
        crypto: &'a CryptoProvider,
    ) -> Self {
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
    pub fn validate(
        &mut self,
        leaf: &C,
        intermediates: &[Vec<u8>],
    ) -> ChainValidationResult<C, Vec<PolicyFailureReason>> {
        let store = match parse_certificate_store(intermediates) {
            Ok(store) => store,
            Err(reason) => return ChainValidationResult::CouldNotValidate(vec![reason]),
        };
        self.validate_with_diagnostics(leaf, &store, &mut |_: VerificationDiagnostic<C>| {})
    }

    /// Same as `validate`, but calls `diagnostic_callback` with progress and
    /// failure events during chain building, useful for debugging and
    /// detailed error reporting.
    pub fn validate_with_diagnostics(
        &mut self,
        leaf: &C,
        intermediates: &CertificateStore<C>,
        diagnostic_callback: &mut dyn FnMut(VerificationDiagnostic<C>),
    ) -> ChainValidationResult<C, Vec<PolicyFailureReason>> {
        if has_unhandled_critical_extensions(leaf, &self.policy) {
            let handled = self.policy.verifying_critical_extensions();
            let oid = leaf
                .extensions()
                .oids()
                .into_iter()
                .find(|(oid, critical)| *critical && !handled.contains(oid))
                .map(|(oid, _)| oid)
                .expect("has_unhandled_critical_extensions confirmed an unhandled critical extension exists");
            diagnostic_callback(VerificationDiagnostic::LeafCertificateHasUnhandledCriticalExtension { oid });
            return ChainValidationResult::CouldNotValidate(vec![PolicyFailureReason::new(
                "leaf certificate has unhandled critical extension",
            )]);
        }

        let mut policy_failures = Vec::new();

        let leaf_key = subject_key(leaf);
        if self
            .root_certificates
            .find_by_subject(&leaf_key)
            .iter()
            .any(|c| c == leaf)
        {
            let chain = UnverifiedCertificateChain::new(vec![leaf.clone()]);
            match self.policy.chain_meets_policy_requirements(&chain) {
                Ok(()) => {
                    diagnostic_callback(VerificationDiagnostic::FoundValidCertificateChain {
                        chain: vec![leaf.clone()],
                    });
                    return ChainValidationResult::ValidCertificate(
                        ValidatedCertificateChain::new_unchecked(vec![leaf.clone()]),
                    );
                }
                Err(reason) => {
                    diagnostic_callback(VerificationDiagnostic::LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy {
                        reason: reason.clone(),
                    });
                    policy_failures.push(reason);
                }
            }
        }

        let mut stack: Vec<Vec<C>> = vec![vec![leaf.clone()]];

        while let Some(partial_chain) = stack.pop() {
            diagnostic_callback(VerificationDiagnostic::SearchingForIssuerOfPartialChain {
                partial_chain: partial_chain.clone(),
            });

            let tip = partial_chain.last().unwrap();
            let issuer_key = issuer_key_of(tip);

            let mut root_candidates = self.root_certificates.find_by_subject(&issuer_key).to_vec();
            sort_by_suitability_for_issuing(&mut root_candidates, tip);
            if !root_candidates.is_empty() {
                diagnostic_callback(VerificationDiagnostic::FoundCandidateIssuersOfPartialChainInRootStore {
                    partial_chain: partial_chain.clone(),
                    candidates: root_candidates.clone(),
                });
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
                        diagnostic_callback(VerificationDiagnostic::FoundValidCertificateChain {
                            chain: chain_certs.clone(),
                        });
                        return ChainValidationResult::ValidCertificate(
                            ValidatedCertificateChain::new_unchecked(chain_certs),
                        );
                    }
                    Err(reason) => {
                        diagnostic_callback(VerificationDiagnostic::ChainFailsToMeetPolicy {
                            chain: chain_certs,
                            reason: reason.clone(),
                        });
                        policy_failures.push(reason);
                    }
                }
            }

            let mut intermediate_candidates = intermediates.find_by_subject(&issuer_key).to_vec();
            sort_by_suitability_for_issuing(&mut intermediate_candidates, tip);
            if !intermediate_candidates.is_empty() {
                diagnostic_callback(VerificationDiagnostic::FoundCandidateIssuersOfPartialChainInIntermediateStore {
                    partial_chain: partial_chain.clone(),
                    candidates: intermediate_candidates.clone(),
                });
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

        diagnostic_callback(VerificationDiagnostic::CouldNotValidateLeafCertificate {
            reasons: policy_failures.clone(),
        });
        ChainValidationResult::CouldNotValidate(policy_failures)
    }
}

/// True if `cert` carries a critical extension whose OID is not among the
/// ones `policy` declares it understands and enforces
/// (`VerifierPolicy::verifying_critical_extensions`). Per RFC 5280 section
/// 4.2, a certificate consumer must reject a certificate that contains a
/// critical extension it does not recognize.
fn has_unhandled_critical_extensions<C: CertificateView>(cert: &C, policy: &impl VerifierPolicy<C>) -> bool {
    let handled = policy.verifying_critical_extensions();
    cert.extensions()
        .oids()
        .into_iter()
        .any(|(oid, critical)| critical && !handled.contains(&oid))
}

/// Canonical lookup key for the *issuer* name of a certificate (as opposed
/// to `subject_key`, which keys by the certificate's own subject). Both use
/// the same canonical-DER byte representation so entries stored by subject
/// can be found by an issuer-name lookup.
fn issuer_key_of<C: CertificateView>(cert: &C) -> Vec<u8> {
    cert.issuer().canonical_der().to_vec()
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
fn sort_by_suitability_for_issuing<C: CertificateView>(candidates: &mut Vec<C>, subject: &C) {
    let subject_aki = subject
        .extensions()
        .authority_key_identifier()
        .ok()
        .flatten()
        .and_then(|aki| aki.key_identifier);

    let matches_aki = |candidate: &C| -> bool {
        match (&subject_aki, candidate.extensions().subject_key_identifier().ok().flatten()) {
            (Some(aki), Some(ski)) => *aki == ski.key_identifier,
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
fn should_skip_adding_certificate<C: CertificateView + Clone + PartialEq>(
    candidate: &C,
    partial_chain: &[C],
    crypto: &CryptoProvider,
    policy: &impl VerifierPolicy<C>,
    diagnostic_callback: &mut dyn FnMut(VerificationDiagnostic<C>),
) -> bool {
    if has_unhandled_critical_extensions(candidate, policy) {
        let handled = policy.verifying_critical_extensions();
        let oid = candidate
            .extensions()
            .oids()
            .into_iter()
            .find(|(oid, critical)| *critical && !handled.contains(oid))
            .map(|(oid, _)| oid)
            .expect("has_unhandled_critical_extensions confirmed an unhandled critical extension exists");
        diagnostic_callback(VerificationDiagnostic::IssuerHasUnhandledCriticalExtension {
            issuer: candidate.clone(),
            oid,
        });
        return true;
    }

    if partial_chain.iter().any(|existing| same_certificate_identity(existing, candidate)) {
        diagnostic_callback(VerificationDiagnostic::IssuerIsAlreadyInTheChain { issuer: candidate.clone() });
        return true;
    }

    let tip = partial_chain.last().unwrap();
    let signature_verifies = crypto
        .verify_signature(
            tip.signature_algorithm(),
            candidate.public_key_info().subject_public_key_info_der(),
            tip.tbs_der(),
            tip.signature(),
        )
        .is_ok();

    if !signature_verifies {
        diagnostic_callback(VerificationDiagnostic::IssuerHasNotSignedCertificate {
            issuer: candidate.clone(),
            subject: tip.clone(),
        });
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
fn same_certificate_identity<C: CertificateView>(a: &C, b: &C) -> bool {
    if a.subject() != b.subject() {
        return false;
    }
    if a.public_key_info() != b.public_key_info() {
        return false;
    }
    let sans = |c: &C| c.extensions().subject_alt_names().ok().flatten().unwrap_or_default();
    sans(a) == sans(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoError, Digest, KeyProvider, PublicKey};
    use crate::policy::{PolicyFailureReason, VerifierPolicy};
    use crate::PolicyEvaluationResult;
    use x509_validator_core::{
        AuthorityKeyIdentifier, BasicConstraints, ExtensionsView, GeneralNameKind, NameConstraints, NameView, Oid,
        PublicKeyInfoView, SignatureAlgorithmId, SubjectKeyIdentifier, Timestamp,
    };
    // ---- Fake CertificateView family ----

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeName(Vec<u8>);

    impl NameView for FakeName {
        fn general_names(&self) -> Vec<(GeneralNameKind, Vec<u8>)> {
            vec![(GeneralNameKind::DirectoryName, self.0.clone())]
        }
        fn canonical_der(&self) -> &[u8] {
            &self.0
        }
        fn common_name(&self) -> Option<Vec<u8>> {
            None
        }
    }

    #[derive(Debug, Clone, Default)]
    struct FakeExtensions {
        critical_oids: Vec<Oid>,
        aki: Option<Vec<u8>>,
        ski: Option<Vec<u8>>,
        sans: Option<Vec<(GeneralNameKind, Vec<u8>)>>,
    }

    impl ExtensionsView for FakeExtensions {
        type Error = std::io::Error;

        fn oids(&self) -> Vec<(Oid, bool)> {
            self.critical_oids.iter().cloned().map(|oid| (oid, true)).collect()
        }
        fn bytes_for(&self, _oid: &Oid) -> Option<&[u8]> {
            None
        }
        fn basic_constraints(&self) -> Result<Option<BasicConstraints>, Self::Error> {
            Ok(None)
        }
        fn name_constraints(&self) -> Result<Option<NameConstraints>, Self::Error> {
            Ok(None)
        }
        fn key_usage_present(&self) -> Result<bool, Self::Error> {
            Ok(false)
        }
        fn extended_key_usage_contains_ocsp_signing(&self) -> Result<bool, Self::Error> {
            Ok(false)
        }
        fn subject_alt_names(&self) -> Result<Option<Vec<(GeneralNameKind, Vec<u8>)>>, Self::Error> {
            Ok(self.sans.clone())
        }
        fn authority_key_identifier(&self) -> Result<Option<AuthorityKeyIdentifier>, Self::Error> {
            Ok(Some(AuthorityKeyIdentifier {
                key_identifier: self.aki.clone(),
            }))
        }
        fn subject_key_identifier(&self) -> Result<Option<SubjectKeyIdentifier>, Self::Error> {
            Ok(self.ski.clone().map(|key_identifier| SubjectKeyIdentifier { key_identifier }))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakePublicKeyInfo(Vec<u8>);

    impl PublicKeyInfoView for FakePublicKeyInfo {
        fn subject_public_key_info_der(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Debug, Clone)]
    struct FakeCertificate {
        subject: FakeName,
        issuer: FakeName,
        extensions: FakeExtensions,
        public_key: FakePublicKeyInfo,
        signature_algo: SignatureAlgorithmId,
        signature_bytes: Vec<u8>,
        tbs_bytes: Vec<u8>,
    }

    impl PartialEq for FakeCertificate {
        // Full-DER-equality stand-in for tests: two fakes are equal iff all
        // fields the test cares about match. Used only for the
        // leaf-in-root-store bytewise-equality check in `validate`.
        fn eq(&self, other: &Self) -> bool {
            self.subject == other.subject
                && self.issuer == other.issuer
                && self.public_key == other.public_key
                && self.signature_bytes == other.signature_bytes
                && self.tbs_bytes == other.tbs_bytes
        }
    }

    impl CertificateView for FakeCertificate {
        type Name = FakeName;
        type Extensions = FakeExtensions;
        type PublicKeyInfo = FakePublicKeyInfo;
        type Error = std::io::Error;

        fn from_der(_der: &[u8]) -> Result<Self, Self::Error> {
            Err(std::io::Error::other("FakeCertificate does not support from_der"))
        }

        fn subject(&self) -> &Self::Name {
            &self.subject
        }
        fn issuer(&self) -> &Self::Name {
            &self.issuer
        }
        fn is_v1(&self) -> bool {
            false
        }
        fn has_extensions(&self) -> bool {
            true
        }
        fn not_before(&self) -> Timestamp {
            0
        }
        fn not_after(&self) -> Timestamp {
            i64::MAX
        }
        fn extensions(&self) -> &Self::Extensions {
            &self.extensions
        }
        fn public_key_info(&self) -> &Self::PublicKeyInfo {
            &self.public_key
        }
        fn signature_algorithm(&self) -> SignatureAlgorithmId {
            self.signature_algo
        }
        fn signature(&self) -> &[u8] {
            &self.signature_bytes
        }
        fn tbs_der(&self) -> &[u8] {
            &self.tbs_bytes
        }
    }

    fn make_cert(subject: &str, issuer: &str, key: &str) -> FakeCertificate {
        FakeCertificate {
            subject: FakeName(subject.as_bytes().to_vec()),
            issuer: FakeName(issuer.as_bytes().to_vec()),
            extensions: FakeExtensions::default(),
            public_key: FakePublicKeyInfo(key.as_bytes().to_vec()),
            signature_algo: SignatureAlgorithmId::EcdsaP256Sha256,
            // tbs/signature bytes just need to be stable per-subject; the
            // fake `SignatureVerifier`s below decide pass/fail purely from
            // the candidate's public key, not from these byte contents.
            signature_bytes: format!("signed:{subject}").into_bytes(),
            tbs_bytes: format!("tbs:{subject}").into_bytes(),
        }
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
        fn public_key(
            &self,
            _algorithm: SignatureAlgorithmId,
            _public_key_der: &[u8],
        ) -> Result<Box<dyn PublicKey>, CryptoError> {
            Ok(Box::new(AlwaysValidKey))
        }
    }

    /// Fails verification whenever the candidate's public key matches one
    /// of a fixed set of "bad" keys; otherwise succeeds. Lets tests mark a
    /// specific candidate as having a non-verifying signature.
    #[derive(Debug)]
    struct RejectKeysProvider {
        bad_keys: &'static [&'static str],
    }
    impl KeyProvider for RejectKeysProvider {
        fn public_key(
            &self,
            _algorithm: SignatureAlgorithmId,
            public_key_der: &[u8],
        ) -> Result<Box<dyn PublicKey>, CryptoError> {
            let key = std::str::from_utf8(public_key_der).unwrap_or("").to_string();
            let rejected = self.bad_keys.contains(&key.as_str());
            Ok(Box::new(RejectKeysKey { rejected }))
        }
    }

    #[derive(Debug)]
    struct RejectKeysKey {
        rejected: bool,
    }
    impl PublicKey for RejectKeysKey {
        fn is_valid(&self, _signature: &[u8], _message: &[u8]) -> Result<(), CryptoError> {
            if self.rejected {
                Err(CryptoError::VerificationFailed)
            } else {
                Ok(())
            }
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

    static REJECT_INTERMEDIATE: RejectKeysProvider = RejectKeysProvider {
        bad_keys: &["intermediate-key"],
    };

    fn rejecting_crypto() -> CryptoProvider {
        CryptoProvider {
            key_provider: &REJECT_INTERMEDIATE,
            sha256: &FAKE_DIGEST,
        }
    }

    // ---- Fake VerifierPolicy ----

    struct AlwaysMeetsPolicy;
    impl VerifierPolicy<FakeCertificate> for AlwaysMeetsPolicy {
        fn verifying_critical_extensions(&self) -> Vec<Oid> {
            vec![]
        }
        fn chain_meets_policy_requirements(
            &mut self,
            _chain: &UnverifiedCertificateChain<FakeCertificate>,
        ) -> PolicyEvaluationResult {
            Ok(())
        }
    }

    #[test]
    fn trivial_chain_succeeds_leaf_intermediate_root() {
        let leaf = make_cert("leaf", "intermediate", "leaf-key");
        let intermediate = make_cert("intermediate", "root", "intermediate-key");
        let root = make_cert("root", "root", "root-key");

        let roots = CertificateStore::from_iter(vec![root.clone()]);
        let intermediates = CertificateStore::from_iter(vec![intermediate.clone()]);
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        match result {
            ChainValidationResult::ValidCertificate(chain) => {
                let certs: Vec<&FakeCertificate> = chain.iter().collect();
                assert_eq!(certs.len(), 3);
                assert_eq!(certs[0].subject.0, b"leaf");
                assert_eq!(certs[1].subject.0, b"intermediate");
                assert_eq!(certs[2].subject.0, b"root");
            }
            ChainValidationResult::CouldNotValidate(reasons) => {
                panic!("expected valid chain, got failures: {reasons:?}")
            }
        }
    }

    #[test]
    fn missing_issuer_fails() {
        let leaf = make_cert("leaf", "nowhere", "leaf-key");
        let roots: CertificateStore<FakeCertificate> = CertificateStore::new();
        let intermediates: CertificateStore<FakeCertificate> = CertificateStore::new();
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert!(matches!(result, ChainValidationResult::CouldNotValidate(_)));
    }

    #[test]
    fn leaf_directly_in_root_store_is_accepted_immediately() {
        let leaf = make_cert("leaf-is-root", "leaf-is-root", "leaf-key");
        let roots = CertificateStore::from_iter(vec![leaf.clone()]);
        let intermediates: CertificateStore<FakeCertificate> = CertificateStore::new();
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        match result {
            ChainValidationResult::ValidCertificate(chain) => {
                let certs: Vec<&FakeCertificate> = chain.iter().collect();
                assert_eq!(certs.len(), 1);
                assert_eq!(certs[0].subject.0, b"leaf-is-root");
            }
            ChainValidationResult::CouldNotValidate(reasons) => {
                panic!("expected immediate root acceptance, got failures: {reasons:?}")
            }
        }
    }

    #[test]
    fn candidate_with_non_verifying_signature_is_skipped() {
        // intermediate's signature over root's tbs won't actually be
        // checked here; rather, the intermediate itself has "intermediate-key"
        // as its public key, which is what signs the leaf's tbs. Wiring the
        // rejecting verifier fails that check, so the intermediate is
        // skipped as a candidate issuer for leaf, and no path to root exists.
        let leaf = make_cert("leaf", "intermediate", "leaf-key");
        let intermediate = make_cert("intermediate", "root", "intermediate-key");
        let root = make_cert("root", "root", "root-key");

        let roots = CertificateStore::from_iter(vec![root]);
        let intermediates = CertificateStore::from_iter(vec![intermediate]);
        let crypto = rejecting_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert!(matches!(result, ChainValidationResult::CouldNotValidate(_)));
    }

    #[test]
    fn loop_prevention_self_referential_candidate_terminates() {
        // A malformed intermediate that claims to be issued by itself (same
        // subject and issuer name). The DFS pulls it in once as the leaf's
        // issuer, then must not pull it in again as its own issuer — proving
        // identity-based loop prevention, since otherwise this would
        // recurse/loop forever instead of returning.
        let self_signed = make_cert("only", "only", "only-key");

        let roots: CertificateStore<FakeCertificate> = CertificateStore::new();
        let mut intermediates = CertificateStore::new();
        intermediates.append(self_signed);
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        // Leaf's issuer matches the self-referential intermediate's subject.
        let leaf = make_cert("leaf", "only", "leaf-key");

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        // No root present, so this cannot validate — the important
        // assertion is that this call returns at all (proving the DFS
        // terminates) rather than hanging.
        assert!(matches!(result, ChainValidationResult::CouldNotValidate(_)));
    }

    #[test]
    fn leaf_with_unhandled_critical_extension_is_rejected() {
        let mut leaf = make_cert("leaf", "root", "leaf-key");
        leaf.extensions.critical_oids = vec![Oid(vec![1, 2, 3])];

        let root = make_cert("root", "root", "root-key");
        let roots = CertificateStore::from_iter(vec![root]);
        let intermediates: CertificateStore<FakeCertificate> = CertificateStore::new();
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        match result {
            ChainValidationResult::CouldNotValidate(reasons) => {
                assert_eq!(reasons.len(), 1);
            }
            ChainValidationResult::ValidCertificate(_) => panic!("expected rejection"),
        }
    }

    #[test]
    fn candidate_with_unhandled_critical_extension_is_skipped() {
        let leaf = make_cert("leaf", "root", "leaf-key");
        let mut root = make_cert("root", "root", "root-key");
        root.extensions.critical_oids = vec![Oid(vec![9, 9, 9])];

        let roots = CertificateStore::from_iter(vec![root]);
        let intermediates: CertificateStore<FakeCertificate> = CertificateStore::new();
        let crypto = always_valid_crypto();
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, AlwaysMeetsPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        assert!(matches!(result, ChainValidationResult::CouldNotValidate(_)));
    }

    #[test]
    fn policy_failure_on_first_root_candidate_continues_search() {
        // Two roots share the same subject name "root"; only the second
        // one (by insertion order, since no AKI/SKI is set to reorder them)
        // satisfies the policy. Confirms policy failures accumulate and the
        // DFS keeps trying further candidates rather than stopping at the
        // first failure.
        let leaf = make_cert("leaf", "root", "leaf-key");
        let wrong_root = make_cert("root", "root", "wrong-root-key");
        let right_root = make_cert("root", "root", "right-root-key");

        let roots = CertificateStore::from_iter(vec![wrong_root, right_root]);
        let intermediates: CertificateStore<FakeCertificate> = CertificateStore::new();
        let crypto = always_valid_crypto();

        // Policy requires the accepted chain's root to have "right-root-key";
        // simulate via subject check trick: use RequireRootSubjectPolicy but
        // key off public key instead by wrapping: simplest is to just check
        // both roots have same subject, so RequireRootSubjectPolicy can't
        // distinguish. Instead, use a policy keyed on public key.
        struct RequireRootKeyPolicy;
        impl VerifierPolicy<FakeCertificate> for RequireRootKeyPolicy {
            fn verifying_critical_extensions(&self) -> Vec<Oid> {
                vec![]
            }
            fn chain_meets_policy_requirements(
                &mut self,
                chain: &UnverifiedCertificateChain<FakeCertificate>,
            ) -> crate::policy::PolicyEvaluationResult {
                let root = &chain[chain.len() - 1];
                if root.public_key.0 == b"right-root-key" {
                    Ok(())
                } else {
                    Err(PolicyFailureReason::new("wrong root key"))
                }
            }
        }
        let mut verifier = BaseVerifier::with_policy_and_backend(roots, RequireRootKeyPolicy, &crypto);

        let result = verifier.validate_with_diagnostics(&leaf, &intermediates, &mut |_| {});
        match result {
            ChainValidationResult::ValidCertificate(chain) => {
                assert_eq!(chain.root().public_key.0, b"right-root-key");
            }
            ChainValidationResult::CouldNotValidate(reasons) => {
                panic!("expected eventual success, got: {reasons:?}")
            }
        }
    }

    #[test]
    fn sort_by_suitability_prefers_matching_ski_over_aki() {
        let mut subject = make_cert("subject", "issuer", "subject-key");
        subject.extensions.aki = Some(b"target-ski".to_vec());

        let mut non_matching = make_cert("issuer", "root", "non-matching-key");
        non_matching.extensions.ski = Some(b"other-ski".to_vec());

        let mut matching = make_cert("issuer", "root", "matching-key");
        matching.extensions.ski = Some(b"target-ski".to_vec());

        let mut candidates = vec![non_matching.clone(), matching.clone()];
        sort_by_suitability_for_issuing(&mut candidates, &subject);

        assert_eq!(candidates[0].public_key.0, b"matching-key");
        assert_eq!(candidates[1].public_key.0, b"non-matching-key");
    }
}
