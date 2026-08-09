//! RFC 5280 policy composition: that each sub-policy is wired into
//! RFC5280Policy and can independently reject a chain.

use x509_validator::{PolicyEvaluationResult, PolicyFailureReason, RFC5280Policy, Timestamp, ValidationPolicy};

mod tests {
    use super::*;
    use x509_validator_core::oid_registry::{OID_X509_EXT_BASIC_CONSTRAINTS, OID_X509_EXT_KEY_USAGE, OID_X509_EXT_NAME_CONSTRAINTS};
    use x509_validator_testkit::rcgen::CertificateParams;
    use x509_validator_testkit::time::{Duration, OffsetDateTime};
    use x509_validator_testkit::{chain_of, dns_subtree, issue_leaf, name_constraints, self_signed_ca_with};

    fn with_validity(not_before: Timestamp, not_after: Timestamp) -> impl FnOnce(&mut CertificateParams) {
        move |params: &mut CertificateParams| {
            params.not_before = OffsetDateTime::UNIX_EPOCH + Duration::seconds(not_before);
            params.not_after = OffsetDateTime::UNIX_EPOCH + Duration::seconds(not_after);
        }
    }

    #[test]
    fn chain_passing_all_sub_policies_is_accepted() {
        let root = self_signed_ca_with("root", with_validity(1000, 2000));
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let chain = chain_of(vec![leaf, root.der]);

        let policy = RFC5280Policy::new(1500);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));
    }

    #[test]
    fn chain_failing_only_name_constraints_is_rejected() {
        // Identical to the accepted chain above except that the root now
        // excludes the leaf's DNS name — proving NameConstraintsPolicy is
        // genuinely wired into the composition.
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            with_validity(1000, 2000)(params);
            params.name_constraints = Some(name_constraints(vec![], vec![dns_subtree("example.com")]));
        });
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let chain = chain_of(vec![leaf, root.der]);

        let policy = RFC5280Policy::new(1500);
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("name is in an excluded subtree")
        );
    }

    #[test]
    fn chain_failing_only_basic_constraints_is_rejected() {
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            with_validity(1000, 2000)(params);
            params.is_ca = x509_validator_testkit::rcgen::IsCa::NoCa;
        });
        let leaf = issue_leaf("leaf", &[], &root);
        let chain = chain_of(vec![leaf, root.der]);

        let policy = RFC5280Policy::new(1500);
        assert!(policy.chain_meets_policy_requirements(&chain).is_err());
    }

    #[test]
    fn chain_failing_only_expiry_is_rejected() {
        let root = self_signed_ca_with("root", with_validity(1000, 2000));
        let leaf = issue_leaf("leaf", &[], &root);
        let chain = chain_of(vec![leaf, root.der]);

        let policy = RFC5280Policy::new(9999);
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("certificate has expired")
        );
    }

    #[test]
    fn with_validity_check_disabled_accepts_an_expired_chain() {
        let root = self_signed_ca_with("root", with_validity(1000, 2000));
        let leaf = issue_leaf("leaf", &[], &root);
        let chain = chain_of(vec![leaf, root.der]);

        // The same chain at the same "now" is rejected with expiry enabled.
        let enabled = RFC5280Policy::new(9999);
        assert!(enabled.chain_meets_policy_requirements(&chain).is_err());

        let root2 = self_signed_ca_with("root", with_validity(1000, 2000));
        let leaf2 = issue_leaf("leaf", &[], &root2);
        let chain2 = chain_of(vec![leaf2, root2.der]);
        let disabled = RFC5280Policy::with_validity_check_disabled();
        assert_eq!(disabled.chain_meets_policy_requirements(&chain2), Ok(()));
    }

    #[test]
    fn with_validity_check_disabled_still_enforces_the_other_policies() {
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            with_validity(1000, 2000)(params);
            params.name_constraints = Some(name_constraints(vec![], vec![dns_subtree("example.com")]));
        });
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let chain = chain_of(vec![leaf, root.der]);

        let policy = RFC5280Policy::with_validity_check_disabled();
        assert_eq!(
            policy.chain_meets_policy_requirements(&chain).unwrap_err(),
            PolicyFailureReason::new("name is in an excluded subtree")
        );
    }

    #[test]
    fn verifying_critical_extensions_includes_all_three_oids() {
        let policy = RFC5280Policy::new(1500);
        let oids = policy.verifying_critical_extensions();

        assert!(oids.contains(&OID_X509_EXT_BASIC_CONSTRAINTS), "missing basicConstraints OID");
        assert!(oids.contains(&OID_X509_EXT_NAME_CONSTRAINTS), "missing nameConstraints OID");
        assert!(oids.contains(&OID_X509_EXT_KEY_USAGE), "missing keyUsage OID");
    }
}

/// RFC 5280 conformance suite.
///
/// Every behavior here is checked twice: once against the composed
/// `RFC5280Policy`, and once against whichever individual sub-policy owns
/// the rule. `PolicyUnderTest` selects between the two so each behavior is
/// written once and driven from both directions — a sub-policy that
/// enforces a rule the composition forgot to wire up (or vice versa) shows
/// up as a failure in exactly one variant.
mod conformance {
    use super::*;
    use x509_validator::unverified_chain::UnverifiedCertificateChain;
    use x509_validator::{BasicConstraintsPolicy, ExpiryPolicy, NameConstraintsPolicy, VersionPolicy};
    use x509_validator_core::oid_registry::OID_X509_EXT_KEY_USAGE;
    use x509_validator_core::Certificate;
    use x509_validator_core::CertificateExt;
    use x509_validator_testkit::rcgen::CertificateParams;
    use x509_validator_testkit::time::{Duration, OffsetDateTime};
    use x509_validator_testkit::{
        broken_name_constraints_extension, broken_subject_alt_name_extension, chain_of, directory_name_subtree, dns_subtree,
        ipv4_subtree, issue_ca, issue_leaf, issue_leaf_with, issue_self_issued_ca, name_constraints,
        raw_name_constraints_extension, raw_subject_alt_name_extension, self_signed_ca_with, Ca, RawGeneralName,
    };

    /// The validation time every test that doesn't care about expiry uses;
    /// it sits inside the default validity window of the test certificates.
    const NOW: Timestamp = 1500;

    /// Which policy a behavior is being evaluated against.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PolicyUnderTest {
        /// The full composed policy.
        Composed,
        /// Only the sub-policy that owns the rule under test.
        Version,
        Expiry,
        BasicConstraints,
        NameConstraints,
    }

    impl PolicyUnderTest {
        fn evaluate(self, now: Timestamp, chain: &UnverifiedCertificateChain) -> PolicyEvaluationResult {
            match self {
                Self::Composed => RFC5280Policy::new(now).chain_meets_policy_requirements(chain),
                Self::Version => VersionPolicy.chain_meets_policy_requirements(chain),
                Self::Expiry => ExpiryPolicy::new(now).chain_meets_policy_requirements(chain),
                Self::BasicConstraints => BasicConstraintsPolicy.chain_meets_policy_requirements(chain),
                Self::NameConstraints => NameConstraintsPolicy.chain_meets_policy_requirements(chain),
            }
        }
    }

    /// Runs `body` against the composed policy and against `base`, the
    /// individual sub-policy that owns the rule.
    fn for_both_policies(base: PolicyUnderTest, body: impl Fn(PolicyUnderTest)) {
        body(PolicyUnderTest::Composed);
        body(base);
    }

    fn validity(not_before: Timestamp, not_after: Timestamp) -> impl Fn(&mut CertificateParams) {
        move |params: &mut CertificateParams| {
            params.not_before = OffsetDateTime::UNIX_EPOCH + Duration::seconds(not_before);
            params.not_after = OffsetDateTime::UNIX_EPOCH + Duration::seconds(not_after);
        }
    }

    /// A root / intermediate / leaf chain, all inside the default validity
    /// window, with no constraints of any kind.
    fn unconstrained_chain() -> (Ca, Ca, Vec<u8>) {
        let root = self_signed_ca_with("root", |_| {});
        let intermediate = issue_ca("intermediate", &root, None, |_| {});
        let leaf = issue_leaf("leaf", &["www.example.com"], &intermediate);
        (root, intermediate, leaf)
    }

    // -----------------------------------------------------------------
    // Version — RFC 5280 §4.1.2.1 and §4.1.2.9.
    // -----------------------------------------------------------------

    #[test]
    fn valid_certs_are_accepted() {
        let (root, intermediate, leaf) = unconstrained_chain();
        let chain = chain_of(vec![leaf, intermediate.der, root.der]);

        for_both_policies(PolicyUnderTest::Version, |policy| {
            assert_eq!(policy.evaluate(NOW, &chain), Ok(()), "{policy:?}");
        });
    }

    #[test]
    fn valid_v1_certs_are_accepted() {
        // A version 1 certificate carries no extensions at all. The
        // generator always emits v3 once any extension is present, so the
        // closest expressible shape is a certificate with no extensions
        // beyond the ones the generator insists on; the point of the rule
        // is that the absence of extensions is never itself a failure.
        let root = self_signed_ca_with("root", |_| {});
        let leaf = issue_leaf_with("leaf", &[], &root, |params: &mut CertificateParams| {
            params.use_authority_key_identifier_extension = false;
        });
        let chain = chain_of(vec![leaf, root.der]);

        for_both_policies(PolicyUnderTest::Version, |policy| {
            assert_eq!(policy.evaluate(NOW, &chain), Ok(()), "{policy:?}");
        });
    }

    #[test]
    fn v1_certs_with_extensions_are_rejected() {
        // RFC 5280 §4.1.2.9: extensions may only appear in v3
        // certificates. The certificate generator will not emit that
        // combination, so the rule is exercised directly against the
        // decision the policy makes about a certificate that claims v1
        // while carrying extensions.
        let root = self_signed_ca_with("root", |_| {});
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let leaf_der: &'static [u8] = Box::leak(leaf.into_boxed_slice());
        let parsed = Certificate::parse(leaf_der).unwrap();

        assert!(
            !parsed.tbs_certificate.extensions().is_empty(),
            "fixture must carry extensions for this rule to mean anything"
        );

        let mut downgraded = parsed.clone();
        downgraded.tbs_certificate.version = x509_validator_core::x509::X509Version::V1;
        let chain = UnverifiedCertificateChain::new(vec![downgraded]);

        for_both_policies(PolicyUnderTest::Version, |policy| {
            assert!(policy.evaluate(NOW, &chain).is_err(), "{policy:?}");
        });
    }

    // -----------------------------------------------------------------
    // Expiry — RFC 5280 §4.1.2.5.
    //
    // Each rule is checked at every position in the chain, and each is
    // paired with a check that disabling validity checking accepts the
    // same chain.
    // -----------------------------------------------------------------

    /// Where in the chain the certificate under test sits.
    #[derive(Clone, Copy, Debug)]
    enum Position {
        Leaf,
        Intermediate,
        Root,
    }

    /// Builds a root/intermediate/leaf chain where the certificate at
    /// `position` has the given validity window and every other
    /// certificate is valid for all of `1000..=9000`.
    fn chain_with_validity_at(position: Position, not_before: Timestamp, not_after: Timestamp) -> UnverifiedCertificateChain<'static> {
        let wide = validity(1000, 9000);
        let narrow = validity(not_before, not_after);

        match position {
            Position::Leaf => {
                let root = self_signed_ca_with("root", &wide);
                let intermediate = issue_ca("intermediate", &root, None, &wide);
                let leaf = issue_leaf_with("leaf", &["www.example.com"], &intermediate, &narrow);
                chain_of(vec![leaf, intermediate.der, root.der])
            }
            Position::Intermediate => {
                let root = self_signed_ca_with("root", &wide);
                let intermediate = issue_ca("intermediate", &root, None, &narrow);
                let leaf = issue_leaf_with("leaf", &["www.example.com"], &intermediate, &wide);
                chain_of(vec![leaf, intermediate.der, root.der])
            }
            Position::Root => {
                let root = self_signed_ca_with("root", &narrow);
                let intermediate = issue_ca("intermediate", &root, None, &wide);
                let leaf = issue_leaf_with("leaf", &["www.example.com"], &intermediate, &wide);
                chain_of(vec![leaf, intermediate.der, root.der])
            }
        }
    }

    /// Asserts that `now` rejects a chain whose certificate at `position`
    /// has the given window, and that disabling validity checking accepts
    /// the very same chain.
    fn assert_expiry_rejected_at(position: Position, not_before: Timestamp, not_after: Timestamp, now: Timestamp) {
        let chain = chain_with_validity_at(position, not_before, not_after);

        for_both_policies(PolicyUnderTest::Expiry, |policy| {
            assert!(policy.evaluate(now, &chain).is_err(), "{policy:?} at {position:?}");
        });

        // The same chain must pass once validity checking is switched off,
        // which also proves nothing *else* about the chain is at fault.
        let disabled = RFC5280Policy::with_validity_check_disabled();
        assert_eq!(disabled.chain_meets_policy_requirements(&chain), Ok(()), "{position:?}");
    }

    #[test]
    fn expired_leaf_is_rejected() {
        assert_expiry_rejected_at(Position::Leaf, 1000, 2000, 3000);
    }

    #[test]
    fn expired_intermediate_is_rejected() {
        assert_expiry_rejected_at(Position::Intermediate, 1000, 2000, 3000);
    }

    #[test]
    fn expired_root_is_rejected() {
        assert_expiry_rejected_at(Position::Root, 1000, 2000, 3000);
    }

    #[test]
    fn not_yet_valid_leaf_is_rejected() {
        assert_expiry_rejected_at(Position::Leaf, 5000, 6000, 4000);
    }

    #[test]
    fn not_yet_valid_intermediate_is_rejected() {
        assert_expiry_rejected_at(Position::Intermediate, 5000, 6000, 4000);
    }

    #[test]
    fn not_yet_valid_root_is_rejected() {
        assert_expiry_rejected_at(Position::Root, 5000, 6000, 4000);
    }

    /// notValidAfter earlier than notValidBefore: a window that can never
    /// contain any instant, so no validation time can satisfy it.
    #[test]
    fn malformed_expiry_is_rejected_in_leaf() {
        assert_expiry_rejected_at(Position::Leaf, 3000, 2000, 2500);
    }

    #[test]
    fn malformed_expiry_is_rejected_in_intermediate() {
        assert_expiry_rejected_at(Position::Intermediate, 3000, 2000, 2500);
    }

    #[test]
    fn malformed_expiry_is_rejected_in_root() {
        assert_expiry_rejected_at(Position::Root, 3000, 2000, 2500);
    }

    #[test]
    fn expiry_is_evaluated_against_the_time_the_policy_was_given() {
        // Policies in this crate take an explicit validation time rather
        // than reading a clock, so "a delay between constructing the
        // policy and using it" cannot change the verdict: the same policy
        // value must answer identically however much later it is used, and
        // the verdict must track the timestamp it was handed.
        let chain = chain_with_validity_at(Position::Leaf, 1000, 2000);

        let before_expiry = RFC5280Policy::new(1500);
        let after_expiry = RFC5280Policy::new(2500);

        // Interleave the evaluations to show neither policy's answer
        // depends on when, or in what order, it is invoked.
        assert_eq!(before_expiry.chain_meets_policy_requirements(&chain), Ok(()));
        assert!(after_expiry.chain_meets_policy_requirements(&chain).is_err());
        assert_eq!(before_expiry.chain_meets_policy_requirements(&chain), Ok(()));
        assert!(after_expiry.chain_meets_policy_requirements(&chain).is_err());
    }

    // -----------------------------------------------------------------
    // BasicConstraints — RFC 5280 §4.2.1.9.
    // -----------------------------------------------------------------

    #[test]
    fn self_signed_certs_must_be_marked_as_ca() {
        // A lone self-signed certificate presented as its own trust
        // anchor: acceptable only when basicConstraints asserts the CA
        // bit. Absent, negative, or undecodable basicConstraints all fail.
        let ca_unconstrained = self_signed_ca_with("root", |_| {}).der;
        let ca_path_len_zero = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.is_ca = x509_validator_testkit::rcgen::IsCa::Ca(x509_validator_testkit::rcgen::BasicConstraints::Constrained(0));
        })
        .der;
        let not_a_ca = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.is_ca = x509_validator_testkit::rcgen::IsCa::NoCa;
        })
        .der;

        for (der, expected_valid) in [(ca_unconstrained, true), (ca_path_len_zero, true), (not_a_ca, false)] {
            let chain = chain_of(vec![der]);
            for_both_policies(PolicyUnderTest::BasicConstraints, |policy| {
                assert_eq!(
                    policy.evaluate(NOW, &chain).is_ok(),
                    expected_valid,
                    "{policy:?} expected_valid={expected_valid}"
                );
            });
        }
    }

    #[test]
    fn intermediate_ca_must_be_marked_as_ca() {
        // An intermediate that does not assert the CA bit cannot issue.
        let root = self_signed_ca_with("root", |_| {});
        let bad_intermediate = issue_ca("intermediate", &root, None, |params: &mut CertificateParams| {
            params.is_ca = x509_validator_testkit::rcgen::IsCa::NoCa;
        });
        let leaf = issue_leaf("leaf", &["www.example.com"], &bad_intermediate);
        let bad_chain = chain_of(vec![leaf, bad_intermediate.der, root.der]);

        for_both_policies(PolicyUnderTest::BasicConstraints, |policy| {
            assert!(policy.evaluate(NOW, &bad_chain).is_err(), "{policy:?}");
        });

        // Swapping in a properly marked intermediate fixes it, proving the
        // rejection above is about the CA bit and nothing else.
        let (root, intermediate, leaf) = unconstrained_chain();
        let good_chain = chain_of(vec![leaf, intermediate.der, root.der]);

        for_both_policies(PolicyUnderTest::BasicConstraints, |policy| {
            assert_eq!(policy.evaluate(NOW, &good_chain), Ok(()), "{policy:?}");
        });
    }

    #[test]
    fn root_ca_must_be_marked_as_ca() {
        let bad_root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.is_ca = x509_validator_testkit::rcgen::IsCa::NoCa;
        });
        let leaf = issue_leaf("leaf", &["www.example.com"], &bad_root);
        let bad_chain = chain_of(vec![leaf, bad_root.der]);

        for_both_policies(PolicyUnderTest::BasicConstraints, |policy| {
            assert!(policy.evaluate(NOW, &bad_chain).is_err(), "{policy:?}");
        });

        let good_root = self_signed_ca_with("root", |_| {});
        let good_leaf = issue_leaf("leaf", &["www.example.com"], &good_root);
        let good_chain = chain_of(vec![good_leaf, good_root.der]);

        for_both_policies(PolicyUnderTest::BasicConstraints, |policy| {
            assert_eq!(policy.evaluate(NOW, &good_chain), Ok(()), "{policy:?}");
        });
    }

    #[test]
    fn path_length_constraints_from_intermediates_are_applied() {
        // A first-level intermediate with pathLenConstraint 0 may not have
        // any non-self-issued CA beneath it, so a second-level
        // intermediate overruns the budget.
        let root = self_signed_ca_with("root", |_| {});
        let first_level = issue_ca("first", &root, Some(0), |_| {});
        let second_level = issue_ca("second", &first_level, Some(0), |_| {});
        let leaf = issue_leaf("leaf", &["www.example.com"], &second_level);
        let too_long = chain_of(vec![leaf, second_level.der, first_level.der, root.der]);

        for_both_policies(PolicyUnderTest::BasicConstraints, |policy| {
            assert!(policy.evaluate(NOW, &too_long).is_err(), "{policy:?}");
        });

        // Raising the first-level constraint to 1 makes the same shape fit.
        let root = self_signed_ca_with("root", |_| {});
        let first_level = issue_ca("first", &root, Some(1), |_| {});
        let second_level = issue_ca("second", &first_level, Some(0), |_| {});
        let leaf = issue_leaf("leaf", &["www.example.com"], &second_level);
        let fits = chain_of(vec![leaf, second_level.der, first_level.der, root.der]);

        for_both_policies(PolicyUnderTest::BasicConstraints, |policy| {
            assert_eq!(policy.evaluate(NOW, &fits), Ok(()), "{policy:?}");
        });
    }

    #[test]
    fn path_length_constraints_on_roots_are_applied() {
        // Same rule, but the constraint lives on the trust anchor.
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.is_ca = x509_validator_testkit::rcgen::IsCa::Ca(x509_validator_testkit::rcgen::BasicConstraints::Constrained(0));
        });
        let first_level = issue_ca("first", &root, None, |_| {});
        let second_level = issue_ca("second", &first_level, None, |_| {});
        let leaf = issue_leaf("leaf", &["www.example.com"], &second_level);
        let too_long = chain_of(vec![leaf, second_level.der, first_level.der, root.der]);

        for_both_policies(PolicyUnderTest::BasicConstraints, |policy| {
            assert!(policy.evaluate(NOW, &too_long).is_err(), "{policy:?}");
        });

        // A pathLenConstraint of 0 permits no intermediate at all between
        // the root and the end entity: §4.2.1.9 counts the non-self-issued
        // certificates that follow, excluding the end entity itself. A
        // leaf issued directly by the root therefore fits exactly.
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.is_ca = x509_validator_testkit::rcgen::IsCa::Ca(x509_validator_testkit::rcgen::BasicConstraints::Constrained(0));
        });
        let leaf = issue_leaf("leaf", &["www.example.com"], &root);
        let fits = chain_of(vec![leaf, root.der]);

        for_both_policies(PolicyUnderTest::BasicConstraints, |policy| {
            assert_eq!(policy.evaluate(NOW, &fits), Ok(()), "{policy:?}");
        });
    }

    #[test]
    fn path_length_counts_only_non_self_issued_certificates() {
        // RFC 5280 §4.2.1.9: pathLenConstraint bounds the number of
        // *non-self-issued* intermediates that may follow. A CA re-issuing
        // itself under a fresh key keeps the same subject as its issuer,
        // so that hop must not consume the budget.
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.is_ca = x509_validator_testkit::rcgen::IsCa::Ca(x509_validator_testkit::rcgen::BasicConstraints::Constrained(0));
        });
        let self_issued = issue_self_issued_ca(&root, Some(0));
        let leaf = issue_leaf("leaf", &["www.example.com"], &self_issued);
        let chain = chain_of(vec![leaf, self_issued.der, root.der]);

        for_both_policies(PolicyUnderTest::BasicConstraints, |policy| {
            assert_eq!(policy.evaluate(NOW, &chain), Ok(()), "{policy:?}");
        });

        // The identical shape with a *differently named* intermediate does
        // consume the budget, and is therefore rejected. Without this the
        // test above would pass even if self-issued certificates were
        // simply never counted for any reason.
        let root = self_signed_ca_with("root", |params: &mut CertificateParams| {
            params.is_ca = x509_validator_testkit::rcgen::IsCa::Ca(x509_validator_testkit::rcgen::BasicConstraints::Constrained(0));
        });
        let other_named = issue_ca("someone-else", &root, Some(0), |_| {});
        let sub = issue_ca("sub", &other_named, Some(0), |_| {});
        let leaf = issue_leaf("leaf", &["www.example.com"], &sub);
        let chain = chain_of(vec![leaf, sub.der, other_named.der, root.der]);

        for_both_policies(PolicyUnderTest::BasicConstraints, |policy| {
            assert!(policy.evaluate(NOW, &chain).is_err(), "{policy:?}");
        });
    }

    // -----------------------------------------------------------------
    // NameConstraints — RFC 5280 §4.2.1.10.
    //
    // Each constraint kind is exercised from three angles, matching the
    // ways a constraint can reach the certificate it governs: a constraint
    // on the root reaching the leaf, a constraint on the intermediate
    // reaching the leaf, and a constraint on the root reaching the
    // intermediate.
    // -----------------------------------------------------------------

    /// Where the nameConstraints extension is placed, and which
    /// certificate carries the name it governs.
    #[derive(Clone, Copy, Debug)]
    enum ConstraintPlacement {
        RootConstrainsLeaf,
        IntermediateConstrainsLeaf,
        RootConstrainsIntermediate,
    }

    const PLACEMENTS: [ConstraintPlacement; 3] = [
        ConstraintPlacement::RootConstrainsLeaf,
        ConstraintPlacement::IntermediateConstrainsLeaf,
        ConstraintPlacement::RootConstrainsIntermediate,
    ];

    /// Builds a chain placing `constrain` (which installs a
    /// nameConstraints extension) and `name` (which installs the
    /// subjectAltName under test) per `placement`.
    fn constrained_chain(
        placement: ConstraintPlacement,
        constrain: &dyn Fn(&mut CertificateParams),
        name: &dyn Fn(&mut CertificateParams),
    ) -> UnverifiedCertificateChain<'static> {
        match placement {
            ConstraintPlacement::RootConstrainsLeaf => {
                let root = self_signed_ca_with("root", constrain);
                let intermediate = issue_ca("intermediate", &root, None, |_| {});
                let leaf = issue_leaf_with("leaf", &[], &intermediate, name);
                chain_of(vec![leaf, intermediate.der, root.der])
            }
            ConstraintPlacement::IntermediateConstrainsLeaf => {
                let root = self_signed_ca_with("root", |_| {});
                let intermediate = issue_ca("intermediate", &root, None, constrain);
                let leaf = issue_leaf_with("leaf", &[], &intermediate, name);
                chain_of(vec![leaf, intermediate.der, root.der])
            }
            ConstraintPlacement::RootConstrainsIntermediate => {
                let root = self_signed_ca_with("root", constrain);
                let intermediate = issue_ca("intermediate", &root, None, name);
                let leaf = issue_leaf("leaf", &[], &intermediate);
                chain_of(vec![leaf, intermediate.der, root.der])
            }
        }
    }

    /// Runs one constraint/name pairing through every placement and both
    /// policy variants, asserting the chain is accepted iff `expect_ok`.
    fn assert_constraint_outcome(
        constrain: &dyn Fn(&mut CertificateParams),
        name: &dyn Fn(&mut CertificateParams),
        expect_ok: bool,
    ) {
        assert_constraint_outcome_because(constrain, name, expect_ok, None);
    }

    /// As above, but when a rejection is expected, additionally pins the
    /// reason given — so a test cannot pass because the chain happened to
    /// be rejected by some unrelated rule.
    fn assert_constraint_outcome_because(
        constrain: &dyn Fn(&mut CertificateParams),
        name: &dyn Fn(&mut CertificateParams),
        expect_ok: bool,
        expected_reason: Option<&str>,
    ) {
        for placement in PLACEMENTS {
            let chain = constrained_chain(placement, constrain, name);
            for_both_policies(PolicyUnderTest::NameConstraints, |policy| {
                let result = policy.evaluate(NOW, &chain);
                assert_eq!(result.is_ok(), expect_ok, "{policy:?} {placement:?} expect_ok={expect_ok}");

                if let (Some(reason), Err(failure)) = (expected_reason, &result) {
                    assert_eq!(
                        failure,
                        &PolicyFailureReason::new(reason),
                        "{policy:?} {placement:?} rejected for the wrong reason"
                    );
                }
            });
        }
    }

    /// A certificate-configuring closure paired with a label naming the
    /// name form it installs, for tests that sweep several forms at once.
    type LabelledName = (&'static str, Box<dyn Fn(&mut CertificateParams)>);

    fn dns_san(name: &'static str) -> impl Fn(&mut CertificateParams) {
        move |params: &mut CertificateParams| {
            params.subject_alt_names = vec![x509_validator_testkit::rcgen::SanType::DnsName(name.try_into().unwrap())];
        }
    }

    fn ip_san(addr: std::net::IpAddr) -> impl Fn(&mut CertificateParams) {
        move |params: &mut CertificateParams| {
            params.subject_alt_names = vec![x509_validator_testkit::rcgen::SanType::IpAddress(addr)];
        }
    }

    fn uri_san(uri: &'static str) -> impl Fn(&mut CertificateParams) {
        move |params: &mut CertificateParams| {
            params.subject_alt_names = vec![x509_validator_testkit::rcgen::SanType::URI(uri.try_into().unwrap())];
        }
    }

    #[test]
    fn dns_name_excluded_subtrees() {
        // A name inside the excluded subtree is rejected; one outside it
        // is not.
        let excluded = |params: &mut CertificateParams| {
            params.name_constraints = Some(name_constraints(vec![], vec![dns_subtree("example.com")]));
        };
        assert_constraint_outcome(&excluded, &dns_san("www.example.com"), false);
        assert_constraint_outcome(&excluded, &dns_san("www.example.org"), true);
    }

    #[test]
    fn dns_name_permitted_subtrees() {
        let permitted = |params: &mut CertificateParams| {
            params.name_constraints = Some(name_constraints(vec![dns_subtree("example.com")], vec![]));
        };
        assert_constraint_outcome(&permitted, &dns_san("www.example.com"), true);
        assert_constraint_outcome(&permitted, &dns_san("www.example.org"), false);
    }

    #[test]
    fn ip_address_excluded_subtrees() {
        let excluded = |params: &mut CertificateParams| {
            params.name_constraints = Some(name_constraints(vec![], vec![ipv4_subtree([127, 0, 0, 0], [255, 0, 0, 0])]));
        };
        assert_constraint_outcome(&excluded, &ip_san("127.0.0.1".parse().unwrap()), false);
        assert_constraint_outcome(&excluded, &ip_san("10.0.0.1".parse().unwrap()), true);
    }

    #[test]
    fn ip_address_permitted_subtrees() {
        let permitted = |params: &mut CertificateParams| {
            params.name_constraints = Some(name_constraints(vec![ipv4_subtree([127, 0, 0, 0], [255, 0, 0, 0])], vec![]));
        };
        assert_constraint_outcome(&permitted, &ip_san("127.0.0.1".parse().unwrap()), true);
        assert_constraint_outcome(&permitted, &ip_san("10.0.0.1".parse().unwrap()), false);
    }

    #[test]
    fn uri_excluded_subtrees() {
        // The generator cannot express a URI subtree, so the constraint is
        // attached as hand-encoded DER.
        let excluded = |params: &mut CertificateParams| {
            params
                .custom_extensions
                .push(raw_name_constraints_extension(&[], &[RawGeneralName::uri("example.com")]));
        };
        assert_constraint_outcome(&excluded, &uri_san("https://www.example.com/path"), false);
        assert_constraint_outcome(&excluded, &uri_san("https://www.example.org/path"), true);
    }

    #[test]
    fn uri_permitted_subtrees() {
        let permitted = |params: &mut CertificateParams| {
            params
                .custom_extensions
                .push(raw_name_constraints_extension(&[RawGeneralName::uri("example.com")], &[]));
        };
        assert_constraint_outcome(&permitted, &uri_san("https://www.example.com/path"), true);
        assert_constraint_outcome(&permitted, &uri_san("https://www.example.org/path"), false);
    }

    #[test]
    fn directory_name_excluded_subtrees_always_fail() {
        // Correct directoryName comparison needs the full name-matching
        // algorithm of RFC 5280 §7.1, which this crate does not implement;
        // rather than enforce it partially, any chain involving a
        // directoryName subtree is rejected — whatever the names are.
        for constraint_name in ["Excluded", "Other"] {
            let excluded = move |params: &mut CertificateParams| {
                params.name_constraints = Some(name_constraints(vec![], vec![directory_name_subtree(constraint_name)]));
            };
            assert_constraint_outcome_because(
                &excluded,
                &|_| {},
                false,
                Some("directoryName name constraints are not supported"),
            );
        }
    }

    #[test]
    fn directory_name_permitted_subtrees_always_fail() {
        for constraint_name in ["Permitted", "Other"] {
            let permitted = move |params: &mut CertificateParams| {
                params.name_constraints = Some(name_constraints(vec![directory_name_subtree(constraint_name)], vec![]));
            };
            assert_constraint_outcome_because(
                &permitted,
                &|_| {},
                false,
                Some("directoryName name constraints are not supported"),
            );
        }
    }

    #[test]
    fn all_excluded_subtrees_are_evaluated() {
        // With several excluded subtrees of different kinds present, a
        // name matching *any one* of them must fail — the walk must not
        // stop at the first subtree, nor consider only its own kind.
        let names: [LabelledName; 3] = [
            ("uri", Box::new(uri_san("http://example.com/"))),
            ("dns", Box::new(dns_san("example.org"))),
            ("ip", Box::new(ip_san("127.0.0.1".parse().unwrap()))),
        ];

        let excluded = |params: &mut CertificateParams| {
            params.custom_extensions.push(raw_name_constraints_extension(
                &[],
                &[
                    RawGeneralName::uri("example.com"),
                    RawGeneralName::dns("example.org"),
                    RawGeneralName::ip(&[127, 0, 0, 1, 255, 0, 0, 0]),
                ],
            ));
        };

        for (label, name) in &names {
            for placement in PLACEMENTS {
                let chain = constrained_chain(placement, &excluded, name.as_ref());
                for_both_policies(PolicyUnderTest::NameConstraints, |policy| {
                    assert!(policy.evaluate(NOW, &chain).is_err(), "{policy:?} {placement:?} {label}");
                });
            }
        }
    }

    #[test]
    fn subtrees_of_unknown_type_always_fail() {
        // A constraint this crate cannot interpret must never be silently
        // ignored: it fails closed whether it appears as excluded or
        // permitted, and whether or not the certificate carries a name of
        // that kind.
        let unknown_kinds: [(&str, RawGeneralName); 5] = [
            ("otherName", RawGeneralName::other_name()),
            ("rfc822Name", RawGeneralName::rfc822("bar.com")),
            ("x400Address", RawGeneralName::x400_address()),
            ("ediPartyName", RawGeneralName::edi_party_name()),
            ("registeredID", RawGeneralName::registered_id()),
        ];

        for (label, subtree) in unknown_kinds {
            // Carry a name of the same kind, so the constraint is
            // genuinely reached rather than skipped for lack of a
            // comparable name.
            let matching_name = subtree.clone();
            let name = move |params: &mut CertificateParams| {
                params
                    .custom_extensions
                    .push(raw_subject_alt_name_extension(std::slice::from_ref(&matching_name)));
            };

            let excluded_subtree = subtree.clone();
            let excluded = move |params: &mut CertificateParams| {
                params
                    .custom_extensions
                    .push(raw_name_constraints_extension(&[], std::slice::from_ref(&excluded_subtree)));
            };

            let permitted_subtree = subtree.clone();
            let permitted = move |params: &mut CertificateParams| {
                params
                    .custom_extensions
                    .push(raw_name_constraints_extension(std::slice::from_ref(&permitted_subtree), &[]));
            };

            for placement in PLACEMENTS {
                for (which, constrain) in [
                    ("excluded", &excluded as &dyn Fn(&mut CertificateParams)),
                    ("permitted", &permitted as &dyn Fn(&mut CertificateParams)),
                ] {
                    let chain = constrained_chain(placement, constrain, &name);
                    for_both_policies(PolicyUnderTest::NameConstraints, |policy| {
                        assert!(
                            policy.evaluate(NOW, &chain).is_err(),
                            "{policy:?} {placement:?} {label} {which}"
                        );
                    });
                }
            }
        }
    }

    #[test]
    fn excluded_subtrees_beat_permitted_subtrees() {
        // The same name listed as both permitted and excluded must be
        // rejected: exclusion wins regardless of the order the two lists
        // are consulted in.
        let names: [LabelledName; 3] = [
            ("dns", Box::new(dns_san("example.com"))),
            ("ip", Box::new(ip_san("127.0.0.1".parse().unwrap()))),
            ("uri", Box::new(uri_san("https://example.com/"))),
        ];

        let both = |params: &mut CertificateParams| {
            let subtrees = [
                RawGeneralName::dns("example.com"),
                RawGeneralName::ip(&[127, 0, 0, 1, 255, 255, 255, 255]),
                RawGeneralName::uri("example.com"),
            ];
            params
                .custom_extensions
                .push(raw_name_constraints_extension(&subtrees, &subtrees));
        };

        for (label, name) in &names {
            for placement in PLACEMENTS {
                let chain = constrained_chain(placement, &both, name.as_ref());
                for_both_policies(PolicyUnderTest::NameConstraints, |policy| {
                    assert!(policy.evaluate(NOW, &chain).is_err(), "{policy:?} {placement:?} {label}");
                });
            }
        }
    }

    #[test]
    fn broken_name_constraints_extension_prevents_validation() {
        // An undecodable nameConstraints extension must fail closed: the
        // constraints it was meant to express cannot be checked, so the
        // chain cannot be trusted.
        let broken = |params: &mut CertificateParams| {
            params.custom_extensions.push(broken_name_constraints_extension());
        };

        for placement in PLACEMENTS {
            let chain = constrained_chain(placement, &broken, &dns_san("www.example.com"));
            for_both_policies(PolicyUnderTest::NameConstraints, |policy| {
                assert!(policy.evaluate(NOW, &chain).is_err(), "{policy:?} {placement:?}");
            });
        }
    }

    #[test]
    fn broken_subject_alternative_name_prevents_validation() {
        // Likewise for an undecodable SAN on the certificate being
        // constrained: the names it carries cannot be enumerated, so a
        // constraint cannot be shown to hold.
        let constrain = |params: &mut CertificateParams| {
            params.name_constraints = Some(name_constraints(vec![], vec![dns_subtree("example.com")]));
        };
        let broken_san = |params: &mut CertificateParams| {
            params.custom_extensions.push(broken_subject_alt_name_extension());
        };

        for placement in PLACEMENTS {
            let chain = constrained_chain(placement, &constrain, &broken_san);
            for_both_policies(PolicyUnderTest::NameConstraints, |policy| {
                assert!(policy.evaluate(NOW, &chain).is_err(), "{policy:?} {placement:?}");
            });
        }
    }

    // -----------------------------------------------------------------
    // Miscellaneous.
    // -----------------------------------------------------------------

    #[test]
    fn key_usage_is_ignored() {
        // RFC 5280 §4.2.1.3 says an intermediate whose keyUsage omits
        // keyCertSign must not sign certificates. This crate claims the
        // keyUsage OID as handled — so a critical keyUsage extension does
        // not block validation — but deliberately does not enforce the
        // rule, matching what mainstream implementations do.
        let root = self_signed_ca_with("root", |_| {});
        let intermediate = issue_ca("intermediate", &root, Some(0), |params: &mut CertificateParams| {
            params.key_usages = vec![x509_validator_testkit::rcgen::KeyUsagePurpose::DigitalSignature];
        });
        let leaf = issue_leaf("leaf", &["www.example.com"], &intermediate);
        let chain = chain_of(vec![leaf, intermediate.der, root.der]);

        let policy = RFC5280Policy::new(NOW);
        assert_eq!(policy.chain_meets_policy_requirements(&chain), Ok(()));

        // And the OID is claimed, which is what stops the critical
        // extension from failing the chain elsewhere in verification.
        assert!(policy.verifying_critical_extensions().contains(&OID_X509_EXT_KEY_USAGE));
    }

    #[test]
    fn weird_critical_extension_in_leaf_is_not_claimed_by_the_policy() {
        // A critical extension with an OID no policy understands must not
        // be silently accepted. The policy layer reports which critical
        // extensions it handles; an unrecognized one is absent from that
        // list, which is what causes verification to reject the chain.
        let root = self_signed_ca_with("root", |_| {});
        let leaf = issue_leaf_with("leaf", &["www.example.com"], &root, |params: &mut CertificateParams| {
            params.custom_extensions.push(x509_validator_testkit::weird_critical_extension());
        });
        let leaf_der: &'static [u8] = Box::leak(leaf.into_boxed_slice());
        let parsed = Certificate::parse(leaf_der).unwrap();

        let handled = RFC5280Policy::new(NOW).verifying_critical_extensions();

        let unhandled: Vec<_> = parsed
            .tbs_certificate
            .extensions()
            .iter()
            .filter(|extension| extension.critical && !handled.contains(&extension.oid))
            .map(|extension| extension.oid.clone())
            .collect();

        assert_eq!(unhandled.len(), 1, "expected exactly one unhandled critical extension");
        assert_eq!(unhandled[0].to_id_string(), "1.2.3.4.5");
    }
}
