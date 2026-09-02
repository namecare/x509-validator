//! Extended Key Usage policy, RFC 5280 §4.2.1.12.

use x509_validator::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE;
use x509_validator::rfc5280::{CertificateRole, EkuPolicy, eku_oids};
use x509_validator::{ValidationPolicy, policy};
use x509_validator_testkit::rcgen::{CertificateParams, CustomExtension, ExtendedKeyUsagePurpose};
use x509_validator_testkit::{chain_of, issue_ca, issue_leaf_with, self_signed_ca_with};

/// id-ce-extKeyUsage, 2.5.29.37, as the generator's arc-of-u64 form.
const EKU_OID_ARCS: &[u64] = &[2, 5, 29, 37];

/// Attaches an extendedKeyUsage naming exactly the given purposes.
fn with_ekus(purposes: Vec<ExtendedKeyUsagePurpose>) -> impl FnOnce(&mut CertificateParams) {
    move |params: &mut CertificateParams| {
        params.extended_key_usages = purposes;
    }
}

/// Attaches a hand-built extendedKeyUsage, for the shapes the generator will
/// not produce: an empty SEQUENCE, or bytes that are not well-formed DER.
fn with_raw_eku(body: Vec<u8>) -> impl FnOnce(&mut CertificateParams) {
    move |params: &mut CertificateParams| {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(EKU_OID_ARCS, body));
    }
}

/// `SEQUENCE {}` — present, but naming no key purpose.
fn empty_eku_sequence() -> Vec<u8> {
    vec![0x30, 0x00]
}

/// A SEQUENCE whose length header runs past the end of the buffer.
fn malformed_eku() -> Vec<u8> {
    vec![0x30, 0x7f, 0x06, 0x03]
}

/// serverAuth, or anyExtendedKeyUsage standing in for it.
fn server_auth_or_any() -> EkuPolicy {
    EkuPolicy::key_purposes([eku_oids::server_auth(), eku_oids::any_extended_key_usage()])
}

// ---------------------------------------------------------------------------
// The required purpose is present.
// ---------------------------------------------------------------------------

#[test]
fn leaf_naming_the_required_purpose_is_accepted() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &root,
        with_ekus(vec![ExtendedKeyUsagePurpose::ServerAuth]),
    );
    let chain = chain_of(vec![leaf, root.der]);

    assert_eq!(
        EkuPolicy::server_auth().chain_meets_policy_requirements(&chain),
        Ok(())
    );
}

#[test]
fn required_purpose_among_several_is_accepted() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &root,
        with_ekus(vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::EmailProtection,
        ]),
    );
    let chain = chain_of(vec![leaf, root.der]);

    assert_eq!(
        EkuPolicy::server_auth().chain_meets_policy_requirements(&chain),
        Ok(())
    );
}

#[test]
fn client_auth_is_not_satisfied_by_server_auth() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &root,
        with_ekus(vec![ExtendedKeyUsagePurpose::ServerAuth]),
    );
    let chain = chain_of(vec![leaf, root.der]);

    assert!(
        EkuPolicy::client_auth()
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

#[test]
fn an_arbitrary_purpose_oid_can_be_required() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &root,
        with_ekus(vec![ExtendedKeyUsagePurpose::CodeSigning]),
    );
    let chain = chain_of(vec![leaf, root.der]);

    assert_eq!(
        EkuPolicy::new(eku_oids::code_signing()).chain_meets_policy_requirements(&chain),
        Ok(())
    );
}

// ---------------------------------------------------------------------------
// Several accepted purposes: any one of them suffices.
// ---------------------------------------------------------------------------

#[test]
fn any_one_of_the_accepted_purposes_suffices() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &root,
        with_ekus(vec![ExtendedKeyUsagePurpose::Any]),
    );
    let chain = chain_of(vec![leaf, root.der]);

    assert_eq!(
        server_auth_or_any().chain_meets_policy_requirements(&chain),
        Ok(())
    );
}

#[test]
fn a_purpose_outside_the_accepted_set_is_rejected() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &root,
        with_ekus(vec![ExtendedKeyUsagePurpose::ClientAuth]),
    );
    let chain = chain_of(vec![leaf, root.der]);

    assert!(
        server_auth_or_any()
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

/// anyExtendedKeyUsage carries no special meaning: it satisfies a requirement
/// only when it is one of the accepted purposes.
#[test]
fn any_extended_key_usage_alone_does_not_satisfy_a_specific_purpose() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &root,
        with_ekus(vec![ExtendedKeyUsagePurpose::Any]),
    );
    let chain = chain_of(vec![leaf, root.der]);

    assert!(
        EkuPolicy::server_auth()
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// An absent extension asserts no restriction.
// ---------------------------------------------------------------------------

#[test]
fn leaf_without_the_extension_is_accepted() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf_with("leaf", &["www.example.com"], &root, |_| {});
    let chain = chain_of(vec![leaf, root.der]);

    assert_eq!(
        EkuPolicy::server_auth().chain_meets_policy_requirements(&chain),
        Ok(())
    );
}

#[test]
fn requiring_the_extension_rejects_a_leaf_without_one() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf_with("leaf", &["www.example.com"], &root, |_| {});
    let chain = chain_of(vec![leaf, root.der]);

    assert!(
        EkuPolicy::server_auth()
            .applies_to(CertificateRole::EndEntity)
            .require_extension()
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

#[test]
fn requiring_the_extension_accepts_a_leaf_that_names_the_purpose() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &root,
        with_ekus(vec![ExtendedKeyUsagePurpose::ServerAuth]),
    );
    let chain = chain_of(vec![leaf, root.der]);

    assert_eq!(
        EkuPolicy::server_auth()
            .applies_to(CertificateRole::EndEntity)
            .require_extension()
            .chain_meets_policy_requirements(&chain),
        Ok(())
    );
}

/// Requiring the extension chain-wide also binds the issuers, which is why
/// the requirement is normally narrowed to the end entity: issuers throughout
/// the deployed web PKI omit the extension.
#[test]
fn requiring_the_extension_chain_wide_rejects_an_issuer_without_one() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &root,
        with_ekus(vec![ExtendedKeyUsagePurpose::ServerAuth]),
    );
    let chain = chain_of(vec![leaf, root.der]);

    assert!(
        EkuPolicy::server_auth()
            .require_extension()
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Malformed and empty extensions fail closed.
// ---------------------------------------------------------------------------

#[test]
fn empty_eku_sequence_is_rejected() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &root,
        with_raw_eku(empty_eku_sequence()),
    );
    let chain = chain_of(vec![leaf, root.der]);

    assert!(
        EkuPolicy::server_auth()
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

#[test]
fn malformed_eku_extension_is_rejected() {
    let root = self_signed_ca_with("root", |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &root,
        with_raw_eku(malformed_eku()),
    );
    let chain = chain_of(vec![leaf, root.der]);

    assert!(
        EkuPolicy::server_auth()
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Roles: which certificates the requirement lands on.
// ---------------------------------------------------------------------------

#[test]
fn entire_chain_rejects_a_restrictive_issuer() {
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca(
        "intermediate",
        &root,
        None,
        with_ekus(vec![ExtendedKeyUsagePurpose::ClientAuth]),
    );
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &intermediate,
        with_ekus(vec![ExtendedKeyUsagePurpose::ServerAuth]),
    );
    let chain = chain_of(vec![leaf, intermediate.der, root.der]);

    assert!(
        EkuPolicy::server_auth()
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

#[test]
fn end_entity_role_ignores_a_restrictive_issuer() {
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca(
        "intermediate",
        &root,
        None,
        with_ekus(vec![ExtendedKeyUsagePurpose::ClientAuth]),
    );
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &intermediate,
        with_ekus(vec![ExtendedKeyUsagePurpose::ServerAuth]),
    );
    let chain = chain_of(vec![leaf, intermediate.der, root.der]);

    assert_eq!(
        EkuPolicy::server_auth()
            .applies_to(CertificateRole::EndEntity)
            .chain_meets_policy_requirements(&chain),
        Ok(())
    );
}

#[test]
fn issuers_role_ignores_a_restrictive_leaf() {
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca(
        "intermediate",
        &root,
        None,
        with_ekus(vec![ExtendedKeyUsagePurpose::ServerAuth]),
    );
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &intermediate,
        with_ekus(vec![ExtendedKeyUsagePurpose::ClientAuth]),
    );
    let chain = chain_of(vec![leaf, intermediate.der, root.der]);

    assert_eq!(
        EkuPolicy::server_auth()
            .applies_to(CertificateRole::Issuers)
            .chain_meets_policy_requirements(&chain),
        Ok(())
    );
}

#[test]
fn issuers_role_rejects_a_restrictive_intermediate() {
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca(
        "intermediate",
        &root,
        None,
        with_ekus(vec![ExtendedKeyUsagePurpose::ClientAuth]),
    );
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &intermediate,
        with_ekus(vec![ExtendedKeyUsagePurpose::ServerAuth]),
    );
    let chain = chain_of(vec![leaf, intermediate.der, root.der]);

    assert!(
        EkuPolicy::server_auth()
            .applies_to(CertificateRole::Issuers)
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

#[test]
fn issuers_role_covers_the_trust_anchor() {
    let root = self_signed_ca_with("root", with_ekus(vec![ExtendedKeyUsagePurpose::ClientAuth]));
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &intermediate,
        with_ekus(vec![ExtendedKeyUsagePurpose::ServerAuth]),
    );
    let chain = chain_of(vec![leaf, intermediate.der, root.der]);

    assert!(
        EkuPolicy::server_auth()
            .applies_to(CertificateRole::Issuers)
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

#[test]
fn excluding_the_anchor_ignores_a_restrictive_root() {
    let root = self_signed_ca_with("root", with_ekus(vec![ExtendedKeyUsagePurpose::ClientAuth]));
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &intermediate,
        with_ekus(vec![ExtendedKeyUsagePurpose::ServerAuth]),
    );
    let chain = chain_of(vec![leaf, intermediate.der, root.der]);

    assert_eq!(
        EkuPolicy::server_auth()
            .applies_to(CertificateRole::IssuersExcludingAnchor)
            .chain_meets_policy_requirements(&chain),
        Ok(())
    );
}

#[test]
fn excluding_the_anchor_still_checks_intermediates() {
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca(
        "intermediate",
        &root,
        None,
        with_ekus(vec![ExtendedKeyUsagePurpose::ClientAuth]),
    );
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &intermediate,
        with_ekus(vec![ExtendedKeyUsagePurpose::ServerAuth]),
    );
    let chain = chain_of(vec![leaf, intermediate.der, root.der]);

    assert!(
        EkuPolicy::server_auth()
            .applies_to(CertificateRole::IssuersExcludingAnchor)
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

/// A one-certificate chain is that certificate acting as the end entity, so
/// an issuer-scoped requirement has nothing to check.
#[test]
fn issuer_roles_are_vacuous_on_a_single_certificate_chain() {
    let root = self_signed_ca_with("root", with_ekus(vec![ExtendedKeyUsagePurpose::ClientAuth]));
    let chain = chain_of(vec![root.der]);

    assert_eq!(
        EkuPolicy::server_auth()
            .applies_to(CertificateRole::IssuersExcludingAnchor)
            .chain_meets_policy_requirements(&chain),
        Ok(())
    );
}

#[test]
fn end_entity_role_checks_a_single_certificate_chain() {
    let root = self_signed_ca_with("root", with_ekus(vec![ExtendedKeyUsagePurpose::ClientAuth]));
    let chain = chain_of(vec![root.der]);

    assert!(
        EkuPolicy::server_auth()
            .applies_to(CertificateRole::EndEntity)
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Composing roles: a stricter rule for the end entity than for its issuers.
// ---------------------------------------------------------------------------

#[test]
fn a_composed_policy_requires_the_purpose_of_the_leaf_and_allows_any_on_issuers() {
    let composed = || {
        policy! {
            EkuPolicy::server_auth()
                .applies_to(CertificateRole::EndEntity)
                .require_extension();
            server_auth_or_any().applies_to(CertificateRole::IssuersExcludingAnchor)
        }
    };

    // An issuer standing on anyExtendedKeyUsage is accepted.
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca(
        "intermediate",
        &root,
        None,
        with_ekus(vec![ExtendedKeyUsagePurpose::Any]),
    );
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &intermediate,
        with_ekus(vec![ExtendedKeyUsagePurpose::ServerAuth]),
    );
    let chain = chain_of(vec![leaf, intermediate.der, root.der]);
    assert_eq!(composed().chain_meets_policy_requirements(&chain), Ok(()));

    // The same latitude does not extend to the end entity.
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf = issue_leaf_with(
        "leaf",
        &["www.example.com"],
        &intermediate,
        with_ekus(vec![ExtendedKeyUsagePurpose::Any]),
    );
    let chain = chain_of(vec![leaf, intermediate.der, root.der]);
    assert!(
        composed()
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );

    // Nor does an end entity that omits the extension pass.
    let root = self_signed_ca_with("root", |_| {});
    let intermediate = issue_ca("intermediate", &root, None, |_| {});
    let leaf = issue_leaf_with("leaf", &["www.example.com"], &intermediate, |_| {});
    let chain = chain_of(vec![leaf, intermediate.der, root.der]);
    assert!(
        composed()
            .chain_meets_policy_requirements(&chain)
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Extension claims.
// ---------------------------------------------------------------------------

#[test]
fn policy_claims_the_extended_key_usage_extension() {
    assert_eq!(
        EkuPolicy::server_auth().verifying_critical_extensions(),
        vec![OID_X509_EXT_EXTENDED_KEY_USAGE]
    );
}
