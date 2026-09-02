use crate::der_parser::Oid;
use crate::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE;
use crate::unverified_chain::UnverifiedCertificateChain;
use crate::{Certificate, PolicyEvaluationResult, PolicyFailureReason, ValidationPolicy};

/// The key purpose OIDs registered by RFC 5280 §4.2.1.12.
pub mod eku_oids {
    use crate::der_parser::{Oid, oid};

    /// id-kp-serverAuth, 1.3.6.1.5.5.7.3.1.
    pub fn server_auth() -> Oid<'static> {
        oid!(1.3.6.1.5.5.7.3.1)
    }

    /// id-kp-clientAuth, 1.3.6.1.5.5.7.3.2.
    pub fn client_auth() -> Oid<'static> {
        oid!(1.3.6.1.5.5.7.3.2)
    }

    /// id-kp-codeSigning, 1.3.6.1.5.5.7.3.3.
    pub fn code_signing() -> Oid<'static> {
        oid!(1.3.6.1.5.5.7.3.3)
    }

    /// id-kp-emailProtection, 1.3.6.1.5.5.7.3.4.
    pub fn email_protection() -> Oid<'static> {
        oid!(1.3.6.1.5.5.7.3.4)
    }

    /// id-kp-timeStamping, 1.3.6.1.5.5.7.3.8.
    pub fn time_stamping() -> Oid<'static> {
        oid!(1.3.6.1.5.5.7.3.8)
    }

    /// id-kp-OCSPSigning, 1.3.6.1.5.5.7.3.9.
    pub fn ocsp_signing() -> Oid<'static> {
        oid!(1.3.6.1.5.5.7.3.9)
    }

    /// anyExtendedKeyUsage, 2.5.29.37.0.
    pub fn any_extended_key_usage() -> Oid<'static> {
        oid!(2.5.29.37.0)
    }
}

/// id-ce-extKeyUsage, RFC 5280 §4.2.1.12: 2.5.29.37.
fn extended_key_usage_oid() -> Oid<'static> {
    OID_X509_EXT_EXTENDED_KEY_USAGE
}

/// The part a certificate plays in a chain, which decides whether a given
/// requirement applies to it.
///
/// A chain is ordered from the end entity to the trust anchor, so the role is
/// a matter of position: the first certificate is the end entity and the rest
/// are its issuers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CertificateRole {
    /// The end entity certificate alone.
    EndEntity,
    /// Every issuer above the end entity, the trust anchor included.
    Issuers,
    /// Every issuer above the end entity, the trust anchor excluded.
    ///
    /// An anchor is trusted because it is in the store, so what it claims
    /// about its own key can be left out of the decision.
    IssuersExcludingAnchor,
    /// Every certificate on the path.
    EntireChain,
}

impl CertificateRole {
    /// Whether a certificate at `index` of a `length`-certificate chain plays
    /// this role.
    fn covers(self, index: usize, length: usize) -> bool {
        let is_end_entity = index == 0;
        let is_anchor = index + 1 == length;
        match self {
            Self::EndEntity => is_end_entity,
            Self::Issuers => !is_end_entity,
            Self::IssuersExcludingAnchor => !is_end_entity && !is_anchor,
            Self::EntireChain => true,
        }
    }
}

/// A [`ValidationPolicy`] that requires a key purpose from the extendedKeyUsage
/// extension, RFC 5280 §4.2.1.12.
///
/// A certificate satisfies the policy when its extendedKeyUsage names any one
/// of the accepted key purposes. The extension is optional, and a certificate
/// without one asserts no restriction, so it satisfies the policy as well —
/// [`EkuPolicy::require_extension`] withdraws that latitude.
///
/// RFC 5280 does not say whether an extendedKeyUsage on a CA restricts what
/// that CA may issue for. By default the requirement applies to every
/// certificate on the path, so a restrictive issuer constrains the chain
/// beneath it; [`EkuPolicy::applies_to`] narrows that to one
/// [`CertificateRole`].
///
/// `anyExtendedKeyUsage` gets no special treatment. It satisfies a policy only
/// where it is one of the accepted purposes, which
/// [`EkuPolicy::key_purposes`] makes explicit at the call site.
///
/// # Examples
///
/// A TLS server certificate, with the requirement applied chain-wide:
///
/// ```
/// use x509_validator::rfc5280::EkuPolicy;
///
/// let policy = EkuPolicy::server_auth();
/// ```
///
/// Where issuers need more latitude than the end entity, compose two: the end
/// entity must name serverAuth, while its issuers may stand on
/// `anyExtendedKeyUsage` instead.
///
/// ```
/// use x509_validator::policy;
/// use x509_validator::rfc5280::{CertificateRole, EkuPolicy, eku_oids};
///
/// let policy = policy! {
///     EkuPolicy::server_auth()
///         .applies_to(CertificateRole::EndEntity)
///         .require_extension();
///     EkuPolicy::key_purposes([eku_oids::server_auth(), eku_oids::any_extended_key_usage()])
///         .applies_to(CertificateRole::IssuersExcludingAnchor)
/// };
/// ```
pub struct EkuPolicy {
    accepted_purposes: Vec<Oid<'static>>,
    role: CertificateRole,
    extension_required: bool,
}

impl EkuPolicy {
    /// Requires `purpose`.
    pub fn new(purpose: Oid<'static>) -> Self {
        Self::key_purposes([purpose])
    }

    /// Requires any one of `purposes`.
    pub fn key_purposes(purposes: impl IntoIterator<Item = Oid<'static>>) -> Self {
        Self {
            accepted_purposes: purposes.into_iter().collect(),
            role: CertificateRole::EntireChain,
            extension_required: false,
        }
    }

    /// Requires id-kp-serverAuth, the purpose a TLS server certificate needs.
    pub fn server_auth() -> Self {
        Self::new(eku_oids::server_auth())
    }

    /// Requires id-kp-clientAuth, the purpose a TLS client certificate needs.
    pub fn client_auth() -> Self {
        Self::new(eku_oids::client_auth())
    }

    /// Narrows the requirement to certificates playing `role`. Applies to the
    /// entire chain by default.
    pub fn applies_to(mut self, role: CertificateRole) -> Self {
        self.role = role;
        self
    }

    /// Requires the extension to be present, so that a certificate omitting it
    /// no longer counts as unrestricted.
    ///
    /// Pair this with [`CertificateRole::EndEntity`] unless the chain is known
    /// to carry the extension throughout: issuers across the deployed web PKI
    /// leave it out, and the requirement binds every certificate it covers.
    pub fn require_extension(mut self) -> Self {
        self.extension_required = true;
        self
    }

    fn certificate_meets_requirement(
        &self,
        certificate: &Certificate<'_>,
    ) -> PolicyEvaluationResult {
        let extension = certificate
            .tbs_certificate
            .get_extension_unique(&extended_key_usage_oid())
            .map_err(|error| {
                PolicyFailureReason::new(format!(
                    "error processing extended key usage for {:?}: {}",
                    certificate, error
                ))
            })?;

        let Some(extension) = extension else {
            return if self.extension_required {
                Err(PolicyFailureReason::new(format!(
                    "certificate {:?} carries no extended key usage extension",
                    certificate
                )))
            } else {
                // No extension, so no restriction to enforce.
                Ok(())
            };
        };

        // RFC 5280 §4.2.1.12 defines the extension as a SEQUENCE SIZE (1..MAX),
        // so a present-but-empty one is malformed. It has to be caught from the
        // raw bytes: parsing yields the same all-absent value for an empty
        // SEQUENCE as for one naming only unrecognised purposes.
        if is_empty_sequence(extension.value) {
            return Err(PolicyFailureReason::new(format!(
                "certificate {:?} has an empty extended key usage extension",
                certificate
            )));
        }

        // A present extension that failed to parse surfaces as an error here
        // rather than as an absent one, so malformed contents fail closed.
        let usage = certificate
            .tbs_certificate
            .extended_key_usage()
            .map_err(|error| {
                PolicyFailureReason::new(format!(
                    "error processing extended key usage for {:?}: {}",
                    certificate, error
                ))
            })?
            .ok_or_else(|| {
                PolicyFailureReason::new(format!(
                    "error processing extended key usage for {:?}",
                    certificate
                ))
            })?;

        if self.accepts(usage.value) {
            Ok(())
        } else {
            Err(PolicyFailureReason::new(format!(
                "certificate {:?} names none of the accepted extended key usages {}",
                certificate,
                self.accepted_purposes_display()
            )))
        }
    }

    /// Whether any accepted purpose is among a certificate's key purposes.
    ///
    /// The parser lifts the purposes it recognises into named booleans and
    /// leaves the rest in `other`, so both have to be consulted.
    fn accepts(&self, usage: &crate::extensions::ExtendedKeyUsage<'_>) -> bool {
        let named = [
            (usage.server_auth, eku_oids::server_auth()),
            (usage.client_auth, eku_oids::client_auth()),
            (usage.code_signing, eku_oids::code_signing()),
            (usage.email_protection, eku_oids::email_protection()),
            (usage.time_stamping, eku_oids::time_stamping()),
            (usage.ocsp_signing, eku_oids::ocsp_signing()),
            (usage.any, eku_oids::any_extended_key_usage()),
        ];

        self.accepted_purposes
            .iter()
            .any(|accepted| {
                named
                    .iter()
                    .any(|(present, oid)| *present && oid == accepted)
                    || usage.other.contains(accepted)
            })
    }

    fn accepted_purposes_display(&self) -> String {
        self.accepted_purposes
            .iter()
            .map(|oid| oid.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Whether `value` is a DER SEQUENCE with no contents. DER admits only the
/// zero-length short form, so this is `30 00` exactly.
fn is_empty_sequence(value: &[u8]) -> bool {
    value == [0x30, 0x00]
}

impl ValidationPolicy for EkuPolicy {
    fn verifying_critical_extensions(&self) -> Vec<Oid<'static>> {
        vec![extended_key_usage_oid()]
    }

    fn chain_meets_policy_requirements(
        &self,
        chain: &UnverifiedCertificateChain<'_>,
    ) -> PolicyEvaluationResult {
        let length = chain.len();
        for (index, certificate) in chain.iter().enumerate() {
            if self.role.covers(index, length) {
                self.certificate_meets_requirement(certificate)?;
            }
        }
        Ok(())
    }
}
