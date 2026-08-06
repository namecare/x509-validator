use crate::signature;
use x509_validator_core::FromDer;
use x509_validator_core::error::{PolicyFailure, PolicyFailureReason};
use x509_validator_core::unverified_chain::UnverifiedCertificateChain;
use x509_validator_core::validated_chain::ValidatedCertificateChain;
use x509_validator_core::{Certificate, ChainValidationResult};

pub struct Verifier<'a> {
    roots: Vec<Certificate<'a>>,
}

impl<'a> x509_validator_core::Verifier<'a> for Verifier<'a> {
    fn new(root_certificates: &'a [Certificate<'a>]) -> Self {
        Self {
            roots: root_certificates.to_vec(),
        }
    }

    /// `root_certificates` must be one or more concatenated DER-encoded
    /// certificates (not PEM) — decoding PEM would require allocating owned
    /// bytes that cannot satisfy this crate's `'a` roots, since decoded DER
    /// can't be a subslice of the original PEM text.
    fn with_raw_certificates(root_certificates: &'a [u8]) -> Self {
        let mut remaining = root_certificates;
        let mut roots = Vec::new();

        while !remaining.is_empty() {
            match Certificate::from_der(remaining) {
                Ok((rest, cert)) => {
                    roots.push(cert);
                    remaining = rest;
                }
                Err(_) => break,
            }
        }

        Self { roots }
    }

    fn validate_raw(&self, leaf: &'a [u8], intermediates: &'a [&'a [u8]]) -> ChainValidationResult<'a> {
        let leaf = match Certificate::from_der(leaf) {
            Ok((_, leaf)) => leaf,
            Err(_) => {
                return ChainValidationResult::CouldNotValidate(PolicyFailure::new(
                    UnverifiedCertificateChain::new(vec![]),
                    PolicyFailureReason::new("leaf certificate could not be parsed"),
                ))
            }
        };

        let intermediates: Vec<Certificate> = match intermediates
            .iter()
            .map(|der| Certificate::from_der(der).map(|(_, cert)| cert))
            .collect::<Result<_, _>>()
        {
            Ok(intermediates) => intermediates,
            Err(_) => {
                return ChainValidationResult::CouldNotValidate(PolicyFailure::new(
                    UnverifiedCertificateChain::new(vec![leaf]),
                    PolicyFailureReason::new("intermediate certificate could not be parsed"),
                ))
            }
        };

        self.validate(leaf, intermediates)
    }

    fn validate(&self, leaf: Certificate<'a>, intermediates: Vec<Certificate<'a>>) -> ChainValidationResult<'a> {
        let mut chain = vec![leaf];
        loop {
            let current = chain.last().unwrap();

            if let Some(root) = self.roots.iter().find(|root| root.subject() == current.issuer()) {
                if signature::verify(
                    root.public_key(),
                    &current.signature_algorithm,
                    current.signature_value.as_ref(),
                    current.tbs_certificate.as_ref(),
                )
                .is_err()
                {
                    return could_not_validate(chain, "signature verification against trusted root failed");
                }

                chain.push(root.clone());
                return ChainValidationResult::ValidCertificate(ValidatedCertificateChain::new_unchecked(chain));
            }

            let issuer = intermediates
                .iter()
                .find(|candidate| candidate.subject() == current.issuer() && !chain.iter().any(|c| c.as_raw() == candidate.as_raw()));

            let Some(issuer) = issuer else {
                return could_not_validate(chain, "no trusted root or intermediate found for issuer");
            };

            if signature::verify(
                issuer.public_key(),
                &current.signature_algorithm,
                current.signature_value.as_ref(),
                current.tbs_certificate.as_ref(),
            )
            .is_err()
            {
                return could_not_validate(chain, "signature verification against intermediate failed");
            }

            chain.push(issuer.clone());
        }
    }
}

fn could_not_validate<'a>(chain: Vec<Certificate<'a>>, reason: &str) -> ChainValidationResult<'a> {
    ChainValidationResult::CouldNotValidate(PolicyFailure::new(
        UnverifiedCertificateChain::new(chain),
        PolicyFailureReason::new(reason),
    ))
}