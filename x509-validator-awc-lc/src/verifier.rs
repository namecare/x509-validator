use x509_validator_core::{ChainValidationResult, Verifier};

pub struct AwsVerifier {

}

impl Verifier<Vec<u8>, aws_lc_rs::error::Unspecified> for AwsVerifier {
    fn new(root_certificates_der: &[Vec<u8>]) -> Self {
        todo!()
    }

    fn validate(&mut self, leaf: &Vec<u8>, intermediates: &[Vec<u8>]) -> ChainValidationResult<Vec<u8>, R> {
        todo!()
    }
}