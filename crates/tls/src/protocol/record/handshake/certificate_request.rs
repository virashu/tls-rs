use anyhow::Result;

use super::extension::{SignatureAlgorithms, SignatureScheme, extension_types};
use crate::protocol::parse::{DataVec8, DataVec16, RawDeser, RawSer, RawSize};

#[derive(Clone, Debug)]
pub enum CertificateRequestExtensionContent {
    SignatureAlgorithms(SignatureAlgorithms),
}

#[derive(Clone, Debug)]
pub struct CertificateRequestExtension {
    pub content: CertificateRequestExtensionContent,
}

impl RawSize for CertificateRequestExtension {
    fn size(&self) -> usize {
        match &self.content {
            CertificateRequestExtensionContent::SignatureAlgorithms(s_a) => s_a.size(),
        }
    }
}

impl RawSer for CertificateRequestExtension {
    fn ser(&self) -> Box<[u8]> {
        match &self.content {
            CertificateRequestExtensionContent::SignatureAlgorithms(s_a) => {
                let mut res = Vec::new();

                res.extend(extension_types::SIGNATURE_ALGORITHMS.to_be_bytes());
                res.extend(s_a.ser());

                res.into_boxed_slice()
            }
        }
    }
}

impl CertificateRequestExtension {
    pub fn new_signature_algorithms(signature_algorithms: &[SignatureScheme]) -> Result<Self> {
        Ok(Self {
            content: CertificateRequestExtensionContent::SignatureAlgorithms(SignatureAlgorithms {
                supported_signature_algorithms: DataVec16::try_from(signature_algorithms)?,
            }),
        })
    }
}

#[derive(Clone, Debug)]
pub struct CertificateRequest {
    pub certificate_request_context: DataVec8<u8>,
    pub extensions: DataVec16<CertificateRequestExtension>,
}

impl CertificateRequest {
    pub fn new(context: &[u8], extensions: &[CertificateRequestExtension]) -> Result<Self> {
        Ok(Self {
            certificate_request_context: DataVec8::try_from(context)?,
            extensions: DataVec16::try_from(extensions)?,
        })
    }
}

impl RawDeser for CertificateRequest {
    fn deser(raw: &[u8]) -> Result<Self> {
        todo!()
    }
}

impl RawSer for CertificateRequest {
    fn ser(&self) -> Box<[u8]> {
        let mut res = Vec::new();

        res.extend(self.certificate_request_context.ser());
        res.extend(self.extensions.ser());

        res.into_boxed_slice()
    }
}
