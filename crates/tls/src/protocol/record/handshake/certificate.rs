use anyhow::Result;
use utils::concat_dyn;

use crate::protocol::parse::{DataVec8, DataVec16, DataVec24, RawDeser, RawSer, RawSize};

#[derive(Clone, Debug)]
pub struct CertificateExtension {}

impl RawSer for CertificateExtension {
    fn ser(&self) -> Box<[u8]> {
        Box::new([])
    }
}

#[derive(Clone, Debug)]
pub enum CertificateEntryContent {
    /// ID: 0
    X509 { cert_data: DataVec24<u8> },
    /// ID: 2
    RawPublicKey {
        asn1_subject_public_key_info: DataVec24<u8>,
    },
}

impl RawSer for CertificateEntryContent {
    fn ser(&self) -> Box<[u8]> {
        match self {
            CertificateEntryContent::X509 { cert_data } => cert_data.ser(),
            CertificateEntryContent::RawPublicKey {
                asn1_subject_public_key_info,
            } => asn1_subject_public_key_info.ser(),
        }
    }
}

impl RawSize for CertificateEntryContent {
    fn size(&self) -> usize {
        match self {
            CertificateEntryContent::X509 { cert_data } => cert_data.size(),
            CertificateEntryContent::RawPublicKey {
                asn1_subject_public_key_info,
            } => asn1_subject_public_key_info.size(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CertificateEntry {
    pub content: CertificateEntryContent,

    pub extensions: DataVec16<CertificateExtension>,
}

impl CertificateEntry {
    pub fn new(cert: &[u8]) -> Result<Self> {
        Ok(Self {
            content: CertificateEntryContent::X509 {
                cert_data: DataVec24::try_from(cert)?,
            },
            extensions: DataVec16::new(),
        })
    }
}

impl RawSize for CertificateEntry {
    fn size(&self) -> usize {
        self.content.size() + self.extensions.size()
    }
}

impl RawDeser for CertificateEntry {
    fn deser(raw: &[u8]) -> Result<Self> {
        todo!()
    }
}

impl RawSer for CertificateEntry {
    fn ser(&self) -> Box<[u8]> {
        concat_dyn![self.content.ser(), self.extensions.ser()]
    }
}

#[derive(Clone, Debug)]
pub struct Certificate {
    pub certificate_request_context: DataVec8<u8>,
    pub certificate_list: DataVec24<CertificateEntry>,
}

impl Certificate {
    pub fn new(context: &[u8], certificates: &[CertificateEntry]) -> Result<Self> {
        Ok(Self {
            certificate_request_context: DataVec8::try_from(context)?,
            certificate_list: DataVec24::try_from(certificates)?,
        })
    }
}

impl RawDeser for Certificate {
    fn deser(raw: &[u8]) -> Result<Self> {
        let context = DataVec8::deser(raw)?;
        let list = DataVec24::<CertificateEntry>::deser(&raw[context.size()..])?;

        Ok(Self {
            certificate_request_context: context,
            certificate_list: list,
        })
    }
}

impl RawSer for Certificate {
    fn ser(&self) -> Box<[u8]> {
        concat_dyn![
            self.certificate_request_context.ser(),
            self.certificate_list.ser()
        ]
    }
}
