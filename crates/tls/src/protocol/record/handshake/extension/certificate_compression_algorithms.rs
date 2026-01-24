use anyhow::Result;

use crate::{
    macros::auto_try_from,
    protocol::parse::{DataVec8, RawDeser, RawSize},
};

auto_try_from! {
    #[repr(u16)]
    #[allow(non_camel_case_types)]
    #[derive(Clone, Copy, Debug)]
    pub enum CertificateCompressionAlgorithm {
        zlib = 1,
        brotli = 2,
        zstd = 3,
    }
}

impl RawDeser for CertificateCompressionAlgorithm {
    fn deser(raw: &[u8]) -> Result<Self> {
        Self::try_from(u16::deser(raw)?)
    }
}

impl RawSize for CertificateCompressionAlgorithm {
    fn size(&self) -> usize {
        2
    }
}

#[derive(Clone, Debug)]
pub struct CertificateCompressionAlgorithms {
    pub algorithms: DataVec8<CertificateCompressionAlgorithm>,
}

impl RawDeser for CertificateCompressionAlgorithms {
    fn deser(raw: &[u8]) -> Result<Self> {
        Ok(Self {
            algorithms: DataVec8::deser(raw)?,
        })
    }
}
