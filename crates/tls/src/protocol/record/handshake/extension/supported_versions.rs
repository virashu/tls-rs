use anyhow::Result;

use crate::protocol::parse::{DataVec8, RawDeser};

#[derive(Clone, Debug)]
pub struct SupportedVersionsClientHello {
    pub versions: Box<[u16]>,
}

impl RawDeser for SupportedVersionsClientHello {
    fn deser(raw: &[u8]) -> Result<Self> {
        let versions = DataVec8::<u16>::deser(raw)?.into_inner();

        Ok(Self { versions })
    }
}

#[derive(Clone, Debug)]
pub struct SupportedVersionsServerHello {
    pub selected_version: u16,
}

impl RawDeser for SupportedVersionsServerHello {
    fn deser(raw: &[u8]) -> Result<Self> {
        let selected_version = u16::from_be_bytes([raw[0], raw[1]]);

        Ok(Self { selected_version })
    }
}
