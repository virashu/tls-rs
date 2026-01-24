use anyhow::{Ok, Result};

use crate::{
    macros::auto_try_from,
    protocol::parse::{DataVec8, RawDeser, RawSize},
};

auto_try_from! {
    #[repr(u8)]
    #[derive(Clone, Copy, Debug)]
    pub enum EcPointFormat {
        Uncompressed = 0,
        Deprecated1 = 1,
        Deprecated2 = 2,
    }
}

impl RawSize for EcPointFormat {
    fn size(&self) -> usize {
        1
    }
}

impl RawDeser for EcPointFormat {
    fn deser(raw: &[u8]) -> Result<Self> {
        Self::try_from(raw[0])
    }
}

#[derive(Clone, Debug)]
pub struct EcPointFormats {
    pub ec_point_format_list: Box<[EcPointFormat]>,
}

impl RawDeser for EcPointFormats {
    fn deser(raw: &[u8]) -> Result<Self> {
        let ec_point_format_list = DataVec8::<EcPointFormat>::deser(raw)?.into_inner();

        Ok(Self {
            ec_point_format_list,
        })
    }
}
