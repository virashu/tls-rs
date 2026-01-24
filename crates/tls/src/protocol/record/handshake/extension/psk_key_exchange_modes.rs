use anyhow::Result;

use crate::{
    macros::auto_try_from,
    protocol::parse::{DataVec8, RawDeser, RawSize},
};

auto_try_from! {
    #[repr(u8)]
    #[allow(non_camel_case_types)]
    #[derive(Clone, Copy, Debug)]
    pub enum PskKeyExchangeMode {
        psk_ke = 0,
        psk_dhe_ke = 1,
    }
}

impl RawSize for PskKeyExchangeMode {
    fn size(&self) -> usize {
        1
    }
}

impl RawDeser for PskKeyExchangeMode {
    fn deser(raw: &[u8]) -> Result<Self> {
        Self::try_from(raw[0])
    }
}

#[derive(Clone, Debug)]
pub struct PskKeyExchangeModes {
    pub ke_modes: Box<[PskKeyExchangeMode]>,
}

impl RawDeser for PskKeyExchangeModes {
    fn deser(raw: &[u8]) -> Result<Self> {
        let ke_modes = DataVec8::<PskKeyExchangeMode>::deser(raw)?.into_inner();

        Ok(Self { ke_modes })
    }
}
