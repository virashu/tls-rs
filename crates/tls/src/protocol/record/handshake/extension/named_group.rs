use anyhow::Result;

use crate::{
    macros::auto_from,
    protocol::parse::{RawDeser, RawSize},
};

auto_from! {
    #[repr(u16)]
    #[allow(non_camel_case_types)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum NamedGroup {
        /* Elliptic Curve Groups (ECDHE) */
        secp256r1 = 0x0017,
        secp384r1 = 0x0018,
        secp521r1 = 0x0019,
        x25519 = 0x001D,
        x448 = 0x001E,

        /* Finite Field Groups (DHE) */
        ffdhe2048 = 0x0100,
        ffdhe3072 = 0x0101,
        ffdhe4096 = 0x0102,
        ffdhe6144 = 0x0103,
        ffdhe8192 = 0x0104,
    }
}

impl RawSize for NamedGroup {
    fn size(&self) -> usize {
        2
    }
}

impl RawDeser for NamedGroup {
    fn deser(raw: &[u8]) -> Result<Self> {
        Ok(Self::from(u16::from_be_bytes([raw[0], raw[1]])))
    }
}
