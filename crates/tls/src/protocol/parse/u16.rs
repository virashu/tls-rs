use anyhow::Result;

use super::{RawDeser, RawSer, RawSize};

impl RawSize for u16 {
    fn size(&self) -> usize {
        2
    }
}

impl RawDeser for u16 {
    fn deser(raw: &[u8]) -> Result<Self> {
        Ok(u16::from_be_bytes([raw[0], raw[1]]))
    }
}

impl RawSer for u16 {
    fn ser(&self) -> Box<[u8]> {
        Box::new(self.to_be_bytes())
    }
}
