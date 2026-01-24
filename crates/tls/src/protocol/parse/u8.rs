use anyhow::Result;

use super::{RawDeser, RawSer, RawSize};

impl RawSize for u8 {
    fn size(&self) -> usize {
        1
    }
}

impl RawDeser for u8 {
    fn deser(raw: &[u8]) -> Result<Self> {
        Ok(raw[0])
    }
}

impl RawSer for u8 {
    fn ser(&self) -> Box<[u8]> {
        Box::new(self.to_be_bytes())
    }
}
