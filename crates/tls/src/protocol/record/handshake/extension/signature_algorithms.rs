use anyhow::Result;

use super::signature_scheme::SignatureScheme;
use crate::protocol::parse::{DataVec16, RawDeser, RawSer, RawSize};

#[derive(Clone, Debug)]
pub struct SignatureAlgorithms {
    pub supported_signature_algorithms: DataVec16<SignatureScheme>,
}

impl RawSize for SignatureAlgorithms {
    fn size(&self) -> usize {
        self.supported_signature_algorithms.size()
    }
}

impl RawSer for SignatureAlgorithms {
    fn ser(&self) -> Box<[u8]> {
        self.supported_signature_algorithms.ser()
    }
}

impl RawDeser for SignatureAlgorithms {
    fn deser(raw: &[u8]) -> Result<Self> {
        Ok(Self {
            supported_signature_algorithms: DataVec16::<SignatureScheme>::deser(raw)?,
        })
    }
}
