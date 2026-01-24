use anyhow::Result;
use utils::concat_dyn;

use crate::protocol::{
    parse::{DataVec16, RawDeser, RawSer},
    record::handshake::extension::SignatureScheme,
};

#[derive(Clone, Debug)]
pub struct CertificateVerify {
    pub algorithm: SignatureScheme,
    pub signature: DataVec16<u8>,
}

impl CertificateVerify {
    pub fn new(algorithm: SignatureScheme, signature: &[u8]) -> Result<Self> {
        Ok(Self {
            algorithm,
            signature: DataVec16::try_from(signature)?,
        })
    }
}

impl RawSer for CertificateVerify {
    fn ser(&self) -> Box<[u8]> {
        concat_dyn!(self.algorithm.ser(), self.signature.ser())
    }
}

impl RawDeser for CertificateVerify {
    fn deser(raw: &[u8]) -> anyhow::Result<Self> {
        todo!()
    }
}
