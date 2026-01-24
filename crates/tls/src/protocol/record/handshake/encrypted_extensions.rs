use anyhow::Result;

use crate::protocol::{
    parse::{DataVec16, RawDeser, RawSer},
    record::handshake::server_hello::ServerHelloExtension,
};
// #[derive(Clone, Debug)]
// pub struct EncryptedExtensionsExtension {}

// impl RawSer for EncryptedExtensionsExtension {
//     fn ser(&self) -> Box<[u8]> {
//         todo!()
//     }
// }

// impl RawDeser for EncryptedExtensionsExtension {
//     fn deser(raw: &[u8]) -> Result<Self> {
//         todo!()
//     }
// }

// impl RawSize for EncryptedExtensionsExtension {
//     fn size(&self) -> usize {
//         todo!()
//     }
// }

#[derive(Clone, Debug)]
pub struct EncryptedExtensions {
    extensions: DataVec16<ServerHelloExtension>,
}

impl EncryptedExtensions {
    pub fn new(extensions: &[ServerHelloExtension]) -> Result<Self> {
        Ok(Self {
            extensions: DataVec16::try_from(extensions)?,
        })
    }
}

impl RawSer for EncryptedExtensions {
    fn ser(&self) -> Box<[u8]> {
        self.extensions.ser()
    }
}

impl RawDeser for EncryptedExtensions {
    fn deser(raw: &[u8]) -> Result<Self> {
        Ok(Self {
            extensions: DataVec16::deser(raw)?,
        })
    }
}
