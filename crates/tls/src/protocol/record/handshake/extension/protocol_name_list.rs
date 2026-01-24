use anyhow::Result;

use crate::protocol::parse::{DataVec8, DataVec16, RawDeser, RawSer, RawSize};

#[derive(Clone, Debug)]
pub struct ProtocolName(DataVec8<u8>);

impl ProtocolName {
    pub fn new(protocol: &[u8]) -> Result<Self> {
        Ok(Self(DataVec8::try_from(protocol)?))
    }
}

impl RawSize for ProtocolName {
    fn size(&self) -> usize {
        self.0.size()
    }
}

impl RawSer for ProtocolName {
    fn ser(&self) -> Box<[u8]> {
        self.0.ser()
    }
}

impl RawDeser for ProtocolName {
    fn deser(raw: &[u8]) -> Result<Self> {
        Ok(Self(DataVec8::deser(raw)?))
    }
}

#[derive(Clone, Debug)]
pub struct ProtocolNameList {
    pub protocol_name_list: DataVec16<ProtocolName>,
}

impl RawSer for ProtocolNameList {
    fn ser(&self) -> Box<[u8]> {
        self.protocol_name_list.ser()
    }
}

impl RawDeser for ProtocolNameList {
    fn deser(raw: &[u8]) -> Result<Self> {
        Ok(Self {
            protocol_name_list: DataVec16::<ProtocolName>::deser(raw)?,
        })
    }
}
