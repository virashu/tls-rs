use anyhow::{Result, bail};

use crate::protocol::parse::{DataVec16, RawDeser, RawSize};

#[derive(Clone, Debug)]
pub enum ServerName {
    HostName(Box<[u8]>),
}

impl RawSize for ServerName {
    fn size(&self) -> usize {
        match self {
            ServerName::HostName(n) => n.len() + 2,
        }
    }
}

impl RawDeser for ServerName {
    fn deser(raw: &[u8]) -> Result<Self> {
        let name_type = raw[0];

        Ok(match name_type {
            0 => {
                let data = DataVec16::<u8>::deser(&raw[1..])?.into_inner();
                Self::HostName(data)
            }
            _ => bail!("Unknown ServerName type: {name_type}"),
        })
    }
}

#[derive(Clone, Debug)]
pub struct ServerNameList {
    pub server_name_list: Box<[ServerName]>,
}

impl RawDeser for ServerNameList {
    fn deser(raw: &[u8]) -> Result<Self> {
        // TODO: Fix implementation
        let length = u16::from_be_bytes([raw[0], raw[1]]);
        let payload = &raw[2..];

        let mut server_name_list = Vec::new();
        let mut offset: usize = 0;
        while offset < length as usize {
            let Ok(el) = ServerName::deser(&payload[offset..]) else {
                break;
            };
            offset += el.size();
            server_name_list.push(el);
        }

        Ok(Self {
            server_name_list: server_name_list.into_boxed_slice(),
        })
    }
}
