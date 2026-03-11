use anyhow::{Context, Result, anyhow, ensure};

pub struct Addons {
    pub inner: Box<[u8]>,
}

impl Addons {
    pub fn serialize(&self) -> Box<[u8]> {
        todo!()
    }

    pub fn deserialize(raw: &mut dyn Iterator<Item = u8>) -> Result<Self> {
        let addons_length = raw.next().context("")? as usize;
        let addons = raw.take(addons_length).collect::<Box<[u8]>>();
        ensure!(addons_length == addons.len());

        Ok(Self { inner: addons })
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Command {
    TCP = 0x01,
    UDP = 0x02,
}

impl TryFrom<u8> for Command {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::TCP),
            0x02 => Ok(Self::UDP),

            _ => Err(anyhow!("Unknown `Command` value: 0x{value:02X}")),
        }
    }
}

pub enum Address {
    Ipv4([u8; 4]),
    Domain(Box<[u8]>),
    Ipv6([u8; 16]),
}

impl Address {
    pub fn serialize(&self) -> Box<[u8]> {
        todo!()
    }

    pub fn deserialize(raw: &mut dyn Iterator<Item = u8>) -> Result<Self> {
        let address_type = raw.next().context("")?;

        match address_type {
            0x01 => {
                let address = raw.take(4).collect::<Box<[u8]>>().as_ref().try_into()?;

                Ok(Self::Ipv4(address))
            }
            0x02 => {
                let domain_length = raw.next().context("")? as usize;
                let domain = raw.take(domain_length).collect::<Box<[u8]>>();
                ensure!(domain_length == domain.len());

                Ok(Self::Domain(domain))
            }
            0x03 => {
                let address = raw.take(16).collect::<Box<[u8]>>().as_ref().try_into()?;

                Ok(Self::Ipv6(address))
            }

            _ => Err(anyhow!("Unknown Address Type: 0x{address_type:02X}")),
        }
    }
}

pub struct RequestHeader {
    pub version: u8,
    pub user_id: [u8; 16],
    pub addons: Addons,
    pub command: Command,
    pub port: u16,
    pub address: Address,
}

impl RequestHeader {
    pub fn serialize(&self) -> Box<[u8]> {
        let mut buf = Vec::new();

        buf.push(self.version);
        buf.extend(self.user_id);
        buf.extend(self.addons.serialize());
        buf.push(self.command as u8);
        buf.extend(self.port.to_be_bytes());
        buf.extend(self.address.serialize());

        buf.into_boxed_slice()
    }

    pub fn deserialize(raw: &mut dyn Iterator<Item = u8>) -> Result<Self> {
        let version = raw.next().context("")?;
        let user_id = raw.take(16).collect::<Box<[u8]>>().as_ref().try_into()?;

        let addons = Addons::deserialize(raw)?;
        let command = Command::try_from(raw.next().context("")?)?;
        let port = u16::from_be_bytes(raw.take(2).collect::<Box<[u8]>>().as_ref().try_into()?);

        let address = Address::deserialize(raw)?;

        Ok(Self {
            version,
            user_id,
            addons,
            command,
            port,
            address,
        })
    }
}

pub struct Request {
    pub header: RequestHeader,
    pub content: Box<[u8]>,
}

impl Request {
    pub fn deserialize(raw: &mut dyn Iterator<Item = u8>) -> Result<Self> {
        let header = RequestHeader::deserialize(raw)?;
        let content = raw.collect();

        Ok(Self { header, content })
    }
}

pub struct ResponseHeader {
    pub version: u8,
    pub addons: Addons,
}

impl ResponseHeader {
    pub fn deserialize(raw: &mut dyn Iterator<Item = u8>) -> Result<Self> {
        let version = raw.next().context("")?;
        let addons = Addons::deserialize(raw)?;

        Ok(Self { version, addons })
    }
}

pub struct Response {
    pub header: ResponseHeader,
    pub content: Box<[u8]>,
}

impl Response {
    pub fn deserialize(raw: &mut dyn Iterator<Item = u8>) -> Result<Self> {
        let header = ResponseHeader::deserialize(raw)?;
        let content = raw.collect();

        Ok(Self { header, content })
    }
}
