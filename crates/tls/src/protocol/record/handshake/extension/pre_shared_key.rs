use crate::protocol::parse::{DataVec8, DataVec16, RawDeser, RawSize};

#[derive(Clone, Debug)]
pub struct PskIdentity {
    size: usize,

    // u16
    pub identity: Box<[u8]>,
    pub obfuscated_ticket_age: u32,
}

impl RawSize for PskIdentity {
    fn size(&self) -> usize {
        self.size
    }
}

impl RawDeser for PskIdentity {
    fn deser(raw: &[u8]) -> anyhow::Result<Self> {
        let identity = DataVec16::<u8>::deser(raw)?;
        let size = identity.size();
        let obfuscated_ticket_age = u32::from_be_bytes(raw[size..(size + 4)].try_into()?);

        Ok(Self {
            size: size + 4,
            identity: identity.into_inner(),
            obfuscated_ticket_age,
        })
    }
}

pub type PskBinderEntry = Box<[u8]>;

#[derive(Clone, Debug)]
pub struct PreSharedKeyExtensionClientHello {
    pub identities: Box<[PskIdentity]>,
    pub binders: Box<[PskBinderEntry]>,
}

impl RawDeser for PreSharedKeyExtensionClientHello {
    fn deser(raw: &[u8]) -> anyhow::Result<Self> {
        let identities = DataVec16::<PskIdentity>::deser(raw)?;
        let binders = DataVec16::<DataVec8<u8>>::deser(&raw[identities.size()..])?;

        Ok(Self {
            identities: identities.into_inner(),
            binders: binders
                .into_inner()
                .into_iter()
                .map(DataVec8::into_inner)
                .collect(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct PreSharedKeyExtensionServerHello {
    pub selected_identity: u16,
}

impl RawDeser for PreSharedKeyExtensionServerHello {
    fn deser(raw: &[u8]) -> anyhow::Result<Self> {
        let selected_identity = u16::from_be_bytes([raw[0], raw[1]]);

        Ok(Self { selected_identity })
    }
}
