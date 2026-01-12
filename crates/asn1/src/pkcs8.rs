use anyhow::Result;

use crate::{DataElement, Integer, ObjectIdentifier, OctetString, macros::try_extract};

pub struct PrivateKeyInfo {
    pub version: Integer,
    pub algorithm: ObjectIdentifier,
    pub private_key: OctetString,
}

impl PrivateKeyInfo {
    pub fn from_data_element(value: &DataElement) -> Result<Self> {
        dbg!(value);
        let main_seq = try_extract!(DataElement::Sequence, value)?;

        let version = try_extract!(DataElement::Integer, &main_seq[0])?.clone();

        let seq_algo = try_extract!(DataElement::Sequence, &main_seq[1])?;
        let algorithm = try_extract!(DataElement::ObjectIdentifier, &seq_algo[0])?.clone();

        let private_key = try_extract!(DataElement::OctetString, &main_seq[2])?.clone();

        Ok(Self {
            version,
            algorithm,
            private_key,
        })
    }
}
