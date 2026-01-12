use anyhow::Result;

use crate::{BitString, DataElement, Integer, ObjectIdentifier, macros::try_extract};

pub struct Certificate {
    pub tbs_certificate: TbsCertificate,
    pub signature_algorithm: ObjectIdentifier,
    pub signature_value: BitString,
}

impl Certificate {
    pub fn from_data_element(value: &DataElement) -> Result<Self> {
        let main_seq = try_extract!(DataElement::Sequence, value)?;

        let tbs_certificate = TbsCertificate::from_data_element(&main_seq[0])?;

        let seq_algo = try_extract!(DataElement::Sequence, &main_seq[1])?;
        let signature_algorithm =
            try_extract!(DataElement::ObjectIdentifier, &seq_algo[0])?.clone();

        let signature_value = try_extract!(DataElement::BitString, &main_seq[2])?.clone();

        Ok(Self {
            tbs_certificate,
            signature_algorithm,
            signature_value,
        })
    }
}

pub struct TbsCertificate {
    pub version: Integer,
    pub serial_number: Integer,
    pub signature_algorithm: ObjectIdentifier,
}

impl TbsCertificate {
    pub fn from_data_element(value: &DataElement) -> Result<Self> {
        let main_seq = try_extract!(DataElement::Sequence, value)?;

        let seq_ver = try_extract!(DataElement::Other, &main_seq[0])?;
        let version = try_extract!(DataElement::Integer, &seq_ver[0])?.clone();

        let serial_number = try_extract!(DataElement::Integer, &main_seq[1])?.clone();

        let seq_algo = try_extract!(DataElement::Sequence, &main_seq[2])?;
        let signature_algorithm =
            try_extract!(DataElement::ObjectIdentifier, &seq_algo[0])?.clone();

        Ok(Self {
            version,
            serial_number,
            signature_algorithm,
        })
    }
}
