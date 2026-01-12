use anyhow::Result;

use crate::{DataElement, Integer, macros::try_extract};

pub struct RsaPrivateKey {
    pub version: Integer,
    pub modulus: Integer,
    pub public_exponent: Integer,
    pub private_exponent: Integer,
    pub prime1: Integer,
    pub prime2: Integer,
    pub exponent1: Integer,
    pub exponent2: Integer,
    pub coefficient: Integer,
}

impl RsaPrivateKey {
    pub fn from_data_element(value: &DataElement) -> Result<Self> {
        let main_seq = try_extract!(DataElement::Sequence, value)?;

        let version = try_extract!(DataElement::Integer, &main_seq[0])?.clone();
        let modulus = try_extract!(DataElement::Integer, &main_seq[1])?.clone();
        let public_exponent = try_extract!(DataElement::Integer, &main_seq[2])?.clone();
        let private_exponent = try_extract!(DataElement::Integer, &main_seq[3])?.clone();
        let prime1 = try_extract!(DataElement::Integer, &main_seq[4])?.clone();
        let prime2 = try_extract!(DataElement::Integer, &main_seq[5])?.clone();
        let exponent1 = try_extract!(DataElement::Integer, &main_seq[6])?.clone();
        let exponent2 = try_extract!(DataElement::Integer, &main_seq[7])?.clone();
        let coefficient = try_extract!(DataElement::Integer, &main_seq[8])?.clone();

        Ok(Self {
            version,
            modulus,
            public_exponent,
            private_exponent,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
        })
    }
}
