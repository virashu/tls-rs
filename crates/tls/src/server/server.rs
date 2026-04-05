use std::{fs, path::Path};

use anyhow::Result;
use asn1::{
    DataElement as Asn1DataElement,
    pkcs1::RsaPrivateKey,
    pkcs8::PrivateKeyInfo,
    x509::{Certificate as X509Certificate, TbsCertificate as X509TbsCertificate},
};
use crypt::rsa::{PrivateKey, PublicKey};

pub fn load_cert(path: impl AsRef<Path>) -> Result<X509TbsCertificate> {
    let encoded = fs::read(path)?;
    let data = Asn1DataElement::parse(&encoded);
    Ok(X509Certificate::from_data_element(&data)?.tbs_certificate)
}

pub fn load_rsa_keys(path: impl AsRef<Path>) -> Result<(PrivateKey, PublicKey)> {
    let encoded = std::fs::read(path)?;

    let data = Asn1DataElement::parse(&encoded);
    let private_key_info = PrivateKeyInfo::from_data_element(&data)?;

    let key_data = Asn1DataElement::parse(&private_key_info.private_key.0);
    let rsa_private_key = RsaPrivateKey::from_data_element(&key_data)?;

    Ok((
        PrivateKey {
            modulus: rsa_private_key.modulus.0.clone(),
            exponent: rsa_private_key.private_exponent.0.clone(),
        },
        PublicKey {
            modulus: rsa_private_key.modulus.0.clone(),
            exponent: rsa_private_key.public_exponent.0.clone(),
        },
    ))
}

pub struct Config {
    pub certificate: X509TbsCertificate,
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}
