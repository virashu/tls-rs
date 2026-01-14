pub mod alert;
pub mod application_data;
pub mod change_cipher_spec;
pub mod handshake;

use alert::Alert;
use handshake::Handshake;

use anyhow::{Result, anyhow, ensure};
use utils::concat_dyn;

use crate::{
    LEGACY_VERSION_BYTES,
    parse::{RawDeser, RawSer},
    record::application_data::ApplicationData,
};

pub mod content_types {
    pub const INVALID: u8 = 0;
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const HANDSHAKE: u8 = 22;
    pub const APPLICATION_DATA: u8 = 23;
}

#[derive(Clone, Debug)]
pub enum TlsContent {
    Invalid,
    ChangeCipherSpec,
    Alert(Alert),
    Handshake(Handshake),
    ApplicationData(ApplicationData),
}

impl TlsContent {
    pub fn content_type(&self) -> u8 {
        match self {
            TlsContent::Invalid => content_types::INVALID,
            TlsContent::ChangeCipherSpec => content_types::CHANGE_CIPHER_SPEC,
            TlsContent::Alert(_) => content_types::ALERT,
            TlsContent::Handshake(_) => content_types::HANDSHAKE,
            TlsContent::ApplicationData(_) => content_types::APPLICATION_DATA,
        }
    }
}

impl RawSer for TlsContent {
    fn ser(&self) -> Box<[u8]> {
        match self {
            TlsContent::Invalid => todo!(),
            TlsContent::ChangeCipherSpec => todo!(),
            TlsContent::Alert(alert) => alert.ser(),
            TlsContent::Handshake(handshake) => handshake.ser(),
            TlsContent::ApplicationData(_) => todo!(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TlsPlaintext {
    length: u16,
    pub fragment: TlsContent,
}

impl RawSer for TlsPlaintext {
    fn ser(&self) -> Box<[u8]> {
        let mut res = Vec::<u8>::new();

        res.push(self.fragment.content_type());
        res.extend(LEGACY_VERSION_BYTES);
        res.extend(self.length.to_be_bytes());
        res.extend(self.fragment.ser());

        res.into_boxed_slice()
    }
}

impl TlsPlaintext {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let content_type = raw[0];
        let length = u16::from_be_bytes([raw[3], raw[4]]);

        let data = &raw[5..];

        let record = match content_type {
            content_types::INVALID => TlsContent::Invalid,
            content_types::CHANGE_CIPHER_SPEC => TlsContent::ChangeCipherSpec,
            content_types::ALERT => TlsContent::Alert(Alert::deser(data)?),
            content_types::HANDSHAKE => TlsContent::Handshake(Handshake::deser(data)?),
            content_types::APPLICATION_DATA => {
                TlsContent::ApplicationData(ApplicationData::deser(data)?)
            }

            _ => unimplemented!("{}", content_type),
        };

        Ok(Self {
            length,
            fragment: record,
        })
    }

    pub fn new_handshake(handshake: Handshake) -> Result<Self> {
        Ok(Self {
            length: handshake.ser().len().try_into()?,
            fragment: TlsContent::Handshake(handshake),
        })
    }

    pub fn to_raw(&self) -> Box<[u8]> {
        self.ser()
    }
}

#[derive(Clone, Debug)]
pub struct TlsCiphertext {
    // ContentType opaque_type = application_data; /* 23 */
    // ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
    length: u16,
    encrypted_record: Box<[u8]>,
}

impl TlsCiphertext {
    pub fn encrypt(plain: &TlsPlaintext, key: [u8; 32], nonce: [u8; 12]) -> Result<Self> {
        let content = plain.fragment.ser();
        let content_type = plain.fragment.content_type();
        let padding: Vec<u8> = vec![];
        let plaintext = concat_dyn!(content, [content_type], &padding);

        #[allow(clippy::cast_possible_truncation)]
        let plaintext_length = plain.length + padding.len() as u16 + 1;

        let length = plaintext_length + 16;

        let additional_data = concat_dyn!(
            [content_types::APPLICATION_DATA],
            LEGACY_VERSION_BYTES,
            length.to_be_bytes()
        );

        let (ciphertext, tag) =
            crypt::aead::aes_gcm::encrypt_aes_256_gcm(&key, &nonce, &plaintext, &additional_data)?;
        let encrypted_record = concat_dyn!(ciphertext, tag);

        Ok(Self {
            length,
            encrypted_record,
        })
    }

    pub fn decrypt(&self, key: [u8; 32], nonce: [u8; 12]) -> Result<TlsPlaintext> {
        let additional_data = concat_dyn!(
            [content_types::APPLICATION_DATA],
            LEGACY_VERSION_BYTES,
            self.length.to_be_bytes()
        );

        let (ciphertext, tag) = self
            .encrypted_record
            .split_at(self.encrypted_record.len() - 16);

        // AEAD-Decrypt(peer_write_key, nonce, additional_data, AEADEncrypted)

        let plaintext = crypt::aead::aes_gcm::decrypt_aes_256_gcm(
            &key,
            &nonce,
            ciphertext,
            &additional_data,
            tag,
        )?;

        let index = plaintext.iter().rposition(|x| *x != 0).ok_or(anyhow!(""))?;

        let content = &plaintext[..index];
        let content_type = plaintext[index];

        TlsPlaintext::from_raw(&concat_dyn!(
            [content_type],
            LEGACY_VERSION_BYTES,
            (content.len() as u16).to_be_bytes(),
            content
        ))
    }

    pub fn to_raw(&self) -> Box<[u8]> {
        self.ser()
    }

    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        Self::deser(raw)
    }

    pub fn from_encrypted(value: TlsPlaintext) -> Result<Self> {
        Self::deser(&value.to_raw())
    }
}

impl RawDeser for TlsCiphertext {
    fn deser(raw: &[u8]) -> Result<Self> {
        let opaque_type = raw[0];
        ensure!(opaque_type == content_types::APPLICATION_DATA);
        // let legacy_record_version = u16::from_be_bytes([raw[1], raw[2]]);

        let length = u16::from_be_bytes([raw[3], raw[4]]);
        let encrypted_record = Box::from(&raw[5..(5 + length as usize)]);

        Ok(Self {
            length,
            encrypted_record,
        })
    }
}

impl RawSer for TlsCiphertext {
    fn ser(&self) -> Box<[u8]> {
        concat_dyn!(
            [content_types::APPLICATION_DATA],
            LEGACY_VERSION_BYTES,
            self.length.to_be_bytes(),
            &self.encrypted_record
        )
    }
}
