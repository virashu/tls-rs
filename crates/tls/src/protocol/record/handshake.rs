pub mod certificate;
pub mod certificate_request;
pub mod certificate_verify;
pub mod client_hello;
pub mod encrypted_extensions;
pub mod extension;
pub mod finished;
pub mod server_hello;

use certificate::Certificate;
use certificate_request::CertificateRequest;
use certificate_verify::CertificateVerify;
use client_hello::ClientHello;
use encrypted_extensions::EncryptedExtensions;
use finished::Finished;
use server_hello::ServerHello;

use anyhow::Result;

use crate::protocol::parse::{RawDeser, RawSer};

pub mod handshake_types {
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    pub const NEW_SESSION_TICKET: u8 = 4;
    pub const END_OF_EARLY_DATA: u8 = 5;
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    pub const CERTIFICATE: u8 = 11;
    pub const CERTIFICATE_REQUEST: u8 = 13;
    pub const CERTIFICATE_VERIFY: u8 = 15;
    pub const FINISHED: u8 = 20;
    pub const KEY_UPDATE: u8 = 24;
    pub const MESSAGE_HASH: u8 = 254;
}

#[derive(Clone, Debug)]
pub enum Handshake {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    EndOfEarlyData,
    EncryptedExtensions(EncryptedExtensions),
    CertificateRequest(CertificateRequest),
    Certificate(Certificate),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
    NewSessionTicket,
    KeyUpdate,

    MessageHash,
}

impl RawDeser for Handshake {
    fn deser(raw: &[u8]) -> Result<Self> {
        let msg_type = raw[0];
        let data = &raw[1..];
        let _length = u32::from_be_bytes([0, raw[1], raw[2], raw[3]]);

        Ok(match msg_type {
            handshake_types::CLIENT_HELLO => Self::ClientHello(ClientHello::deser(data)?),
            handshake_types::SERVER_HELLO => todo!(),
            handshake_types::NEW_SESSION_TICKET => Self::NewSessionTicket,
            handshake_types::END_OF_EARLY_DATA => Self::EndOfEarlyData,
            handshake_types::ENCRYPTED_EXTENSIONS => {
                Self::EncryptedExtensions(EncryptedExtensions::deser(data)?)
            }
            handshake_types::CERTIFICATE => Self::Certificate(Certificate::deser(data)?),
            handshake_types::CERTIFICATE_REQUEST => {
                Self::CertificateRequest(CertificateRequest::deser(data)?)
            }
            handshake_types::CERTIFICATE_VERIFY => {
                Self::CertificateVerify(CertificateVerify::deser(data)?)
            }
            handshake_types::FINISHED => Self::Finished(Finished::deser(data)?),
            handshake_types::KEY_UPDATE => Self::KeyUpdate,
            handshake_types::MESSAGE_HASH => Self::MessageHash,

            _ => todo!("{msg_type}"),
        })
    }
}

impl RawSer for Handshake {
    fn ser(&self) -> Box<[u8]> {
        match self {
            Self::ServerHello(s_h) => {
                let mut res = Vec::new();

                let raw = s_h.ser();
                let length = raw.len();
                let length_bytes = TryInto::<u32>::try_into(length)
                    .expect("ServerHello size exceeds maximum u32 value")
                    .to_be_bytes();

                res.push(handshake_types::SERVER_HELLO);
                res.extend(&length_bytes[1..=3]);
                res.extend(raw);

                res.into_boxed_slice()
            }

            Self::EncryptedExtensions(e_e) => {
                let mut res = Vec::new();

                let raw = e_e.ser();
                let length = raw.len();
                let length_bytes = TryInto::<u32>::try_into(length)
                    .expect("EncryptedExtensions size exceeds maximum u32 value")
                    .to_be_bytes();

                res.push(handshake_types::ENCRYPTED_EXTENSIONS);
                res.extend(&length_bytes[1..=3]);
                res.extend(raw);

                res.into_boxed_slice()
            }

            Self::CertificateRequest(c_r) => {
                let mut res = Vec::new();

                let raw = c_r.ser();
                let length = raw.len();
                let length_bytes = TryInto::<u32>::try_into(length)
                    .expect("CertificateRequest size exceeds maximum u32 value")
                    .to_be_bytes();

                res.push(handshake_types::CERTIFICATE_REQUEST);
                res.extend(&length_bytes[1..=3]);
                res.extend(raw);

                res.into_boxed_slice()
            }

            Self::Certificate(cert) => {
                let mut res = Vec::new();

                let raw = cert.ser();
                let length = raw.len();
                let length_bytes = TryInto::<u32>::try_into(length)
                    .expect("Certificate size exceeds maximum u32 value")
                    .to_be_bytes();

                res.push(handshake_types::CERTIFICATE);
                res.extend(&length_bytes[1..=3]);
                res.extend(raw);

                res.into_boxed_slice()
            }

            Self::CertificateVerify(cv) => {
                let mut res = Vec::new();

                let raw = cv.ser();
                let length = raw.len();
                let length_bytes = TryInto::<u32>::try_into(length)
                    .expect("CertificateVerify size exceeds maximum u32 value")
                    .to_be_bytes();

                res.push(handshake_types::CERTIFICATE_VERIFY);
                res.extend(&length_bytes[1..=3]);
                res.extend(raw);

                res.into_boxed_slice()
            }

            Self::Finished(fin) => {
                let mut res = Vec::new();

                let raw = fin.ser();
                let length = raw.len();
                let length_bytes = TryInto::<u32>::try_into(length)
                    .expect("Finished size exceeds maximum u32 value")
                    .to_be_bytes();

                res.push(handshake_types::FINISHED);
                res.extend(&length_bytes[1..=3]);
                res.extend(raw);

                res.into_boxed_slice()
            }
            _ => todo!("{:?}", self),
        }
    }
}
