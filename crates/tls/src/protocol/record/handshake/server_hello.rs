use anyhow::Result;

use super::extension::{
    KeyShareEntry,
    KeyShareServerHello,
    PreSharedKeyExtensionServerHello,
    SupportedVersionsServerHello,
    extension_types,
};
use crate::protocol::{
    cipher_suite::CipherSuite,
    parse::{DataVec16, RawDeser, RawSer, RawSize},
    record::handshake::extension::{ProtocolName, ProtocolNameList},
};

#[derive(Clone, Debug)]
pub enum ServerHelloExtensionContent {
    /// ID: 16
    ApplicationLevelProtocolNegotiation(ProtocolNameList),
    /// ID: 23
    ExtendedMainSecret,
    /// ID: 41
    PreSharedKey(PreSharedKeyExtensionServerHello),
    /// ID: 43
    SupportedVersions(SupportedVersionsServerHello),
    /// ID: 51
    KeyShare(KeyShareServerHello),
}

#[derive(Clone, Debug)]
pub struct ServerHelloExtension {
    length: u16,

    pub content: ServerHelloExtensionContent,
}

impl ServerHelloExtension {
    pub fn new_extended_main_secret() -> Self {
        Self {
            length: 0,
            content: ServerHelloExtensionContent::ExtendedMainSecret,
        }
    }

    pub fn new_pre_shared_key(selected_identity: u16) -> Self {
        Self {
            length: 2,
            content: ServerHelloExtensionContent::PreSharedKey(PreSharedKeyExtensionServerHello {
                selected_identity,
            }),
        }
    }

    pub fn new_supported_versions(version: u16) -> Self {
        Self {
            length: 2,
            content: ServerHelloExtensionContent::SupportedVersions(SupportedVersionsServerHello {
                selected_version: version,
            }),
        }
    }

    pub fn new_key_share(share: KeyShareEntry) -> Result<Self> {
        Ok(Self {
            length: share.size().try_into()?,
            content: ServerHelloExtensionContent::KeyShare(KeyShareServerHello {
                server_share: share,
            }),
        })
    }

    pub fn new_alpn(protocol: &[u8]) -> Result<Self> {
        let ext = ProtocolNameList {
            protocol_name_list: DataVec16::try_from(&[ProtocolName::new(protocol)?][..])?,
        };
        Ok(Self {
            length: ext.ser().len() as u16,
            content: ServerHelloExtensionContent::ApplicationLevelProtocolNegotiation(ext),
        })
    }

    pub fn length(&self) -> u16 {
        self.length
    }
}

impl RawSize for ServerHelloExtension {
    fn size(&self) -> usize {
        self.length as usize + 4
    }
}

impl RawSer for ServerHelloExtension {
    fn ser(&self) -> Box<[u8]> {
        match &self.content {
            ServerHelloExtensionContent::ExtendedMainSecret => {
                [extension_types::EXTENDED_MAIN_SECRET.to_be_bytes(), [0, 0]]
                    .concat()
                    .into()
            }
            ServerHelloExtensionContent::PreSharedKey(e) => [
                extension_types::PRE_SHARED_KEY.to_be_bytes(),
                self.length.to_be_bytes(),
                e.selected_identity.to_be_bytes(),
            ]
            .concat()
            .into(),
            ServerHelloExtensionContent::SupportedVersions(e) => [
                extension_types::SUPPORTED_VERSIONS.to_be_bytes(),
                self.length.to_be_bytes(),
                e.selected_version.to_be_bytes(),
            ]
            .concat()
            .into(),
            ServerHelloExtensionContent::KeyShare(e) => {
                let mut res = Vec::new();

                res.extend(extension_types::KEY_SHARE.to_be_bytes());
                res.extend(self.length.to_be_bytes());
                res.extend(e.server_share.ser());

                res.into_boxed_slice()
            }
            ServerHelloExtensionContent::ApplicationLevelProtocolNegotiation(e) => {
                let mut res = Vec::new();

                res.extend(extension_types::APPLICATION_LAYER_PROTOCOL_NEGOTIATION.to_be_bytes());
                res.extend(self.length.to_be_bytes());
                res.extend(e.protocol_name_list.ser());

                res.into_boxed_slice()
            }
        }
    }
}

impl RawDeser for ServerHelloExtension {
    fn deser(raw: &[u8]) -> Result<Self> {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct ServerHello {
    pub random: Box<[u8; 32]>,
    pub legacy_session_id_echo: Box<[u8]>,
    pub cipher_suite: CipherSuite,
    pub extensions: Box<[ServerHelloExtension]>,
}

impl ServerHello {
    pub fn new(
        random: &[u8; 32],
        legacy_session_id_echo: &[u8],
        cipher_suite: CipherSuite,
        extensions: &[ServerHelloExtension],
    ) -> Self {
        Self {
            random: Box::from(*random),
            legacy_session_id_echo: Box::from(legacy_session_id_echo),
            cipher_suite,
            extensions: Box::from(extensions.to_owned()),
        }
    }
}

impl RawSer for ServerHello {
    #[allow(clippy::cast_possible_truncation)]
    fn ser(&self) -> Box<[u8]> {
        let mut res = Vec::new();

        res.extend([0x03, 0x03]);

        res.extend(self.random.as_ref());

        res.push(self.legacy_session_id_echo.len() as u8);
        res.extend(self.legacy_session_id_echo.as_ref());

        res.extend(self.cipher_suite.0.to_be_bytes());

        res.push(0);

        let extensions_length = self.extensions.iter().fold(0, |acc, e| acc + e.size()) as u16;
        res.extend(extensions_length.to_be_bytes());
        res.extend(self.extensions.iter().flat_map(ServerHelloExtension::ser));

        res.into_boxed_slice()
    }
}
