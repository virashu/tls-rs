use anyhow::{Context, Result, bail};

use super::extension::{
    CertificateCompressionAlgorithms, EcPointFormats, KeyShareClientHello,
    PreSharedKeyExtensionClientHello, ProtocolNameList, PskKeyExchangeModes, RenegotiationInfo,
    ServerNameList, SignatureAlgorithms, StatusRequest, SupportedGroups,
    SupportedVersionsClientHello, extension_types,
};
use crate::{
    cipher_suite::CipherSuite,
    parse::{RawDeser, RawSize},
    util::{opaque_vec_8, opaque_vec_16},
};

#[cfg_attr(feature = "trace", derive(strum_macros::AsRefStr))]
#[derive(Clone, Debug)]
pub enum ClientHelloExtensionContent {
    /// ID: 0
    ServerName(ServerNameList),
    /// ID: 5
    StatusRequest(StatusRequest),
    /// ID: 10
    SupportedGroups(SupportedGroups),
    /// ID: 11
    EcPointFormats(EcPointFormats),
    /// ID: 13
    SignatureAlgorithms(SignatureAlgorithms),
    /// ID: 16
    ApplicationLayerProtocolNegotiation(ProtocolNameList),
    /// ID: 18
    SignedCertificateTimestamp,
    /// ID: 23
    ExtendedMainSecret,
    /// ID: 27
    CertificateCompressionAlgorithms(CertificateCompressionAlgorithms),
    /// ID: 28
    RecordSizeLimit(/* */),
    /// ID: 35
    SessionTicket(/* TODO */),
    /// ID: 41
    PreSharedKey(PreSharedKeyExtensionClientHello),
    /// ID: 43
    SupportedVersions(SupportedVersionsClientHello),
    /// ID: 45
    PskKeyExchangeModes(PskKeyExchangeModes),
    /// ID: 49
    PostHandshakeAuth,
    /// ID: 51
    KeyShare(KeyShareClientHello),
    // 65037
    /// ID: 65281
    RenegotiationInfo(RenegotiationInfo),
}

impl RawDeser for ClientHelloExtensionContent {
    fn deser(raw: &[u8]) -> Result<Self> {
        let extension_type = u16::from_be_bytes([raw[0], raw[1]]);
        let data = &raw[4..];

        Ok(match extension_type {
            extension_types::SERVER_NAME => {
                Self::ServerName(ServerNameList::deser(data).context("ServerName")?)
            }
            extension_types::STATUS_REQUEST => {
                Self::StatusRequest(StatusRequest::deser(data).context("StatusRequest")?)
            }
            extension_types::SUPPORTED_GROUPS => {
                Self::SupportedGroups(SupportedGroups::deser(data).context("SupportedGroups")?)
            }
            extension_types::EC_POINT_FORMATS => {
                Self::EcPointFormats(EcPointFormats::deser(data).context("EcPointFormats")?)
            }
            extension_types::SIGNATURE_ALGORITHMS => Self::SignatureAlgorithms(
                SignatureAlgorithms::deser(data).context("SignatureAlgorigthms")?,
            ),
            extension_types::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                Self::ApplicationLayerProtocolNegotiation(
                    ProtocolNameList::deser(data).context("ALPNegotiation")?,
                )
            }
            18 => Self::SignedCertificateTimestamp,
            extension_types::EXTENDED_MAIN_SECRET => Self::ExtendedMainSecret,
            extension_types::COMPRESS_CERTIFICATE => Self::CertificateCompressionAlgorithms(
                CertificateCompressionAlgorithms::deser(data)?,
            ),
            extension_types::SESSION_TICKET => Self::SessionTicket(),
            extension_types::PRE_SHARED_KEY => {
                Self::PreSharedKey(PreSharedKeyExtensionClientHello::deser(data)?)
            }
            extension_types::SUPPORTED_VERSIONS => {
                Self::SupportedVersions(SupportedVersionsClientHello::deser(data)?)
            }
            extension_types::PSK_KEY_EXCHANGE_MODES => {
                Self::PskKeyExchangeModes(PskKeyExchangeModes::deser(data)?)
            }
            extension_types::POST_HANDSHAKE_AUTH => Self::PostHandshakeAuth,
            extension_types::KEY_SHARE => Self::KeyShare(KeyShareClientHello::deser(data)?),
            extension_types::RENEGOTIATION_INFO => {
                Self::RenegotiationInfo(RenegotiationInfo::deser(data)?)
            }

            _ => bail!("Unknown extension type: {extension_type}"),
        })
    }
}

#[derive(Clone, Debug)]
pub struct ClientHelloExtension {
    length: u16,

    pub content: ClientHelloExtensionContent,
}

impl ClientHelloExtension {
    pub fn size_raw(raw: &[u8]) -> usize {
        u16::from_be_bytes([raw[2], raw[3]]) as usize + 4
    }
}

impl RawSize for ClientHelloExtension {
    fn size(&self) -> usize {
        self.length as usize + 4
    }
}

impl RawDeser for ClientHelloExtension {
    fn deser(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[2], raw[3]]);
        let content = ClientHelloExtensionContent::deser(raw)?;

        Ok(Self { length, content })
    }
}

#[derive(Clone, Debug)]
pub struct ClientHello {
    length: u32,

    pub random: Box<[u8; 32]>,
    pub legacy_session_id: Box<[u8]>,
    pub cipher_suites: Box<[CipherSuite]>,
    pub legacy_compression_methods: Box<[u8]>,
    pub extensions: Box<[ClientHelloExtension]>,
}

impl RawSize for ClientHello {
    fn size(&self) -> usize {
        self.length as usize + 3
    }
}

impl RawDeser for ClientHello {
    fn deser(raw: &[u8]) -> Result<Self> {
        let length = u32::from_be_bytes([0, raw[0], raw[1], raw[2]]);

        let legacy_version = u16::from_be_bytes([raw[3], raw[4]]);
        if legacy_version != 0x0303 {
            bail!("Invalid legacy version: {legacy_version} (should be equal 0x0303)");
        }

        let random = Box::new(raw[5..(5 + 32)].try_into()?);

        let mut offset: usize = 5 + 32;

        let (size, legacy_session_id) = opaque_vec_8(&raw[offset..]);
        offset += size;

        let (size, cipher_suites_raw) = opaque_vec_16(&raw[offset..]);
        offset += size;
        let cipher_suites = cipher_suites_raw
            .chunks(2)
            .map(|x| CipherSuite(u16::from_be_bytes([x[0], x[1]])))
            .collect();

        let (size, legacy_compression_methods) = opaque_vec_8(&raw[offset..]);
        offset += size;

        let (_, extensions_raw) = opaque_vec_16(&raw[offset..]);

        // Parse extensions
        let total_length = extensions_raw.len();
        let mut parsed_length = 0;
        let mut extensions = Vec::new();
        while parsed_length < total_length {
            match ClientHelloExtension::deser(&extensions_raw[parsed_length..]) {
                Ok(ext) => {
                    tracing::trace!(
                        "Parsed extension: {} ({} bytes body)",
                        ext.content.as_ref(),
                        ext.size() - 4
                    );
                    parsed_length += ext.size();
                    extensions.push(ext);
                }
                Err(err) => {
                    tracing::warn!("Failed to parse extension: {err:?}");
                    parsed_length +=
                        ClientHelloExtension::size_raw(&extensions_raw[parsed_length..]);
                }
            }
        }

        if parsed_length != total_length {
            tracing::error!("Unparsed extension parts left ({parsed_length}/{total_length})");
        }

        Ok(Self {
            length,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions: extensions.into_boxed_slice(),
        })
    }
}
