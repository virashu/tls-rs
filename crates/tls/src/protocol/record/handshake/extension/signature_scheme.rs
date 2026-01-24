use anyhow::Result;

use crate::{
    macros::auto_from,
    protocol::parse::{RawDeser, RawSer, RawSize},
};

auto_from! {
    #[repr(u16)]
    #[allow(non_camel_case_types)]
    #[derive(Clone, Copy, Debug)]
    pub enum SignatureScheme {
        /* RSASSA-PKCS1-v1_5 algorithms */
        rsa_pkcs1_sha256 = 0x0401,
        rsa_pkcs1_sha384 = 0x0501,
        rsa_pkcs1_sha512 = 0x0601,

        /* ECDSA algorithms */
        ecdsa_secp256r1_sha256 = 0x0403,
        ecdsa_secp384r1_sha384 = 0x0503,
        ecdsa_secp521r1_sha512 = 0x0603,

        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        rsa_pss_rsae_sha256 = 0x0804,
        rsa_pss_rsae_sha384 = 0x0805,
        rsa_pss_rsae_sha512 = 0x0806,

        /* EdDSA algorithms */
        ed25519 = 0x0807,
        ed448 = 0x0808,

        /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        rsa_pss_pss_sha256 = 0x0809,
        rsa_pss_pss_sha384 = 0x080a,
        rsa_pss_pss_sha512 = 0x080b,

        /* Legacy algorithms */
        rsa_pkcs1_sha1 = 0x0201,
        legacy_0x0202 = 0x0202,
        ecdsa_sha1 = 0x0203,
    }
}

impl RawSize for SignatureScheme {
    fn size(&self) -> usize {
        2
    }
}

impl RawDeser for SignatureScheme {
    fn deser(raw: &[u8]) -> Result<Self> {
        Ok(Self::from(u16::from_be_bytes([raw[0], raw[1]])))
    }
}

impl RawSer for SignatureScheme {
    fn ser(&self) -> Box<[u8]> {
        u16::from(self).ser()
    }
}
