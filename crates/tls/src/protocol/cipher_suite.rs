#[derive(Clone, Copy, Debug)]
pub struct CipherSuite(pub u16);

pub const TLS_AES_128_GCM_SHA256: CipherSuite = CipherSuite(0x13_01);
pub const TLS_AES_256_GCM_SHA384: CipherSuite = CipherSuite(0x13_02);
pub const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite(0x13_03);
