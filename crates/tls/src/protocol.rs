pub mod cipher_suite;
pub mod error;
pub mod hkdf;
pub(crate) mod parse;
pub mod record;
pub(crate) mod util;

pub const LEGACY_VERSION: u16 = 0x0303;
pub const LEGACY_VERSION_BYTES: &[u8] = &[0x03, 0x03];
