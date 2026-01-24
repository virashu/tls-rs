mod data_vec_16;
mod data_vec_24;
mod data_vec_8;

pub use data_vec_8::DataVec8;
pub use data_vec_16::DataVec16;
pub use data_vec_24::DataVec24;

// Primitive implementations
pub mod u16;
pub mod u8;

use anyhow::Result;

pub trait RawSize {
    fn size(&self) -> usize;
}

pub trait RawSer {
    fn ser(&self) -> Box<[u8]>;
}

pub trait RawDeser: Sized {
    fn deser(raw: &[u8]) -> Result<Self>;
}
