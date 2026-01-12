pub mod sha;

pub trait Hasher {
    const BLOCK_SIZE: usize;
    const DIGEST_SIZE: usize;

    fn hash(value: &[u8]) -> Box<[u8]>;
}
