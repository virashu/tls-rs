use anyhow::Result;

use crate::parse::RawDeser;

#[derive(Clone, Debug)]
pub struct ApplicationData {
    inner: Box<[u8]>,
}

impl std::fmt::Display for ApplicationData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.inner))
    }
}

impl RawDeser for ApplicationData {
    fn deser(raw: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: Box::from(raw),
        })
    }
}
