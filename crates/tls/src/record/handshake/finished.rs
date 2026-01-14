use crate::parse::{RawDeser, RawSer};

#[derive(Clone, Debug)]
pub struct Finished {
    pub verify_data: Box<[u8]>,
}

impl RawSer for Finished {
    fn ser(&self) -> Box<[u8]> {
        self.verify_data.clone()
    }
}

impl RawDeser for Finished {
    fn deser(raw: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            verify_data: Box::from(raw),
        })
    }
}
