use anyhow::Ok;

use crate::protocol::{parse::RawDeser, util::opaque_vec_8};

#[derive(Clone, Debug)]
pub struct RenegotiationInfo {
    pub renegotiated_connection: Box<[u8]>,
}

impl RawDeser for RenegotiationInfo {
    fn deser(raw: &[u8]) -> anyhow::Result<Self> {
        let (_, renegotiated_connection) = opaque_vec_8(raw);

        Ok(Self {
            renegotiated_connection,
        })
    }
}
