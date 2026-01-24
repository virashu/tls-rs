use anyhow::Result;

use super::named_group::NamedGroup;
use crate::protocol::parse::{DataVec16, RawDeser};

#[derive(Clone, Debug)]
pub struct SupportedGroups {
    pub named_group_list: Box<[NamedGroup]>,
}

impl RawDeser for SupportedGroups {
    fn deser(raw: &[u8]) -> Result<Self> {
        let named_group_list = DataVec16::<NamedGroup>::deser(raw)?.into_inner();

        Ok(Self { named_group_list })
    }
}
