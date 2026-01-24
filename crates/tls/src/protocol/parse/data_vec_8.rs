use anyhow::Result;

use super::{RawDeser, RawSer, RawSize};

#[derive(Clone, Debug)]
pub struct DataVec8<T> {
    length: u8,
    inner: Box<[T]>,
}

impl<T> DataVec8<T> {
    pub fn new() -> Self {
        Self {
            length: 0,
            inner: Box::new([]),
        }
    }

    pub fn into_inner(self) -> Box<[T]> {
        self.inner
    }
}

impl<T> TryFrom<&[T]> for DataVec8<T>
where
    T: RawSize + Clone,
{
    type Error = anyhow::Error;

    fn try_from(value: &[T]) -> Result<Self, Self::Error> {
        let length: usize = value.iter().map(RawSize::size).sum();
        let length: u8 = length.try_into()?;

        Ok(Self {
            length,
            inner: Box::from(value),
        })
    }
}

impl<T> RawSize for DataVec8<T> {
    fn size(&self) -> usize {
        self.length as usize + 1
    }
}

impl<T> RawDeser for DataVec8<T>
where
    T: RawSize + RawDeser,
{
    fn deser(raw: &[u8]) -> Result<Self> {
        let length = raw[0];
        let payload = &raw[1..];

        let mut res = Vec::new();
        let mut offset: usize = 0;
        while offset < length as usize {
            let el = T::deser(&payload[offset..])?;
            offset += el.size();
            res.push(el);
        }

        Ok(Self {
            length,
            inner: res.into_boxed_slice(),
        })
    }
}

impl<T> RawSer for DataVec8<T>
where
    T: RawSer,
{
    fn ser(&self) -> Box<[u8]> {
        let mut res = Vec::new();

        res.extend(self.length.to_be_bytes());

        for elem in &self.inner {
            res.extend(elem.ser());
        }

        res.into_boxed_slice()
    }
}
