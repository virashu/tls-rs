pub mod pkcs1;
pub mod pkcs8;
pub mod x509;

mod macros;

use num_bigint::BigUint;

pub mod object_identifiers {
    pub const PKCS_1: &[u32] = &[1, 2, 840, 113_549, 1, 1];

    pub const RSA_ENCRYPTION: &[u32] = &[1, 2, 840, 113_549, 1, 1, 1];

    pub const RSASSA_PSS: &[u32] = &[1, 2, 840, 113_549, 1, 1, 10];

    pub const MD2_WITH_RSA_ENCRYPTION: &[u32] = &[1, 2, 840, 113_549, 1, 1, 2];
    pub const MD5_WITH_RSA_ENCRYPTION: &[u32] = &[1, 2, 840, 113_549, 1, 1, 4];
    pub const SHA256_WITH_RSA_ENCRYPTION: &[u32] = &[1, 2, 840, 113_549, 1, 1, 11];
    pub const SHA384_WITH_RSA_ENCRYPTION: &[u32] = &[1, 2, 840, 113_549, 1, 1, 12];
    pub const SHA512_WITH_RSA_ENCRYPTION: &[u32] = &[1, 2, 840, 113_549, 1, 1, 13];
}

pub mod der_native_tags {
    // Primitive -- |00|0|xxxxx|
    pub const BOOLEAN: u32 = 0x01;
    pub const INTEGER: u32 = 0x02;
    pub const BIT_STRING: u32 = 0x03;
    pub const OCTET_STRING: u32 = 0x04;
    pub const NULL: u32 = 0x05;
    pub const OBJECT_IDENTIFIER: u32 = 0x06;
    pub const PRINTABLE_STRING: u32 = 0x13;
    pub const IA5_STRING: u32 = 0x16;
    pub const UTC_TIME: u32 = 0x17;
    pub const UTF8_STRING: u32 = 0x0C;

    // Concstructed -- |00|1|xxxxx|
    pub const SEQUENCE: u32 = 0x10;
    pub const SET: u32 = 0x11;
}

pub mod tag_classes {
    pub const NATIVE: u8 = 0;
    pub const APPLICATION: u8 = 1;
    pub const CONTEXT_SPECIFIC: u8 = 2;
    pub const PRIVATE: u8 = 3;
}

#[derive(Clone, Debug)]
pub struct Integer(pub BigUint);

#[derive(Clone, Debug)]
pub struct BitString(pub Box<[u8]>);

#[derive(Clone, Debug)]
pub struct OctetString(pub Box<[u8]>);

#[derive(Clone, Debug)]
pub struct ObjectIdentifier(pub Vec<u32>);

impl ObjectIdentifier {
    pub fn is(&self, id: &[u32]) -> bool {
        *self.0 == *id
    }
}

#[allow(clippy::cast_possible_truncation, reason = "expected behavior")]
fn encode_object_identifier_component(mut value: u32) -> Box<[u8]> {
    if value <= 0x7F {
        return Box::new([value as u8]);
    }

    let mut res_le = Vec::new();
    res_le.push(value as u8 & 0x7F);
    value >>= 7;

    while value != 0 {
        res_le.push(value as u8 & 0x7F | 0x80);
        value >>= 7;
    }

    res_le.reverse();
    res_le.into_boxed_slice()
}

fn decode_object_identifier_component(raw: &[u8]) -> u32 {
    let mut res = 0u32;

    for byte in raw {
        res <<= 7;
        res += u32::from(byte & 0x7F);
    }

    res
}

fn decode_object_identifier(raw: &[u8]) -> Box<[u32]> {
    let mut subs = raw.chunk_by(|x, _| x & 0x80 != 0);

    let mut res = Vec::new();

    {
        let first = decode_object_identifier_component(subs.next().unwrap());
        res.push(first / 40);
        res.push(first % 40);
    }

    for sub in subs {
        res.push(decode_object_identifier_component(sub));
    }

    res.into_boxed_slice()
}

pub struct Tag {
    pub tag_class: u8,
    pub is_constructed: bool,
    pub tag_type: u32,
}

impl Tag {
    pub fn parse(raw: &mut dyn Iterator<Item = u8>) -> Self {
        let tag = raw.next().unwrap();

        let tag_class = tag >> 6;
        let is_constructed = (tag >> 5) & 1 != 0;
        let mut tag_type = u32::from(tag & 0b11111);

        if tag_type == 0b11111 {
            let raw_type = raw.take_while(|x| x & 0x80 != 0).collect::<Box<[u8]>>();
            tag_type = decode_object_identifier_component(&raw_type);
        }

        Tag {
            tag_class,
            is_constructed,
            tag_type,
        }
    }
}

enum Length {
    Definite(usize),
    Indefinite,
}

impl Length {
    pub fn parse(raw: &mut dyn Iterator<Item = u8>) -> Self {
        let octet_1 = raw.next().unwrap();
        let is_short = (octet_1 >> 7) == 0;
        let data = octet_1 & 0b0111_1111;

        if is_short {
            return Self::Definite(data as usize);
        }

        if data == 0 {
            return Self::Indefinite;
        }

        assert!(data != 0x7f, "Reserved");

        if data > 4 {
            unimplemented!("Length in octets is too big");
        }
        let mut bytes = [0u8; 4];
        bytes[(4 - data as usize)..]
            .copy_from_slice(&raw.take(data as usize).collect::<Box<[u8]>>());
        let len = u32::from_be_bytes(bytes);

        Self::Definite(len as usize)
    }
}

#[derive(Debug)]
pub enum DataElement {
    EndOfContent,
    Boolean(bool),
    Integer(Integer),
    BitString(BitString),
    OctetString(OctetString),
    Null,
    ObjectIdentifier(ObjectIdentifier),
    ObjectDescriptor,
    External,
    Real(f32),
    Enumerated,
    Sequence(Box<[DataElement]>),
    Set(Box<[DataElement]>),
    PrintableString(Box<str>),
    IA5String(Box<str>),
    UTF8String(Box<str>),
    UtcTime(Box<str>),

    Other(Box<[DataElement]>),
}

impl DataElement {
    pub fn parse_der(raw: &mut dyn Iterator<Item = u8>) -> Self {
        let tag = Tag::parse(raw);

        let Length::Definite(len) = Length::parse(raw) else {
            unimplemented!()
        };

        match tag.tag_type {
            der_native_tags::INTEGER => Self::Integer(Integer(BigUint::from_bytes_be(
                &raw.take(len).collect::<Box<[u8]>>(),
            ))),

            der_native_tags::BIT_STRING => Self::BitString(BitString(raw.take(len).collect())),

            der_native_tags::OCTET_STRING => {
                Self::OctetString(OctetString(raw.take(len).collect()))
            }

            der_native_tags::NULL => Self::Null,

            der_native_tags::SEQUENCE => {
                let mut sub = raw.take(len).peekable();
                let mut elements = Vec::new();

                while sub.peek().is_some() {
                    elements.push(Self::parse_der(&mut sub));
                }

                Self::Sequence(elements.into_boxed_slice())
            }

            der_native_tags::SET => {
                let mut sub = raw.take(len).peekable();
                let mut elements = Vec::new();

                while sub.peek().is_some() {
                    elements.push(Self::parse_der(&mut sub));
                }

                Self::Set(elements.into_boxed_slice())
            }

            der_native_tags::PRINTABLE_STRING => {
                let bytes = raw.take(len).collect::<Box<[u8]>>();
                let string = String::from_utf8_lossy(&bytes);

                Self::PrintableString(Box::from(string))
            }

            der_native_tags::OBJECT_IDENTIFIER => {
                let bytes = raw.take(len).collect::<Box<[u8]>>();

                Self::ObjectIdentifier(ObjectIdentifier(decode_object_identifier(&bytes).to_vec()))
            }

            der_native_tags::IA5_STRING => {
                let bytes = raw.take(len).collect::<Box<[u8]>>();
                let string = String::from_utf8_lossy(&bytes);

                Self::IA5String(Box::from(string))
            }

            der_native_tags::UTF8_STRING => {
                let bytes = raw.take(len).collect::<Box<[u8]>>();
                let string = String::from_utf8_lossy(&bytes);

                Self::UTF8String(Box::from(string))
            }

            der_native_tags::UTC_TIME => {
                let bytes = raw.take(len).collect::<Box<[u8]>>();
                let string = String::from_utf8_lossy(&bytes);

                Self::UtcTime(Box::from(string))
            }

            _ => {
                if tag.tag_class == tag_classes::NATIVE {
                    unimplemented!(
                        "Native tag: 0x{:02x} ({})",
                        tag.tag_type,
                        tag.is_constructed
                    );
                } else if tag.is_constructed {
                    let mut sub = raw.take(len).peekable();
                    let mut elements = Vec::new();

                    while sub.peek().is_some() {
                        elements.push(Self::parse_der(&mut sub));
                    }

                    Self::Other(elements.into_boxed_slice())
                } else {
                    unimplemented!("0x{:02x}", tag.tag_type);
                }
            }
        }
    }
}

pub fn parse_der(raw: &[u8]) -> DataElement {
    let mut iter = raw.iter().copied();
    DataElement::parse_der(&mut iter)
}
