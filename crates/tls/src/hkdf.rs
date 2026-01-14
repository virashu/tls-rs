use anyhow::Result;
use crypt::hash::Hasher;

pub use crypt::hkdf::{hkdf_expand, hkdf_extract};

pub fn hkdf_expand_label<H: Hasher, const L: usize>(
    secret: &[u8],
    label: impl AsRef<str>,
    context: &[u8],
) -> Result<[u8; L]> {
    let hkdf_label = &{
        let mut x = Vec::new();

        let length = TryInto::<u16>::try_into(L)?;
        x.extend(length.to_be_bytes());

        let label_length = TryInto::<u8>::try_into(label.as_ref().len())?;
        x.push(label_length + 6);
        x.extend(b"tls13 ");
        x.extend(label.as_ref().as_bytes());

        let context_length = TryInto::<u8>::try_into(context.len())?;
        x.push(context_length);
        x.extend(context);

        x.into_boxed_slice()
    };

    Ok(hkdf_expand::<H, L>(secret, hkdf_label))
}

// pub fn derive_secret<H: Hasher>(
//     secret: &[u8],
//     label: impl AsRef<str>,
//     messages: &[u8],
// ) -> Result<Box<[u8]>> {
//     let context = H::hash(messages);
//     let length = H::DIGEST_SIZE;

//     hkdf_expand_label::<H>(secret, label, &context, length)
// }
