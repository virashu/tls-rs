//! <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>

use anyhow::{Result, ensure};

use crate::block_cipher::BlockCipher;

fn xor(mut a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    for i in 0..16 {
        a[i] ^= b[i];
    }
    a
}

fn xor_dyn(a: &[u8], b: &[u8]) -> Result<Box<[u8]>> {
    ensure!(a.len() == b.len(), "Len is not equal");

    Ok(a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect())
}

fn mul(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    const R: u128 = 0xE1 << 120;

    let x = u128::from_be_bytes(x);

    let mut product = 0u128;
    let mut v = u128::from_be_bytes(y);

    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 {
            product ^= v;
        }

        let lsb = v & 1 == 1;
        v >>= 1;
        if lsb {
            v ^= R;
        }
    }

    product.to_be_bytes()
}

fn inc<const N: usize>(y: [u8; N]) -> [u8; N] {
    let a0: [u8; 4] = y[(y.len() - 4)..].try_into().unwrap();
    let a1 = u32::from_be_bytes(a0).wrapping_add(1);

    let mut res = Vec::new();
    res.extend(&y[..(y.len() - 4)]);
    res.extend(a1.to_be_bytes());

    res.as_slice().try_into().unwrap()
}

fn ghash(hash_key: &[u8; 16], value: &[u8]) -> Result<[u8; 16]> {
    ensure!(value.len() % 16 == 0);

    let mut hash = [0; 16];

    for block in value.as_chunks().0 {
        let xor_res = xor(hash, *block);
        hash = mul(xor_res, *hash_key);
    }

    Ok(hash)
}

/// Encrypt `input` with `block_cipher`
/// using `initial_counter` as a starting value for counter
fn gctr(
    block_cipher: &dyn BlockCipher,
    initial_counter: [u8; 16],
    input: &[u8],
) -> Result<Box<[u8]>> {
    if input.is_empty() {
        return Ok(Box::new([]));
    }

    let mut counter = initial_counter;
    let (blocks, remainder) = input.as_chunks::<16>();
    let mut ciphertext: Vec<u8> = Vec::new();

    for block_i in blocks {
        let key_i: [u8; 16] = (*block_cipher.encrypt(&counter)).try_into()?;

        let ciphertext_i = xor(*block_i, key_i);
        ciphertext.extend(ciphertext_i);
        counter = inc(counter);
    }

    let key_n: [u8; 16] = (*block_cipher.encrypt(&counter)).try_into()?;
    let block_n = remainder;
    let ciphertext_n = xor_dyn(block_n, &key_n[..(block_n.len())])?;
    ciphertext.extend(ciphertext_n);

    Ok(ciphertext.into_boxed_slice())
}

type Ciphertext = Box<[u8]>;
type Tag = Box<[u8]>;

fn ghash_tag(hash_key: &[u8; 16], additional_data: &[u8], ciphertext: &[u8]) -> Result<[u8; 16]> {
    let tag_block_input = {
        let u = 16 * ciphertext.len().div_ceil(16) - ciphertext.len();
        let v = 16 * additional_data.len().div_ceil(16) - additional_data.len();

        let mut acc = Vec::new();

        acc.extend(additional_data);
        acc.extend([0u8].repeat(v));

        acc.extend(ciphertext);
        acc.extend([0u8].repeat(u));

        acc.extend(((additional_data.len() * 8) as u64).to_be_bytes());
        acc.extend(((ciphertext.len() * 8) as u64).to_be_bytes());

        acc
    };

    ghash(hash_key, &tag_block_input)
}

fn get_counter(hash_key: &[u8; 16], iv: &[u8]) -> Result<[u8; 16]> {
    if iv.len() == 12 {
        let mut acc = [0; 16];
        acc[0..12].copy_from_slice(iv);
        acc[12..16].copy_from_slice(&1u32.to_be_bytes());
        Ok(acc)
    } else {
        let mut acc = Vec::new();
        let s = 16 * iv.len().div_ceil(16) - iv.len();
        acc.extend(iv);
        acc.extend([0].repeat(s + 8));
        acc.extend((iv.len() as u64).to_be_bytes());
        ghash(hash_key, &acc)
    }
}

#[allow(clippy::missing_errors_doc)]
pub fn encrypt(
    block_cipher: &dyn BlockCipher,
    iv: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<(Ciphertext, Tag)> {
    let hash_key: [u8; 16] = (*block_cipher.encrypt(&[0; 16])).try_into()?;
    let counter_initial = get_counter(&hash_key, iv)?;

    let ciphertext = gctr(block_cipher, inc(counter_initial), plaintext)?;

    let tag_block = ghash_tag(&hash_key, additional_data, &ciphertext)?;
    let tag = gctr(block_cipher, counter_initial, &tag_block)?;

    Ok((ciphertext, tag))
}

#[allow(clippy::missing_errors_doc)]
pub fn decrypt(
    block_cipher: &dyn BlockCipher,
    iv: &[u8],
    ciphertext: &[u8],
    additional_data: &[u8],
    tag: &[u8],
) -> Result<Box<[u8]>> {
    let hash_key: [u8; 16] = (*block_cipher.encrypt(&[0; 16])).try_into()?;
    let counter_initial = get_counter(&hash_key, iv)?;

    let plaintext = gctr(block_cipher, inc(counter_initial), ciphertext)?;

    let tag_block = ghash_tag(&hash_key, additional_data, ciphertext)?;
    let tag_check = gctr(block_cipher, counter_initial, &tag_block)?;

    ensure!(*tag == *tag_check, "Tag does not match");

    Ok(plaintext)
}
