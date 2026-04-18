use anyhow::{Result, ensure};
use utils::concat_dyn;

use super::mgf::generate_mask;
use crate::hash::Hasher;

fn xor_dyn(a: &[u8], b: &[u8]) -> Box<[u8]> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// <https://datatracker.ietf.org/doc/html/rfc8017#section-9.1.1>
pub fn emsa_pss_encode_fixed<H: Hasher>(salt: &[u8], message: &[u8], em_bits: usize) -> Box<[u8]> {
    let em_len = em_bits.div_ceil(8);

    let h_len = H::DIGEST_SIZE;
    let s_len = salt.len();

    let db_len = em_len - h_len - 1;
    let ps_len = db_len - s_len - 1;

    let msg_hash = H::hash(message); // mHash
    let msg_derived = concat_dyn![[0x00; 8], msg_hash, salt]; // M'
    let msg_derived_hash = H::hash(&msg_derived); // H
    let padding = [0x00].repeat(ps_len); // PS
    let db = concat_dyn![padding, [0x01], salt]; // DB
    let db_mask = generate_mask::<H>(&msg_derived_hash, db_len); // dbMask
    let masked_db = xor_dyn(&db, &db_mask); // maskedDB

    // EM
    concat_dyn![masked_db, msg_derived_hash, [0xbc]]
}

/// <https://datatracker.ietf.org/doc/html/rfc8017#section-9.1.1>
pub fn emsa_pss_encode<H: Hasher>(salt_len: usize, message: &[u8], em_bits: usize) -> Box<[u8]> {
    let salt = rand::random_iter().take(salt_len).collect::<Box<[u8]>>();
    emsa_pss_encode_fixed::<H>(&salt, message, em_bits)
}

/// <https://datatracker.ietf.org/doc/html/rfc8017#section-9.1.2>
pub fn emsa_pss_verify<H: Hasher>(
    salt_len: usize,
    message: &[u8],
    encoded_message: &[u8],
    em_bits: usize,
) -> Result<()> {
    let em_len = em_bits.div_ceil(8);

    let h_len = H::DIGEST_SIZE;
    let s_len = salt_len;

    ensure!(em_len >= h_len + s_len + 2, "Length is too small");

    let db_len = em_len - h_len - 1;
    let ps_len = db_len - s_len - 1;

    let msg_hash = H::hash(message); // mHash

    #[allow(clippy::unwrap_used, reason = "checked")]
    let (last_byte, encoded_message) = encoded_message.split_last().unwrap();

    ensure!(
        *last_byte == 0xbc,
        "Invalid last byte (expected: 0xBC, got: {last_byte:02X})"
    );

    let (masked_db, msg_derived_hash) = encoded_message.split_at(db_len);

    let db_mask = generate_mask::<H>(msg_derived_hash, db_len);
    let db = xor_dyn(masked_db, &db_mask);

    let padding = &db[..ps_len];
    ensure!(padding.iter().all(|x| *x == 0), "Wrong padding");

    let first_byte = db[ps_len];
    ensure!(first_byte == 0x01, "Invalid first byte");

    let salt = &db[(ps_len + 1)..];
    let msg_derived = concat_dyn![[0x00; 8], &msg_hash, salt];
    let msg_derived_hash_derived = H::hash(&msg_derived);

    ensure!(
        *msg_derived_hash == *msg_derived_hash_derived,
        "Hash mismatch"
    );

    Ok(())
}
