use anyhow::{Result, ensure};
use num_bigint::BigUint;
use utils::concat_dyn;

use crate::hash::Hasher;

fn xor_dyn(a: &[u8], b: &[u8]) -> Box<[u8]> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

pub struct PublicKey {
    /// RSA modulus (n)
    pub modulus: BigUint,
    /// Public exponent (e)
    pub exponent: BigUint,
}

pub struct PrivateKey {
    /// RSA modulus (n)
    pub modulus: BigUint,
    /// Private exponent (d)
    pub exponent: BigUint,
}

/// Integer to Octet string
/// <https://datatracker.ietf.org/doc/html/rfc8017#section-4.1>
fn int_to_octets(value: &BigUint, len: usize) -> Box<[u8]> {
    let octets = value.to_bytes_be();
    assert!(len >= octets.len());
    let mut v = vec![0; len - octets.len()];
    v.extend(octets);
    v.into_boxed_slice()
}

/// Octet string to Integer
/// <https://datatracker.ietf.org/doc/html/rfc8017#section-4.2>
fn octets_to_int(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// <https://datatracker.ietf.org/doc/html/rfc8017#section-5.1.1>
fn rsa_ep(key: &PublicKey, msg_repr: &BigUint) -> BigUint {
    msg_repr.modpow(&key.exponent, &key.modulus)
}

/// <https://datatracker.ietf.org/doc/html/rfc8017#section-5.1.2>
fn rsa_dp(key: &PrivateKey, msg_repr: &BigUint) -> BigUint {
    msg_repr.modpow(&key.exponent, &key.modulus)
}

/// <https://datatracker.ietf.org/doc/html/rfc8017#section-5.2.1>
fn rsa_sp1(key: &PrivateKey, msg_repr: &BigUint) -> BigUint {
    msg_repr.modpow(&key.exponent, &key.modulus)
}

/// <https://datatracker.ietf.org/doc/html/rfc8017#section-5.2.2>
fn rsa_vp1(key: &PublicKey, sgn_repr: &BigUint) -> BigUint {
    assert!(*sgn_repr < key.modulus);
    sgn_repr.modpow(&key.exponent, &key.modulus)
}

/// MGF1
/// <https://datatracker.ietf.org/doc/html/rfc8017#appendix-B.2.1>
fn generate_mask<H: Hasher>(seed: &[u8], len: usize) -> Box<[u8]> {
    let mut t = Vec::new();

    for i in 0..len.div_ceil(H::DIGEST_SIZE) {
        let counter = (i as u32).to_be_bytes();
        let hash = H::hash(&{
            let mut acc = Vec::new();
            acc.extend(seed);
            acc.extend(counter);
            acc
        });
        t.extend(hash);
    }

    t.into_iter().take(len).collect()
}

fn emsa_pss_encode_fixed<H: Hasher>(salt: &[u8], message: &[u8], em_bits: usize) -> Box<[u8]> {
    let em_len = em_bits.div_ceil(8);
    let h_len = H::DIGEST_SIZE;

    let msg_hash = H::hash(message); // mHash
    let msg_derived = concat_dyn![[0u8; 8], msg_hash, salt]; // M'
    let msg_derived_hash = H::hash(&msg_derived); // H
    let padding = [0u8].repeat(em_len - salt.len() - h_len - 2); // PS
    let db = concat_dyn![padding, [0x01], salt]; // DB
    let db_mask = generate_mask::<H>(&msg_derived_hash, em_len - h_len - 1); // dbMask
    let masked_db = xor_dyn(&db, &db_mask); // maskedDB

    // EM
    concat_dyn!(masked_db, msg_derived_hash, [0xbc])
}

fn emsa_pss_encode<H: Hasher>(salt_len: usize, message: &[u8], bits: usize) -> Box<[u8]> {
    let salt = rand::random_iter().take(salt_len).collect::<Box<[u8]>>();
    emsa_pss_encode_fixed::<H>(&salt, message, bits)
}

fn emsa_pss_verify<H: Hasher>(
    salt_len: usize,
    message: &[u8],
    encoded_message: &[u8],
    em_bits: usize,
) -> Result<()> {
    let em_len = em_bits.div_ceil(8);
    let h_len = H::DIGEST_SIZE;

    let msg_hash = H::hash(message); // mHash

    ensure!(em_len >= h_len + salt_len + 2, "Length is too small");

    #[allow(clippy::unwrap_used, reason = "checked")]
    let (last_byte, encoded_message) = encoded_message.split_last().unwrap();

    ensure!(*last_byte == 0xBC, "Invalid last byte");

    let (masked_db, msg_derived_hash) = encoded_message.split_at(em_len - h_len - 1);

    let db_mask = generate_mask::<H>(msg_derived_hash, em_len - h_len - 1);
    let db = xor_dyn(masked_db, &db_mask);

    let padding = &db[..(em_len - salt_len - h_len - 2)];
    ensure!(padding.iter().all(|x| *x == 0), "Wrong padding");

    let first_byte = db[db.len() - salt_len - 1];
    ensure!(first_byte == 0x01, "Invalid first byte");

    let salt = &db[(db.len() - salt_len)..];
    let msg_derived = concat_dyn![[0u8; 8], &msg_hash, salt];
    let msg_derived_hash_derived = H::hash(&msg_derived);

    ensure!(
        *msg_derived_hash == *msg_derived_hash_derived,
        "Hash mismatch"
    );

    Ok(())
}

#[allow(clippy::let_and_return)]
pub fn rsassa_pss_sign_fixed<H: Hasher>(
    salt: &[u8],
    key: &PrivateKey,
    message: &[u8],
) -> Box<[u8]> {
    #[allow(clippy::cast_possible_truncation)]
    let mod_bits = key.modulus.bits() as usize;
    let mod_len = mod_bits.div_ceil(8);

    let encoded_message = emsa_pss_encode_fixed::<H>(salt, message, mod_bits - 1);
    let msg_repr = octets_to_int(&encoded_message);
    let sgn_repr = rsa_sp1(key, &msg_repr);
    let signature = int_to_octets(&sgn_repr, mod_len);

    signature
}

/// <https://datatracker.ietf.org/doc/html/rfc8017#section-8.1.1>
#[allow(clippy::let_and_return)]
pub fn rsassa_pss_sign<H: Hasher, const SALT_LEN: usize>(
    key: &PrivateKey,
    message: &[u8],
) -> Box<[u8]> {
    #[allow(clippy::cast_possible_truncation)]
    let mod_bits = key.modulus.bits() as usize;
    let mod_len = mod_bits.div_ceil(8);

    let encoded_message = emsa_pss_encode::<H>(SALT_LEN, message, mod_bits - 1);
    let msg_repr = octets_to_int(&encoded_message);
    let sgn_repr = rsa_sp1(key, &msg_repr);
    let signature = int_to_octets(&sgn_repr, mod_len);

    signature
}

pub fn rsassa_pss_verify<H: Hasher, const SALT_LEN: usize>(
    key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    #[allow(clippy::cast_possible_truncation)]
    let mod_bits = key.modulus.bits() as usize;

    let sgn_repr = octets_to_int(signature);
    let msg_repr = rsa_vp1(key, &sgn_repr);
    let em_len = (mod_bits - 1).div_ceil(8);
    let encoded_message = int_to_octets(&msg_repr, em_len);

    emsa_pss_verify::<H>(SALT_LEN, message, &encoded_message, mod_bits - 1)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::hash::sha::Sha256;

    use super::*;

    #[test]
    fn test_sign_testcase_1() {
        let key = PrivateKey {
            modulus: BigUint::from_bytes_be(&hex!(
                "c5062b58d8539c765e1e5dbaf14cf75dd56c2e13105fecfd1a930bbb5948ff328f126abe779359ca59bca752c308d281573bc6178b6c0fef7dc445e4f826430437b9f9d790581de5749c2cb9cb26d42b2fee15b6b26f09c99670336423b86bc5bec71113157be2d944d7ff3eebffb28413143ea36755db0ae62ff5b724eecb3d316b6bac67e89cacd8171937e2ab19bd353a89acea8c36f81c89a620d5fd2effea896601c7f9daca7f033f635a3a943331d1b1b4f5288790b53af352f1121ca1bef205f40dc012c412b40bdd27585b946466d75f7ee0a7f9d549b4bece6f43ac3ee65fe7fd37123359d9f1a850ad450aaf5c94eb11dea3fc0fc6e9856b1805ef"
            )),
            exponent: BigUint::from_bytes_be(&hex!(
                "49e5786bb4d332f94586327bde088875379b75d128488f08e574ab4715302a87eea52d4c4a23d8b97af7944804337c5f55e16ba9ffafc0c9fd9b88eca443f39b7967170ddb8ce7ddb93c6087c8066c4a95538a441b9dc80dc9f7810054fd1e5c9d0250c978bb2d748abe1e9465d71a8165d3126dce5db2adacc003e9062ba37a54b63e5f49a4eafebd7e4bf5b0a796c2b3a950fa09c798d3fa3e86c4b62c33ba9365eda054e5fe74a41f21b595026acf1093c90a8c71722f91af1ed29a41a2449a320fc7ba3120e3e8c3e4240c04925cc698ecd66c7c906bdf240adad972b4dff4869d400b5d13e33eeba38e075e872b0ed3e91cc9c283867a4ffc3901d2069f"
            )),
        };
        let message = hex!(
            "dfc22604b95d15328059745c6c98eb9dfb347cf9f170aff19deeec555f22285a6706c4ecbf0fb1458c60d9bf913fbae6f4c554d245d946b4bc5f34aec2ac6be8b33dc8e0e3a9d601dfd53678f5674443f67df78a3a9e0933e5f158b169ac8d1c4cd0fb872c14ca8e001e542ea0f9cfda88c42dcad8a74097a00c22055b0bd41f"
        );
        let salt = hex!("e1256fc1eeef81773fdd54657e4007fde6bcb9b1");
        let expected = hex!(
            "8b46f2c889d819f860af0a6c4c889e4d1436c6ca174464d22ae11b9ccc265d743c67e569accbc5a80d4dd5f1bf4039e23de52aece40291c75f8936c58c9a2f77a780bbe7ad31eb76742f7b2b8b14ca1a7196af7e673a3cfc237d50f615b75cf4a7ea78a948bedaf9242494b41e1db51f437f15fd2551bb5d24eefb1c3e60f03694d0033a1e0a9b9f5e4ab97d457dff9b9da516dc226d6d6529500308ed74a2e6d9f3c10595788a52a1bc0664aedf33efc8badd037eb7b880772bdb04a6046e9edeee4197c25507fb0f11ab1c9f63f53c8820ea8405cfd7721692475b4d72355fa9a3804f29e6b6a7b059c4441d54b28e4eed2529c6103b5432c71332ce742bcc"
        );

        let signature = rsassa_pss_sign_fixed::<Sha256>(&salt, &key, &message);

        assert_eq!(*signature, expected);
    }

    #[test]
    fn test_sign_verify() {
        let modulus = BigUint::from_bytes_be(&hex!(
            "bcb47b2e0dafcba81ff2a2b5cb115ca7e757184c9d72bcdcda707a146b3b4e29
             989ddc660bd694865b932b71ca24a335cf4d339c719183e6222e4c9ea6875acd
             528a49ba21863fe08147c3a47e41990b51a03f77d22137f8d74c43a5a45f4e9e
             18a2d15db051dc89385db9cf8374b63a8cc88113710e6d8179075b7dc79ee76b"
        ));
        let public_exponent = BigUint::from_bytes_be(&hex!(
            "0000000000000000000000000000000000000000000000000000000000000000
             0000000000000000000000000000000000000000000000000000000000000000
             0000000000000000000000000000000000000000000000000000000000000000
             0000000000000000000000000000000000000000000000000000000000010001"
        ));
        let private_exponent = BigUint::from_bytes_be(&hex!(
            "383a6f19e1ea27fd08c7fbc3bfa684bd6329888c0bbe4c98625e7181f411cfd0
             853144a3039404dda41bce2e31d588ec57c0e148146f0fa65b39008ba5835f82
             9ba35ae2f155d61b8a12581b99c927fd2f22252c5e73cba4a610db3973e019ee
             0f95130d4319ed413432f2e5e20d5215cdd27c2164206b3f80edee51938a25c1"
        ));

        let message = hex!(
            "1248f62a4389f42f7b4bb131053d6c88a994db2075b912ccbe3ea7dc611714f1
             4e075c104858f2f6e6cfd6abdedf015a821d03608bf4eba3169a6725ec422cd9
             069498b5515a9608ae7cc30e3d2ecfc1db6825f3e996ce9a5092926bc1cf61aa
             42d7f240e6f7aa0edb38bf81aa929d66bb5d890018088458720d72d569247b0c"
        );

        let signature = rsassa_pss_sign::<Sha256, 32>(
            &PrivateKey {
                modulus: modulus.clone(),
                exponent: private_exponent,
            },
            &message,
        );
        assert!(
            rsassa_pss_verify::<Sha256, 32>(
                &PublicKey {
                    modulus: modulus.clone(),
                    exponent: public_exponent.clone(),
                },
                &message,
                &signature,
            )
            .is_ok()
        );
        assert!(
            rsassa_pss_verify::<Sha256, 32>(
                &PublicKey {
                    modulus,
                    exponent: public_exponent,
                },
                &message,
                b"JHjklhasJGADSGLKJASDdkjhasD",
            )
            .is_err()
        );
    }
}
