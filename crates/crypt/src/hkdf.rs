use crate::{hash::Hasher, hmac::hmac_hash};

pub fn hkdf_extract<H: Hasher>(salt: &[u8], ikm: &[u8]) -> Box<[u8]> {
    hmac_hash::<H>(salt, ikm)
}

pub fn hkdf_expand<H: Hasher, const L: usize>(prk: &[u8], info: &[u8]) -> [u8; L] {
    let n = L.div_ceil(H::DIGEST_SIZE);
    let mut t: Vec<Box<[u8]>> = Vec::from([Box::from(&[] as &[u8])]);

    for i in 1..=n {
        let concatd = {
            let mut x = Vec::new();
            x.extend(&t[i - 1]);
            x.extend(info);
            #[allow(clippy::cast_possible_truncation)]
            x.push(i as u8);
            x.into_boxed_slice()
        };

        let t_i = hmac_hash::<H>(prk, &concatd);
        t.push(t_i);
    }

    t.into_iter()
        .flatten()
        .take(L)
        .collect::<Box<[u8]>>()
        .as_ref()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use crate::hash::sha::Sha384;
    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_hkdf_hmac_sha384_1() {
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");

        assert_eq!(
            hkdf_expand::<Sha384, 42>(&hkdf_extract::<Sha384>(&salt, &ikm), &info),
            hex!(
                "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5"
            )
        );
    }

    #[test]
    fn test_hkdf_hmac_sha384_2() {
        let ikm = hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
        );
        let salt = hex!(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        );
        let info = hex!(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        );

        assert_eq!(
            hkdf_expand::<Sha384, 82>(&hkdf_extract::<Sha384>(&salt, &ikm), &info),
            hex!(
                "484ca052b8cc724fd1c4ec64d57b4e818c7e25a8e0f4569ed72a6a05fe0649eebf69f8d5c832856bf4e4fbc17967d54975324a94987f7f41835817d8994fdbd6f4c09c5500dca24a56222fea53d8967a8b2e"
            )
        );
    }

    #[test]
    fn test_hkdf_hmac_sha384_3() {
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = [];
        let info = [];

        assert_eq!(
            hkdf_expand::<Sha384, 42>(&hkdf_extract::<Sha384>(&salt, &ikm), &info),
            hex!(
                "c8c96e710f89b0d7990bca68bcdec8cf854062e54c73a7abc743fade9b242daacc1cea5670415b52849c"
            )
        );
    }

    #[test]
    fn test_hkdf_hmac_sha384_4() {
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");

        assert_eq!(
            hkdf_expand::<Sha384, 42>(&hkdf_extract::<Sha384>(&salt, &ikm), &info),
            hex!(
                "fb7e6743eb42cde96f1b70778952ab7548cafe53249f7ffe1497a1635b201ff185b93e951992d858f11a"
            )
        );
    }
}
