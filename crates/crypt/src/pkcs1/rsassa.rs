use anyhow::Result;

use super::{
    PrivateKey,
    PublicKey,
    emsa::{emsa_pss_encode, emsa_pss_encode_fixed, emsa_pss_verify},
    primitives::{int_to_octets, octets_to_int, rsa_dp, rsa_ep, rsa_sp1, rsa_vp1},
};
use crate::hash::Hasher;

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
    use num_bigint::BigUint;

    use super::*;
    use crate::hash::sha::Sha256;

    #[test]
    fn test_sign_testcase_1() {
        let modulus = BigUint::from_bytes_be(&hex!(
            "c5062b58d8539c765e1e5dbaf14cf75dd56c2e13105fecfd1a930bbb5948ff32
             8f126abe779359ca59bca752c308d281573bc6178b6c0fef7dc445e4f8264304
             37b9f9d790581de5749c2cb9cb26d42b2fee15b6b26f09c99670336423b86bc5
             bec71113157be2d944d7ff3eebffb28413143ea36755db0ae62ff5b724eecb3d
             316b6bac67e89cacd8171937e2ab19bd353a89acea8c36f81c89a620d5fd2eff
             ea896601c7f9daca7f033f635a3a943331d1b1b4f5288790b53af352f1121ca1
             bef205f40dc012c412b40bdd27585b946466d75f7ee0a7f9d549b4bece6f43ac
             3ee65fe7fd37123359d9f1a850ad450aaf5c94eb11dea3fc0fc6e9856b1805ef"
        ));
        let exponent = BigUint::from_bytes_be(&hex!(
            "49e5786bb4d332f94586327bde088875379b75d128488f08e574ab4715302a87
             eea52d4c4a23d8b97af7944804337c5f55e16ba9ffafc0c9fd9b88eca443f39b
             7967170ddb8ce7ddb93c6087c8066c4a95538a441b9dc80dc9f7810054fd1e5c
             9d0250c978bb2d748abe1e9465d71a8165d3126dce5db2adacc003e9062ba37a
             54b63e5f49a4eafebd7e4bf5b0a796c2b3a950fa09c798d3fa3e86c4b62c33ba
             9365eda054e5fe74a41f21b595026acf1093c90a8c71722f91af1ed29a41a244
             9a320fc7ba3120e3e8c3e4240c04925cc698ecd66c7c906bdf240adad972b4df
             f4869d400b5d13e33eeba38e075e872b0ed3e91cc9c283867a4ffc3901d2069f"
        ));
        let key = PrivateKey { modulus, exponent };

        let message = hex!(
            "dfc22604b95d15328059745c6c98eb9dfb347cf9f170aff19deeec555f22285a
             6706c4ecbf0fb1458c60d9bf913fbae6f4c554d245d946b4bc5f34aec2ac6be8
             b33dc8e0e3a9d601dfd53678f5674443f67df78a3a9e0933e5f158b169ac8d1c
             4cd0fb872c14ca8e001e542ea0f9cfda88c42dcad8a74097a00c22055b0bd41f"
        );
        let salt = hex!("e1256fc1eeef81773fdd54657e4007fde6bcb9b1");
        let expected = hex!(
            "8b46f2c889d819f860af0a6c4c889e4d1436c6ca174464d22ae11b9ccc265d74
             3c67e569accbc5a80d4dd5f1bf4039e23de52aece40291c75f8936c58c9a2f77
             a780bbe7ad31eb76742f7b2b8b14ca1a7196af7e673a3cfc237d50f615b75cf4
             a7ea78a948bedaf9242494b41e1db51f437f15fd2551bb5d24eefb1c3e60f036
             94d0033a1e0a9b9f5e4ab97d457dff9b9da516dc226d6d6529500308ed74a2e6
             d9f3c10595788a52a1bc0664aedf33efc8badd037eb7b880772bdb04a6046e9e
             deee4197c25507fb0f11ab1c9f63f53c8820ea8405cfd7721692475b4d72355f
             a9a3804f29e6b6a7b059c4441d54b28e4eed2529c6103b5432c71332ce742bcc"
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
