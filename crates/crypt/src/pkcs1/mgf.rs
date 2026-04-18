use utils::concat_dyn;

use crate::hash::Hasher;

/// MGF1
/// <https://datatracker.ietf.org/doc/html/rfc8017#appendix-B.2.1>
pub fn generate_mask<H: Hasher>(seed: &[u8], len: usize) -> Box<[u8]> {
    let mut t = Vec::new();

    for i in 0..len.div_ceil(H::DIGEST_SIZE) {
        let counter = (i as u32).to_be_bytes();
        let hash = H::hash(&concat_dyn![seed, counter]);
        t.extend(hash);
    }

    t.into_iter().take(len).collect()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;
    use crate::hash::sha::{Sha1, Sha256};

    #[test]
    fn test_mgf_testcase_1() {
        let expected = hex!("1ac907");
        assert_eq!(*generate_mask::<Sha1>(b"foo", 3), expected)
    }

    #[test]
    fn test_mgf_testcase_2() {
        let expected = hex!("1ac9075cd4");
        assert_eq!(*generate_mask::<Sha1>(b"foo", 5), expected)
    }

    #[test]
    fn test_mgf_testcase_3() {
        let expected = hex!("bc0c655e01");
        assert_eq!(*generate_mask::<Sha1>(b"bar", 5), expected)
    }

    #[test]
    fn test_mgf_testcase_4() {
        let expected = hex!(
            "bc0c655e016bc2931d85a2e675181adcef7f581f76df2739da74faac41627be2f7f415c89e983fd0ce80ced9878641cb4876"
        );
        assert_eq!(*generate_mask::<Sha1>(b"bar", 50), expected)
    }

    #[test]
    fn test_mgf_testcase_5() {
        let expected = hex!(
            "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1"
        );
        assert_eq!(*generate_mask::<Sha256>(b"bar", 50), expected)
    }
}
