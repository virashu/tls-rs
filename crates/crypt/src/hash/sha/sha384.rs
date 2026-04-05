use super::{
    cap_sigma_512_0,
    cap_sigma_512_1,
    ch_64,
    constants::{INITIAL_SHA384, K_64},
    maj_64,
    sigma_512_0,
    sigma_512_1,
};
use crate::hash::Hasher;

pub struct Sha384 {}
impl Hasher for Sha384 {
    const BLOCK_SIZE: usize = 128;
    const DIGEST_SIZE: usize = 48;

    #[allow(clippy::many_single_char_names)]
    fn hash(value: &[u8]) -> Box<[u8]> {
        let l_bytes = value.len();

        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let k_bytes = ((Self::BLOCK_SIZE as i32 - 16) - (l_bytes as i32 + 1))
            .rem_euclid(Self::BLOCK_SIZE as i32) as usize;

        let message = {
            let mut x = Vec::new();
            x.extend(value);
            x.push(0b1000_0000);
            x.extend([0u8].repeat(k_bytes));
            x.extend(((l_bytes * 8) as u128).to_be_bytes());
            x
        };

        let blocks: Box<[[u64; 16]]> = message
            .chunks_exact(Self::BLOCK_SIZE)
            .map(|block| {
                (*block
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|chunk| u64::from_be_bytes(*chunk))
                    .collect::<Box<[u64]>>())
                .try_into()
                .unwrap()
            })
            .collect();

        let n_blocks = blocks.len();

        let mut hash = INITIAL_SHA384;

        for i in 1..=n_blocks {
            // Prepare the message schedule
            let mut schedule: [u64; _] = [0; 80];
            schedule[..16].copy_from_slice(&blocks[i - 1]);
            for t in 16..80 {
                schedule[t] = sigma_512_1(schedule[t - 2])
                    .wrapping_add(schedule[t - 7])
                    .wrapping_add(sigma_512_0(schedule[t - 15]))
                    .wrapping_add(schedule[t - 16]);
            }

            // Initialize the working variables
            let mut a = hash[0];
            let mut b = hash[1];
            let mut c = hash[2];
            let mut d = hash[3];
            let mut e = hash[4];
            let mut f = hash[5];
            let mut g = hash[6];
            let mut h = hash[7];

            for t in 0..80 {
                let t1 = h
                    .wrapping_add(cap_sigma_512_1(e))
                    .wrapping_add(ch_64(e, f, g))
                    .wrapping_add(K_64[t])
                    .wrapping_add(schedule[t]);
                let t2 = cap_sigma_512_0(a).wrapping_add(maj_64(a, b, c));

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            hash = [
                hash[0].wrapping_add(a),
                hash[1].wrapping_add(b),
                hash[2].wrapping_add(c),
                hash[3].wrapping_add(d),
                hash[4].wrapping_add(e),
                hash[5].wrapping_add(f),
                hash[6].wrapping_add(g),
                hash[7].wrapping_add(h),
            ];
        }

        hash[..6]
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_sha384_empty() {
        let input = b"";
        let output = Sha384::hash(input);

        assert_eq!(
            *output,
            hex!(
                "38b060a751ac9638 4cd9327eb1b1e36a 21fdb71114be0743 4c0cc7bf63f6e1da 274edebfe76f65fb d51ad2f14898b95b"
            )
        );
    }

    #[test]
    fn test_sha384_24bits() {
        let input = b"abc";
        let output = Sha384::hash(input);

        assert_eq!(
            *output,
            hex!(
                "cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7"
            )
        );
    }

    #[test]
    fn test_sha384_896bits() {
        let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let output = Sha384::hash(input);

        assert_eq!(
            *output,
            hex!(
                "09330c33f71147e8 3d192fc782cd1b47 53111b173b3b05d2 2fa08086e3b0f712 fcc7c71a557e2db9 66c3e9fa91746039"
            )
        );
    }

    #[test]
    fn test_sha384_repetitions() {
        let input = b"a".repeat(1_000_000);
        let output = Sha384::hash(&input);

        assert_eq!(
            *output,
            hex!(
                "9d0e1809716474cb 086e834e310a4a1c ed149e9c00f24852 7972cec5704c2a5b 07b8b3dc38ecc4eb ae97ddd87f3d8985"
            )
        );
    }
}
