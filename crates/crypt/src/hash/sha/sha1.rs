use super::{
    ch_32,
    constants::{INITIAL_SHA1, K_SHA_1},
    maj_32,
    parity_32,
};
use crate::hash::Hasher;

pub struct Sha1 {}
impl Hasher for Sha1 {
    const BLOCK_SIZE: usize = 64;
    const DIGEST_SIZE: usize = 20;

    #[allow(clippy::many_single_char_names)]
    fn hash(value: &[u8]) -> Box<[u8]> {
        let l_bytes = value.len();

        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let k_bytes = (56 - (l_bytes as i32 + 1)).rem_euclid(64) as usize;

        let message = {
            let mut x = Vec::new();
            x.extend(value);
            x.push(0b1000_0000);
            x.extend([0u8].repeat(k_bytes));
            x.extend(((l_bytes * 8) as u64).to_be_bytes());
            x
        };

        let blocks: Box<[[u32; 16]]> = message
            .chunks_exact(64)
            .map(|block| {
                (*block
                    .chunks_exact(4)
                    .map(|word| u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
                    .collect::<Box<[u32]>>())
                .try_into()
                .unwrap()
            })
            .collect();

        let n_blocks = blocks.len();

        let mut hash = Vec::from([INITIAL_SHA1]);

        for i in 1..=n_blocks {
            // Prepare the message schedule
            let mut schedule: [u32; _] = [0; 80];
            schedule[..16].copy_from_slice(&blocks[i - 1]);
            for t in 16..80 {
                schedule[t] =
                    (schedule[t - 3] ^ schedule[t - 8] ^ schedule[t - 14] ^ schedule[t - 16])
                        .rotate_left(1);
            }

            // Initialize the working variables
            let mut a = hash[i - 1][0];
            let mut b = hash[i - 1][1];
            let mut c = hash[i - 1][2];
            let mut d = hash[i - 1][3];
            let mut e = hash[i - 1][4];

            for t in 0..80 {
                let f = if (0..20).contains(&t) {
                    ch_32
                } else if (40..60).contains(&t) {
                    maj_32
                } else {
                    parity_32
                };

                let tt = a
                    .rotate_left(5)
                    .wrapping_add(f(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(K_SHA_1[t])
                    .wrapping_add(schedule[t]);

                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = tt;
            }

            let hash_value = [
                a.wrapping_add(hash[i - 1][0]),
                b.wrapping_add(hash[i - 1][1]),
                c.wrapping_add(hash[i - 1][2]),
                d.wrapping_add(hash[i - 1][3]),
                e.wrapping_add(hash[i - 1][4]),
            ];
            hash.push(hash_value);
        }

        hash[n_blocks]
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .collect()
    }
}
