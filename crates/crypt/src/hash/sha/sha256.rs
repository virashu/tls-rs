use super::{
    cap_sigma_256_0,
    cap_sigma_256_1,
    ch_32,
    constants::{INITIAL_SHA256, K_32},
    maj_32,
    sigma_256_0,
    sigma_256_1,
};
use crate::hash::Hasher;

pub struct Sha256 {}
impl Hasher for Sha256 {
    const BLOCK_SIZE: usize = 64;
    const DIGEST_SIZE: usize = 32;

    #[allow(clippy::many_single_char_names)]
    fn hash(value: &[u8]) -> Box<[u8]> {
        let l_bytes = value.len();

        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let k_bytes = ((Self::BLOCK_SIZE as i32 - 8) - (l_bytes as i32 + 1))
            .rem_euclid(Self::BLOCK_SIZE as i32) as usize;

        let message = {
            let mut x = Vec::new();
            x.extend(value);
            x.push(0b1000_0000);
            x.extend([0u8].repeat(k_bytes));
            x.extend(((l_bytes * 8) as u64).to_be_bytes());
            x
        };

        let blocks: Box<[[u32; 16]]> = message
            .chunks_exact(Self::BLOCK_SIZE)
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

        let mut hash = Vec::from([INITIAL_SHA256]);

        for i in 1..=n_blocks {
            // Prepare the message schedule
            let mut schedule: [u32; _] = [0; 64];
            schedule[..16].copy_from_slice(&blocks[i - 1]);
            for t in 16..64 {
                schedule[t] = sigma_256_1(schedule[t - 2])
                    .wrapping_add(schedule[t - 7])
                    .wrapping_add(sigma_256_0(schedule[t - 15]))
                    .wrapping_add(schedule[t - 16]);
            }

            // Initialize the working variables
            let mut a = hash[i - 1][0];
            let mut b = hash[i - 1][1];
            let mut c = hash[i - 1][2];
            let mut d = hash[i - 1][3];
            let mut e = hash[i - 1][4];
            let mut f = hash[i - 1][5];
            let mut g = hash[i - 1][6];
            let mut h = hash[i - 1][7];

            for t in 0..64 {
                let t1 = h
                    .wrapping_add(cap_sigma_256_1(e))
                    .wrapping_add(ch_32(e, f, g))
                    .wrapping_add(K_32[t])
                    .wrapping_add(schedule[t]);
                let t2 = cap_sigma_256_0(a).wrapping_add(maj_32(a, b, c));

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            let hash_value = [
                a.wrapping_add(hash[i - 1][0]),
                b.wrapping_add(hash[i - 1][1]),
                c.wrapping_add(hash[i - 1][2]),
                d.wrapping_add(hash[i - 1][3]),
                e.wrapping_add(hash[i - 1][4]),
                f.wrapping_add(hash[i - 1][5]),
                g.wrapping_add(hash[i - 1][6]),
                h.wrapping_add(hash[i - 1][7]),
            ];
            hash.push(hash_value);
        }

        hash[n_blocks]
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .collect()
    }
}
