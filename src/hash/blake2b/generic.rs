use super::BLAKE2B_IV;
use super::Blake2b;


const SIGMA: [[u8; 16]; 12] = [
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
    [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
    [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
    [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
    [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
    [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
    [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
    [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
    [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 ],
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
];



#[inline]
pub fn transform(state: &mut [u64; 8], block: &[u8], block_counter: u128, flags: u128) {
    debug_assert_eq!(state.len(), 8);
    debug_assert_eq!(block.len(), Blake2b::BLOCK_LEN);

    let mut m = [0u64; 16];
    let mut v = [0u64; 16];

    for i in 0usize..16 {
        let pos = i * 8;
        m[i] = u64::from_le_bytes([
            block[pos + 0],
            block[pos + 1], 
            block[pos + 2], 
            block[pos + 3], 
            block[pos + 4], 
            block[pos + 5], 
            block[pos + 6], 
            block[pos + 7], 
        ]);
    }

    let t1 = (block_counter >> 64) as u64;
    let t0 = block_counter as u64;
    let f1 = (flags >> 64) as u64;
    let f0 = flags as u64;

    v[..8].copy_from_slice(&state[..]);

    v[ 8] = BLAKE2B_IV[0];
    v[ 9] = BLAKE2B_IV[1];
    v[10] = BLAKE2B_IV[2];
    v[11] = BLAKE2B_IV[3];
    v[12] = BLAKE2B_IV[4] ^ t0;
    v[13] = BLAKE2B_IV[5] ^ t1;
    v[14] = BLAKE2B_IV[6] ^ f0;
    v[15] = BLAKE2B_IV[7] ^ f1;

    //                        (R1, R2, R3, R4)
    // G Rotation constants = (32, 24, 16, 63)
    const R1: u32 = 32;
    const R2: u32 = 24;
    const R3: u32 = 16;
    const R4: u32 = 63;

    macro_rules! G {
        ($r:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
            $a = $a.wrapping_add($b).wrapping_add(m[SIGMA[$r][2 * $i + 0] as usize]);
            $d = ($d ^ $a).rotate_right(R1); // R1

            $c = $c.wrapping_add($d);
            $b = ($b ^ $c).rotate_right(R2); // R2

            $a = $a.wrapping_add($b).wrapping_add(m[SIGMA[$r][2 * $i + 1] as usize]);
            $d = ($d ^ $a).rotate_right(R3); // R3

            $c = $c.wrapping_add($d);
            $b = ($b ^ $c).rotate_right(R4); // R4
        }
    }

    macro_rules! ROUND {
        ($r:tt) => {
            G!($r, 0, v[ 0], v[ 4], v[ 8], v[12]);
            G!($r, 1, v[ 1], v[ 5], v[ 9], v[13]);
            G!($r, 2, v[ 2], v[ 6], v[10], v[14]);
            G!($r, 3, v[ 3], v[ 7], v[11], v[15]);
            G!($r, 4, v[ 0], v[ 5], v[10], v[15]);
            G!($r, 5, v[ 1], v[ 6], v[11], v[12]);
            G!($r, 6, v[ 2], v[ 7], v[ 8], v[13]);
            G!($r, 7, v[ 3], v[ 4], v[ 9], v[14]);
        }
    }

    ROUND!(0);
    ROUND!(1);
    ROUND!(2);
    ROUND!(3);
    ROUND!(4);
    ROUND!(5);
    ROUND!(6);
    ROUND!(7);
    ROUND!(8);
    ROUND!(9);
    ROUND!(10);
    ROUND!(11);

    state[0] = state[0] ^ v[0] ^ v[ 8];
    state[1] = state[1] ^ v[1] ^ v[ 9];
    state[2] = state[2] ^ v[2] ^ v[10];
    state[3] = state[3] ^ v[3] ^ v[11];
    state[4] = state[4] ^ v[4] ^ v[12];
    state[5] = state[5] ^ v[5] ^ v[13];
    state[6] = state[6] ^ v[6] ^ v[14];
    state[7] = state[7] ^ v[7] ^ v[15];
}