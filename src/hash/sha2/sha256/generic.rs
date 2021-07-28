use super::Sha256;


// Round constants
const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 
];


macro_rules! CH {
    ($x:expr, $y:expr, $z:expr) => (
        ( ($x) & ($y) ) ^ ( !($x) & ($z) )
    )
}
macro_rules! MAJ {
    ($x:expr, $y:expr, $z:expr) => (
        ( ($x) & ($y) ) ^ ( ($x) & ($z) ) ^ ( ($y) & ($z) )
    )
}
macro_rules! EP0 {
    ($v:expr) => (
        $v.rotate_right(2) ^ $v.rotate_right(13) ^ $v.rotate_right(22)
    )
}
macro_rules! EP1 {
    ($v:expr) => (
        $v.rotate_right(6) ^ $v.rotate_right(11) ^ $v.rotate_right(25)
    )
}
macro_rules! SIG0 {
    ($v:expr) => (
        $v.rotate_right(7) ^ $v.rotate_right(18) ^ ($v >> 3)
    )
}
macro_rules! SIG1 {
    ($v:expr) => (
        $v.rotate_right(17) ^ $v.rotate_right(19) ^ ($v >> 10)
    )
}


#[inline]
pub fn transform(state: &mut [u32; 8], block: &[u8]) {
    debug_assert_eq!(state.len(), 8);
    debug_assert_eq!(block.len(), Sha256::BLOCK_LEN);
    
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i*4 + 0], block[i*4 + 1],
            block[i*4 + 2], block[i*4 + 3],
        ]);
    }
    for t in 16..64 {
        w[t] = SIG1!(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(SIG0!(w[t - 15]))
                .wrapping_add(w[t - 16]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    
    for i in 0..64 {
        let t1 = h.wrapping_add(EP1!(e))
                .wrapping_add(CH!(e, f, g))
                .wrapping_add(K32[i])
                .wrapping_add(w[i]);
        let t2 = EP0!(a).wrapping_add(MAJ!(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}
