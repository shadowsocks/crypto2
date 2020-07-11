use super::K32;
use super::Sha256;


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
