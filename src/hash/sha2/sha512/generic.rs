use super::K64;
use super::Sha512;


macro_rules! S0 {
    ($v:expr) => (
        $v.rotate_right(1) ^ $v.rotate_right(8) ^ ($v >> 7)
    )
}
macro_rules! S1 {
    ($v:expr) => (
        $v.rotate_right(19) ^ $v.rotate_right(61) ^ ($v >> 6)
    )
}
macro_rules! S2 {
    ($v:expr) => (
        $v.rotate_right(28) ^ $v.rotate_right(34) ^ $v.rotate_right(39)
    )
}
macro_rules! S3 {
    ($v:expr) => (
        $v.rotate_right(14) ^ $v.rotate_right(18) ^ $v.rotate_right(41)
    )
}

macro_rules! F0 {
    ($x:expr, $y:expr, $z:expr) => (
        ( ($x) & ($y) ) | ( ($z) & ( ($x) | ($y) ) )
    )
}
macro_rules! F1 {
    ($x:expr, $y:expr, $z:expr) => (
        ( ($z) ^ ( ($x) & ( ($y) ^ ($z) ) ) )
    )
}

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
        $v.rotate_right(28) ^ $v.rotate_right(34) ^ $v.rotate_right(39)
    )
}
macro_rules! EP1 {
    ($v:expr) => (
        $v.rotate_right(14) ^ $v.rotate_right(18) ^ $v.rotate_right(41)
    )
}
macro_rules! SIG0 {
    ($v:expr) => (
        $v.rotate_right(1) ^ $v.rotate_right(8) ^ ($v >> 7)
    )
}
macro_rules! SIG1 {
    ($v:expr) => (
        $v.rotate_right(19) ^ $v.rotate_right(61) ^ ($v >> 6)
    )
}


#[inline]
pub fn transform(state: &mut [u64; 8], block: &[u8]) {
    debug_assert_eq!(state.len(), 8);
    debug_assert_eq!(block.len(), Sha512::BLOCK_LEN);
    
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = u64::from_be_bytes([
            block[i*8 + 0], block[i*8 + 1],
            block[i*8 + 2], block[i*8 + 3],
            block[i*8 + 4], block[i*8 + 5],
            block[i*8 + 6], block[i*8 + 7],
        ]);
    }

    for i in 16..80 {
        w[i] = S1!(w[i -  2])
                .wrapping_add(w[i -  7])
                .wrapping_add(S0!(w[i - 15]))
                .wrapping_add(w[i - 16]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    
    for i in 0..80 {
        let t1 = h.wrapping_add(EP1!(e))
                .wrapping_add(CH!(e, f, g))
                .wrapping_add(K64[i])
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
