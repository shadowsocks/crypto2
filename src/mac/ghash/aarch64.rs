#![allow(non_camel_case_types)]
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
use core::mem::transmute;

// TODO: 等待 stdarch 项目增加 这个类型。
type poly128_t = u128;

#[inline]
unsafe fn vreinterpretq_u8_p128(a: poly128_t) -> uint8x16_t {
    transmute(a)
}

// NOTE: 不同编译器的优化:
// https://gist.github.com/LuoZijun/ffa7ec2487c4debd50c44bba1434f410
#[inline]
unsafe fn vmull_low(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let t1: poly64x1_t = vget_low_p64(vreinterpretq_p64_u64(vreinterpretq_u64_u8(a)));
    let t2: poly64x1_t = vget_low_p64(vreinterpretq_p64_u64(vreinterpretq_u64_u8(b)));

    let r: poly128_t = vmull_p64(transmute(t1), transmute(t2));

    return vreinterpretq_u8_p128(r);
}

#[inline]
unsafe fn vmull_high(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let t1: poly64x2_t = vreinterpretq_p64_u64(vreinterpretq_u64_u8(a));
    let t2: poly64x2_t = vreinterpretq_p64_u64(vreinterpretq_u64_u8(b));

    let r: poly128_t = vmull_high_p64(t1, t2);

    return vreinterpretq_u8_p128(r);
}

// Perform the multiplication and reduction in GF(2^128)
#[inline]
unsafe fn gf_mul(key: uint8x16_t, m: &[u8], tag: &mut uint8x16_t) {
    let m = vrbitq_u8(vld1q_u8(m.as_ptr()));

    let a_p = key;
    let b_p = veorq_u8(m, *tag);

    let z = vdupq_n_u8(0);

    let mut r0 = vmull_low(a_p, b_p);
    let mut r1 = vmull_high(a_p, b_p);
    let mut t0 = vextq_u8(b_p, b_p, 8);
    let mut t1 = vmull_low(a_p, t0);
    t0 = vmull_high(a_p, t0);

    t0 = veorq_u8(t0, t1);
    t1 = vextq_u8(z, t0, 8);
    r0 = veorq_u8(r0, t1);
    t1 = vextq_u8(t0, z, 8);
    r1 = veorq_u8(r1, t1);

    let p = vreinterpretq_u8_u64(vdupq_n_u64(0x0000000000000087));

    t0 = vmull_high(r1, p);
    t1 = vextq_u8(t0, z, 8);
    r1 = veorq_u8(r1, t1);
    t1 = vextq_u8(z, t0, 8);
    r0 = veorq_u8(r0, t1);

    t0 = vmull_low(r1, p);
    let res = veorq_u8(r0, t0);
    *tag = res;
}

#[derive(Clone)]
pub struct GHash {
    key: uint8x16_t,
    tag: uint8x16_t,
}

impl GHash {
    pub const KEY_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize = 16;

    pub fn new(h: &[u8; Self::KEY_LEN]) -> Self {
        unsafe {
            let key: uint8x16_t = vld1q_u8(h.as_ptr());

            Self {
                key: vrbitq_u8(key),
                tag: vdupq_n_u8(0),
            }
        }
    }

    pub fn update(&mut self, m: &[u8]) {
        let mlen = m.len();
        if mlen == 0 {
            return ();
        }

        let n = mlen / Self::BLOCK_LEN;
        for i in 0..n {
            let chunk = &m[i * Self::BLOCK_LEN..i * Self::BLOCK_LEN + Self::BLOCK_LEN];
            let mut block = [0u8; Self::BLOCK_LEN];
            block.copy_from_slice(chunk);

            unsafe {
                gf_mul(self.key, &block, &mut self.tag);
            }
        }

        if mlen % Self::BLOCK_LEN != 0 {
            let rem = &m[n * Self::BLOCK_LEN..];
            let rlen = rem.len();

            let mut last_block = [0u8; Self::BLOCK_LEN];
            last_block[..rlen].copy_from_slice(rem);

            unsafe {
                gf_mul(self.key, &last_block, &mut self.tag);
            }
        }
    }

    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        unsafe {
            // let mut out = [0u8; Self::TAG_LEN];
            // vst1q_u8()
            transmute(vrbitq_u8(self.tag))
        }
    }
}
