use crate::mem::Zeroize;

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
use core::mem::transmute;


// 参考: https://github.com/noloader/AES-Intrinsics/blob/master/clmul-arm.c
// 
// Convert _mm_clmulepi64_si128 to vmull_{high}_p64
// https://stackoverflow.com/questions/38553881/convert-mm-clmulepi64-si128-to-vmull-high-p64

#[inline]
unsafe fn pmull(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    // Low
    let a: poly64_t = transmute(vgetq_lane_u64(vreinterpretq_u64_u8(a), 0));
    let b: poly64_t = transmute(vgetq_lane_u64(vreinterpretq_u64_u8(b), 0));
    transmute(vmull_p64(a, b))
}

#[inline]
unsafe fn pmull2(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    // High
    let a: poly64_t = transmute(vgetq_lane_u64(vreinterpretq_u64_u8(a), 1));
    let b: poly64_t = transmute(vgetq_lane_u64(vreinterpretq_u64_u8(b), 1));
    transmute(vmull_p64(a, b))
}

// reverse bits in each byte to convert from gcm format to little-little endian
unsafe fn vrbitq_u8(a: uint8x16_t) -> uint8x16_t {
    let result: uint8x16_t;

    // rbit v0.16b, v0.16b
    llvm_asm!("rbit v0.16b, v0.16b"
        : "=w" (result)
        : "w"(a)
        :
        );

    result
}


// Perform the multiplication and reduction in GF(2^128)
#[inline]
unsafe fn gf_mul(key: uint8x16_t, m: &[u8], tag: &mut uint8x16_t) {
    let m = vrbitq_u8(*(m.as_ptr() as *const uint8x16_t));

    let a_p = key;
    let b_p = veorq_u8(m, *tag);

    let z = vdupq_n_u8(0);

    let mut r0 = pmull(a_p, b_p);
    let mut r1 = pmull2(a_p, b_p);
    let mut t0 = vextq_u8(b_p, b_p, 8);
    let mut t1 = pmull(a_p, t0);
    t0 = pmull2(a_p, t0);

    t0 = veorq_u8(t0, t1);
    t1 = vextq_u8(z, t0, 8);
    r0 = veorq_u8(r0, t1);
    t1 = vextq_u8(t0, z, 8);
    r1 = veorq_u8(r1, t1);

    // p = (uint8x16_t)vdupq_n_u64(0x0000000000000087);
    let p = [0x0000000000000087u64, 0x0000000000000087];
    let p: uint8x16_t = transmute(p);

    t0 = pmull2(r1, p);
    t1 = vextq_u8(t0, z, 8);
    r1 = veorq_u8(r1, t1);
    t1 = vextq_u8(z, t0, 8);
    r0 = veorq_u8(r0, t1);

    // t0 = (uint8x16_t)vmull_low_p64((poly64x2_t)r1, (poly64x2_t)p);
    t0 = pmull(r1, p);
    let res = veorq_u8(r0, t0);
    *tag = res;
}

#[derive(Clone)]
pub struct GHash {
    key: uint8x16_t,
    tag: uint8x16_t,
}

impl Zeroize for GHash {
    fn zeroize(&mut self) {
        unsafe {
            self.key = vdupq_n_u8(0);
            self.tag = vdupq_n_u8(0);
        }
    }
}

impl Drop for GHash {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl GHash {
    pub const KEY_LEN: usize   = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize   = 16;
    

    pub fn new(h: &[u8; Self::KEY_LEN]) -> Self {
        unsafe {
            let key: uint8x16_t = transmute(h.clone());
            
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
            transmute(vrbitq_u8(self.tag))
        }
    }
}