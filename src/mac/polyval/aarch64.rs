use crate::mem::Zeroize;

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
use core::mem::transmute;


#[inline]
unsafe fn _mm_clmulepi64_si128(a: uint8x16_t, b: uint8x16_t, imm8: u8) -> uint8x16_t {
    match imm8 {
        0x00 => {
            let a: u64 = vgetq_lane_u64(vreinterpretq_u64_u8(a), 0);
            let b: u64 = vgetq_lane_u64(vreinterpretq_u64_u8(b), 0);
            let ret: poly128_t = vmull_p64(transmute(a), transmute(b));
            transmute(ret)
        },
        0x11 => {
            let a: u64 = vgetq_lane_u64(vreinterpretq_u64_u8(a), 1);
            let b: u64 = vgetq_lane_u64(vreinterpretq_u64_u8(b), 1);
            let ret: poly128_t = vmull_p64(transmute(a), transmute(b));
            transmute(ret)
        },
        0x10 => {
            let a: u64 = vgetq_lane_u64(vreinterpretq_u64_u8(a), 0);
            let b: u64 = vgetq_lane_u64(vreinterpretq_u64_u8(b), 1);
            let ret: poly128_t = vmull_p64(transmute(a), transmute(b));
            transmute(ret)
        },
        0x01 => {
            let a: u64 = vgetq_lane_u64(vreinterpretq_u64_u8(a), 1);
            let b: u64 = vgetq_lane_u64(vreinterpretq_u64_u8(b), 0);
            let ret: poly128_t = vmull_p64(transmute(a), transmute(b));
            transmute(ret)
        },
        _ => unreachable!()
    }
}

#[derive(Clone)]
pub struct Polyval {
    key: uint8x16_t,
    h: uint8x16_t,
}

impl Zeroize for Polyval {
    fn zeroize(&mut self) {
        unsafe {
            self.key = vdupq_n_u8(0);
            self.h   = vdupq_n_u8(0);
        }
    }
}

impl Drop for Polyval {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Polyval {
    pub const KEY_LEN: usize   = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize   = 16;


    pub fn new(k: &[u8]) -> Self {
        assert_eq!(k.len(), Self::KEY_LEN);
        
        unsafe {
            let h = vdupq_n_u8(0);
            let key: uint8x16_t = *(k.as_ptr() as *const uint8x16_t).clone();

            Self { key, h  }
        }
    }

    #[inline]
    fn gf_mul(&mut self, block: &[u8]) {
        unsafe {
            let mask: uint8x16_t = transmute([1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194]);

            let a = veorq_u8(self.h, *(block.as_ptr() as *const uint8x16_t));
            let b = self.key;

            let mut tmp1 = _mm_clmulepi64_si128(a, b, 0x00);
            let mut tmp4 = _mm_clmulepi64_si128(a, b, 0x11);
            let mut tmp2 = _mm_clmulepi64_si128(a, b, 0x10);
            let mut tmp3 = _mm_clmulepi64_si128(a, b, 0x01);


            tmp2 = veorq_u8(tmp2, tmp3);
            tmp3 = transmute::<u128, uint8x16_t>(transmute::<uint8x16_t, u128>(tmp2) << 64);
            // vgetq_lane_u64(vreinterpretq_u64_u8(a), 1)

            tmp2 = transmute::<u128, uint8x16_t>(transmute::<uint8x16_t, u128>(tmp2) >> 64);

            tmp1 = veorq_u8(tmp3, tmp1);
            tmp4 = veorq_u8(tmp4, tmp2);

            tmp2 = _mm_clmulepi64_si128(tmp1, mask, 0x10);

            // 0b 01 00 11 10
            //    1   0  3  2
            // tmp3 = _mm_shuffle_epi32(tmp1, 78);
            {
                let [t0, t1, t2, t3] = transmute::<uint8x16_t, [u32; 4]>(tmp1);
                tmp3 = transmute([t2, t3, t0, t1]);
            }
            
            tmp1 = veorq_u8(tmp3, tmp2);
            
            tmp2 = _mm_clmulepi64_si128(tmp1, mask, 0x10);

            {
                let [t0, t1, t2, t3]: [u32; 4] = transmute(tmp1);
                tmp3 = transmute([t2, t3, t0, t1]);
            }

            tmp1 = veorq_u8(tmp3, tmp2);
            
            self.h = veorq_u8(tmp4, tmp1);
        }
    }

    pub fn update(&mut self, m: &[u8]) {
        let mlen = m.len();

        for chunk in m.chunks_exact(Self::BLOCK_LEN) {
            self.gf_mul(chunk);
        }

        let r = mlen % Self::BLOCK_LEN;
        if r > 0 {
            let mut last_block = [0u8; Self::BLOCK_LEN];
            let offset = mlen - r;
            last_block[..r].copy_from_slice(&m[offset..]);
            self.gf_mul(&last_block);
        }
    }

    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        unsafe {
            transmute(self.h)
        }
    }
}