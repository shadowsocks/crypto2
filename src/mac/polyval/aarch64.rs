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
    // 0x00
    let t1: poly64x1_t = vget_low_p64(vreinterpretq_p64_u64(vreinterpretq_u64_u8(a)));
    let t2: poly64x1_t = vget_low_p64(vreinterpretq_p64_u64(vreinterpretq_u64_u8(b)));

    let r: poly128_t = vmull_p64(transmute(t1), transmute(t2));

    return vreinterpretq_u8_p128(r);
}

#[inline]
unsafe fn vmull_high(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    // 0x11
    let t1: poly64x2_t = vreinterpretq_p64_u64(vreinterpretq_u64_u8(a));
    let t2: poly64x2_t = vreinterpretq_p64_u64(vreinterpretq_u64_u8(b));

    let r: poly128_t = vmull_high_p64(t1, t2);

    return vreinterpretq_u8_p128(r);
}

#[inline]
unsafe fn vmull_low_high(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    // 0x10
    let t1: poly64x1_t = vget_low_p64(vreinterpretq_p64_u64(vreinterpretq_u64_u8(a)));
    let t2: poly64x1_t = vget_high_p64(vreinterpretq_p64_u64(vreinterpretq_u64_u8(b)));

    let r: poly128_t = vmull_p64(transmute(t1), transmute(t2));

    return vreinterpretq_u8_p128(r);
}

#[inline]
unsafe fn vmull_high_low(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    // 0x01
    let t1: poly64x1_t = vget_high_p64(vreinterpretq_p64_u64(vreinterpretq_u64_u8(a)));
    let t2: poly64x1_t = vget_low_p64(vreinterpretq_p64_u64(vreinterpretq_u64_u8(b)));

    let r: poly128_t = vmull_p64(transmute(t1), transmute(t2));

    return vreinterpretq_u8_p128(r);
}

#[derive(Clone)]
pub struct Polyval {
    key: uint8x16_t,
    h: uint8x16_t,
}

impl Polyval {
    pub const KEY_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize = 16;

    pub fn new(k: &[u8]) -> Self {
        assert_eq!(k.len(), Self::KEY_LEN);

        unsafe {
            let h = vdupq_n_u8(0);
            let key: uint8x16_t = *(k.as_ptr() as *const uint8x16_t).clone();

            Self { key, h }
        }
    }

    #[inline]
    fn gf_mul(&mut self, block: &[u8]) {
        unsafe {
            let mask: uint8x16_t = transmute([1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194]);

            let a = veorq_u8(self.h, vld1q_u8(block.as_ptr()));
            let b = self.key;

            let mut tmp1 = vmull_low(a, b); // 0x00
            let mut tmp4 = vmull_high(a, b); // 0x11
            let mut tmp2 = vmull_low_high(a, b); // 0x10
            let mut tmp3 = vmull_high_low(a, b); // 0x01

            tmp2 = veorq_u8(tmp2, tmp3);

            // NOTE:
            //   等价于: tmp3 = transmute::<u128, uint8x16_t>(transmute::<uint8x16_t, u128>(tmp2) << 64);
            tmp3 = vreinterpretq_u8_u64(transmute([
                0,
                vgetq_lane_u64::<0>(vreinterpretq_u64_u8(tmp2)),
            ]));

            // NOTE:
            //   等价于: tmp2 = transmute::<u128, uint8x16_t>(transmute::<uint8x16_t, u128>(tmp2) >> 64);
            tmp2 = vreinterpretq_u8_u64(transmute([
                vgetq_lane_u64::<1>(vreinterpretq_u64_u8(tmp2)),
                0,
            ]));

            tmp1 = veorq_u8(tmp3, tmp1);
            tmp4 = veorq_u8(tmp4, tmp2);
            tmp2 = vmull_low_high(tmp1, mask); // 0x10

            // NOTE: 相当于 X86 里面的 _mm_shuffle_epi32(tmp1, 78) 指令。
            //
            //       0b 01 00 11 10
            //          1   0  3  2
            //       等价于:
            //           let [t0, t1, t2, t3] = transmute::<uint8x16_t, [u32; 4]>(tmp1);
            //           tmp3 = transmute([t2, t3, t0, t1]);
            tmp3 = vreinterpretq_u8_u32(vcombine_u32(
                vget_high_u32(vreinterpretq_u32_u8(tmp1)),
                vget_low_u32(vreinterpretq_u32_u8(tmp1)),
            ));

            tmp1 = veorq_u8(tmp3, tmp2);

            tmp2 = vmull_low_high(tmp1, mask); // 0x10

            // NOTE: 相当于 X86 里面的 _mm_shuffle_epi32(tmp1, 78) 指令。
            //
            //       0b 01 00 11 10
            //          1   0  3  2
            //       等价于:
            //           let [t0, t1, t2, t3] = transmute::<uint8x16_t, [u32; 4]>(tmp1);
            //           tmp3 = transmute([t2, t3, t0, t1]);
            tmp3 = vreinterpretq_u8_u32(vcombine_u32(
                vget_high_u32(vreinterpretq_u32_u8(tmp1)),
                vget_low_u32(vreinterpretq_u32_u8(tmp1)),
            ));

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
            // vst1q_u8()
            transmute(self.h)
        }
    }
}
