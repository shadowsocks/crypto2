use crate::mem::Zeroize;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

// Intel® Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode
// 
// https://www.intel.cn/content/www/cn/zh/processors/carry-less-multiplication-instruction-in-gcm-mode-paper.html
// 
// 代码参考：
// 
// https://github.com/Shay-Gueron/AES-GCM-SIV/blob/master/AES_GCM_SIV_128/AES_GCM_SIV_128_C_Intrinsics_Code/polyval.c


#[derive(Clone)]
pub struct Polyval {
    key: __m128i,
    h: __m128i,
}

impl Zeroize for Polyval {
    fn zeroize(&mut self) {
        unsafe {
            self.key = _mm_setzero_si128();
            self.h   = _mm_setzero_si128();
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
            let h = _mm_setzero_si128();
            let key = _mm_loadu_si128(k.as_ptr() as *const __m128i);

            Self { key, h  }
        }
    }

    #[inline]
    fn gf_mul(&mut self, block: &[u8]) {
        unsafe {
            let a = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            let mask = _mm_setr_epi32(0x1, 0, 0, 0xc2000000u32 as _);

            self.h = _mm_xor_si128(self.h, a);

            let mut tmp1 = _mm_clmulepi64_si128(self.h, self.key, 0x00);
            let mut tmp4 = _mm_clmulepi64_si128(self.h, self.key, 0x11);
            let mut tmp2 = _mm_clmulepi64_si128(self.h, self.key, 0x10);
            let mut tmp3 = _mm_clmulepi64_si128(self.h, self.key, 0x01);

            tmp2 = _mm_xor_si128(tmp2, tmp3);
            tmp3 = _mm_slli_si128(tmp2, 8);
            tmp2 = _mm_srli_si128(tmp2, 8);
            tmp1 = _mm_xor_si128(tmp3, tmp1);
            tmp4 = _mm_xor_si128(tmp4, tmp2);
            tmp2 = _mm_clmulepi64_si128(tmp1, mask, 0x10);
            tmp3 = _mm_shuffle_epi32(tmp1, 78);
            tmp1 = _mm_xor_si128(tmp3, tmp2);
            tmp2 = _mm_clmulepi64_si128(tmp1, mask, 0x10);
            tmp3 = _mm_shuffle_epi32(tmp1, 78);
            tmp1 = _mm_xor_si128(tmp3, tmp2);
            self.h = _mm_xor_si128(tmp4, tmp1);
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
            let mut tag = [0u8; Self::TAG_LEN];
            _mm_storeu_si128(tag.as_mut_ptr() as *mut __m128i, self.h);
            tag
        }
    }
}
