use crate::mem::Zeroize;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

// 参考:
// https://www.intel.cn/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf

#[derive(Clone)]
pub struct GHash {
    key: __m128i,
    buf: __m128i,
}

impl Zeroize for GHash {
    fn zeroize(&mut self) {
        unsafe {
            self.key = _mm_setzero_si128();
            self.buf = _mm_setzero_si128();
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


    pub fn new(key: &[u8; Self::KEY_LEN]) -> Self {
        let key = key.clone();
        
        unsafe {
            let tag = _mm_setzero_si128();
            let vm = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
            let key = _mm_shuffle_epi8(_mm_loadu_si128(key.as_ptr() as *const __m128i), vm);

            Self { key, buf: tag, }
        }
    }
    
    // Performing Ghash Using Algorithms 1 and 5 (C)
    #[inline]
    fn gf_mul(&mut self, x: &[u8]) {
        unsafe {
            let a = self.key;

            let vm = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
            let mut b = _mm_loadu_si128(x.as_ptr() as *const __m128i);
            b = _mm_shuffle_epi8(b, vm);
            b = _mm_xor_si128(b, self.buf);

            let mut tmp2: __m128i = core::mem::zeroed();
            let mut tmp3: __m128i = core::mem::zeroed();
            let mut tmp4: __m128i = core::mem::zeroed();
            let mut tmp5: __m128i = core::mem::zeroed();
            let mut tmp6: __m128i = core::mem::zeroed();
            let mut tmp7: __m128i = core::mem::zeroed();
            let mut tmp8: __m128i = core::mem::zeroed();
            let mut tmp9: __m128i = core::mem::zeroed();

            tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
            tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
            tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
            tmp6 = _mm_clmulepi64_si128(a, b, 0x11);
            tmp4 = _mm_xor_si128(tmp4, tmp5);
            tmp5 = _mm_slli_si128(tmp4, 8);
            tmp4 = _mm_srli_si128(tmp4, 8);
            tmp3 = _mm_xor_si128(tmp3, tmp5);
            tmp6 = _mm_xor_si128(tmp6, tmp4);
            tmp7 = _mm_srli_epi32(tmp3, 31);
            tmp8 = _mm_srli_epi32(tmp6, 31);
            tmp3 = _mm_slli_epi32(tmp3, 1);
            tmp6 = _mm_slli_epi32(tmp6, 1);
            tmp9 = _mm_srli_si128(tmp7, 12);
            tmp8 = _mm_slli_si128(tmp8, 4);
            tmp7 = _mm_slli_si128(tmp7, 4);
            tmp3 = _mm_or_si128(tmp3, tmp7);
            tmp6 = _mm_or_si128(tmp6, tmp8);
            tmp6 = _mm_or_si128(tmp6, tmp9);
            tmp7 = _mm_slli_epi32(tmp3, 31);
            tmp8 = _mm_slli_epi32(tmp3, 30);
            tmp9 = _mm_slli_epi32(tmp3, 25);
            tmp7 = _mm_xor_si128(tmp7, tmp8);
            tmp7 = _mm_xor_si128(tmp7, tmp9);
            tmp8 = _mm_srli_si128(tmp7, 4);
            tmp7 = _mm_slli_si128(tmp7, 12);
            tmp3 = _mm_xor_si128(tmp3, tmp7);
            tmp2 = _mm_srli_epi32(tmp3, 1);
            tmp4 = _mm_srli_epi32(tmp3, 2);
            tmp5 = _mm_srli_epi32(tmp3, 7);
            tmp2 = _mm_xor_si128(tmp2, tmp4);
            tmp2 = _mm_xor_si128(tmp2, tmp5);
            tmp2 = _mm_xor_si128(tmp2, tmp8);
            tmp3 = _mm_xor_si128(tmp3, tmp2);
            tmp6 = _mm_xor_si128(tmp6, tmp3);
            
            _mm_storeu_si128(&mut self.buf as _, tmp6);
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
            self.gf_mul(chunk);
        }

        if mlen % Self::BLOCK_LEN != 0 {
            let rem = &m[n * Self::BLOCK_LEN..];
            let rlen = rem.len();

            let mut last_block = [0u8; Self::BLOCK_LEN];
            last_block[..rlen].copy_from_slice(rem);
            self.gf_mul(&last_block);
        }
    }

    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        unsafe {
            let mut out = [0u8; Self::TAG_LEN];

            let vm = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
            _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(self.buf, vm));
            out
        }
    }
}

