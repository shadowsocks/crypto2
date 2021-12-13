#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::BLAKE2S_IV;

#[cfg(all(not(target_feature = "sse4.1"), target_feature = "sse2"))]
#[path = "./sse2.rs"]
mod feature;

#[cfg(target_feature = "sse4.1")]
// #[cfg(all(not(target_feature = "avx2"), target_feature = "sse4.1"))]
#[path = "./sse41.rs"]
mod feature;

// #[cfg(target_feature = "avx2")]
// #[path = "./avx2.rs"]
// mod feature;

use self::feature::*;

/// BLAKE2s
#[derive(Clone)]
pub struct Blake2s {
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
    state: [__m128i; 4],
    counter: u64, // T0, T1
}

impl Blake2s {
    pub const BLOCK_LEN: usize = 64;

    pub const H_MIN: usize = 1;
    pub const H_MAX: usize = 32;

    pub const K_MIN: usize = 0;
    pub const K_MAX: usize = 32;

    pub const M_MIN: u64 = 0;
    pub const M_MAX: u64 = u64::MAX;

    pub const ROUNDS: usize = 10; // Rounds in F

    #[inline]
    pub fn new(iv: [u32; 8], key: &[u8]) -> Self {
        let klen = key.len();
        assert!(klen >= Self::K_MIN && klen <= Self::K_MAX);

        unsafe {
            let va = _mm_loadu_si128(iv.as_ptr().add(0) as *const __m128i);
            let vb = _mm_loadu_si128(iv.as_ptr().add(4) as *const __m128i);
            let vc = _mm_loadu_si128(BLAKE2S_IV.as_ptr().add(0) as *const __m128i);
            let vd = _mm_loadu_si128(BLAKE2S_IV.as_ptr().add(4) as *const __m128i);

            let mut offset = 0usize;
            let mut block = [0u8; Self::BLOCK_LEN];
            if klen > 0 {
                offset = klen;
                block[..klen].copy_from_slice(&key);
            }

            Self {
                buffer: block,
                offset,
                state: [va, vb, vc, vd],
                counter: 0u64,
            }
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;

        const CHUNKS: u64 = 0;

        while i < data.len() {
            if self.offset == Self::BLOCK_LEN {
                self.counter = self.counter.wrapping_add(Self::BLOCK_LEN as u64);
                unsafe {
                    transform(&mut self.state, &self.buffer, self.counter, CHUNKS);
                }
                self.offset = 0;
            }

            if self.offset < Self::BLOCK_LEN {
                self.buffer[self.offset] = data[i];
                self.offset += 1;
                i += 1;
            }
        }
    }

    #[inline]
    pub fn finalize(mut self) -> [u8; Self::H_MAX] {
        const LAST: u64 = u32::MAX as u64;

        self.counter = self.counter.wrapping_add(self.offset as u64);

        // Padding
        while self.offset < Self::BLOCK_LEN {
            self.buffer[self.offset] = 0;
            self.offset += 1;
        }

        unsafe {
            // Last Block
            transform(&mut self.state, &self.buffer, self.counter, LAST);

            let mut hash = [0u8; Self::H_MAX]; // 32

            _mm_storeu_si128(hash.as_mut_ptr().add(0) as *mut __m128i, self.state[0]);
            _mm_storeu_si128(hash.as_mut_ptr().add(16) as *mut __m128i, self.state[1]);

            hash
        }
    }

    #[inline]
    pub fn oneshot_hash<T: AsRef<[u8]>>(iv: [u32; 8], data: T) -> [u8; Self::H_MAX] {
        // NOTE: 避免使用流式的方式。
        let data = data.as_ref();

        unsafe {
            let va = _mm_loadu_si128(iv.as_ptr().add(0) as *const __m128i);
            let vb = _mm_loadu_si128(iv.as_ptr().add(4) as *const __m128i);

            let vc = _mm_loadu_si128(BLAKE2S_IV.as_ptr().add(0) as *const __m128i);
            let vd = _mm_loadu_si128(BLAKE2S_IV.as_ptr().add(4) as *const __m128i);

            let mut state = [va, vb, vc, vd];
            let mut counter = 0u64;

            const CHUNKS: u64 = 0;
            const LAST: u64 = u32::MAX as u64;

            let ilen = data.len();

            let n = ilen / Self::BLOCK_LEN;
            let r = ilen % Self::BLOCK_LEN;

            let chunks: &[u8];
            let last_block_len: usize;

            let mut last_block = [0u8; Self::BLOCK_LEN];

            if r > 0 {
                chunks = data;
                last_block[..r].copy_from_slice(&data[ilen - r..]);
                last_block_len = r;
            } else {
                if n > 0 {
                    // NOTE: last_block 是一个完整的 block.
                    debug_assert!(ilen >= Self::BLOCK_LEN);
                    let clen = ilen - Self::BLOCK_LEN;
                    chunks = &data[..clen];
                    last_block.copy_from_slice(&data[clen..]);
                    last_block_len = Self::BLOCK_LEN;
                } else {
                    // Empty input ( Last Block is all zero.)
                    chunks = data;
                    last_block_len = 0;
                }
            };

            for chunk in chunks.chunks_exact(Self::BLOCK_LEN) {
                counter = counter.wrapping_add(Self::BLOCK_LEN as u64);
                transform(&mut state, chunk, counter, CHUNKS);
            }

            counter = counter.wrapping_add(last_block_len as u64);
            transform(&mut state, &last_block, counter, LAST);

            let mut hash = [0u8; Self::H_MAX]; // 32
            _mm_storeu_si128(hash.as_mut_ptr().add(0) as *mut __m128i, state[0]);
            _mm_storeu_si128(hash.as_mut_ptr().add(16) as *mut __m128i, state[1]);

            hash
        }
    }

    pub fn oneshot<T: AsRef<[u8]>>(iv: [u32; 8], key: &[u8], data: T) -> [u8; Self::H_MAX] {
        let mut h = Self::new(iv, key);
        h.update(data.as_ref());
        h.finalize()
    }
}
