#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;


// #[cfg(all(not(target_feature = "sse4.1"), target_feature = "sse2"))]
// #[path = "./sse2.rs"]
// mod feature;

#[cfg(target_feature = "sse4.1")]
#[path = "./sse41.rs"]
mod feature;

use self::feature::*;


// pub mod sse2;
// pub mod sse41;


// Table 3: Admissible values for input d in the BLAKE3 compression function.
//     ------------------  ------
//     Flag name           Value
//     ------------------  ------
//     CHUNK_START         2**0
//     CHUNK_END           2**1
//     PARENT              2**2
//     ROOT                2**3
//     KEYED_HASH          2**4
//     DERIVE_KEY_CONTEXT  2**5
//     DERIVE_KEY_MATERIAL 2**6
//     ------------------- ------
const CHUNK_START: u32         =  1;
const CHUNK_END: u32           =  2;
const PARENT: u32              =  4;
const ROOT: u32                =  8;
const KEYED_HASH: u32          = 16;
const DERIVE_KEY_CONTEXT: u32  = 32;
const DERIVE_KEY_MATERIAL: u32 = 64;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 
];


#[derive(Clone)]
pub struct Blake3 {
    initial_flags: u32,
    initial_state: [__m128i; 3],
    
    buf: [u8; Self::BLOCK_LEN],
    offset: usize,

    chunk_len: usize,
    chunk_counter: u64,
    chunk_state: [__m128i; 3],

    stack: [[__m128i; 2]; 54],
    stack_len: usize,
}

impl Blake3 {
    pub const BLOCK_LEN: usize  =  64;
    pub const KEY_LEN: usize    =  32;
    pub const CHUNK_LEN: usize  = 1024;

    const BLOCK_ZERO: [u8; Self::BLOCK_LEN] = [0u8; Self::BLOCK_LEN];
    const CHUNK_LAST_BLOCK_START: usize = Self::CHUNK_LEN - Self::BLOCK_LEN; // 1024 - 64


    #[inline]
    pub fn new() -> Self {
        unsafe {
            let a = _mm_loadu_si128(IV.as_ptr().add(0) as *const __m128i);
            let b = _mm_loadu_si128(IV.as_ptr().add(4) as *const __m128i);
            let c = a;

            Self::new_([a, b, c], 0)
        }
    }

    #[inline]
    pub fn with_keyed(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), Self::KEY_LEN);

        unsafe {
            let a = _mm_loadu_si128(key.as_ptr().add( 0) as *const __m128i);
            let b = _mm_loadu_si128(key.as_ptr().add(16) as *const __m128i);
            let c = _mm_loadu_si128( IV.as_ptr().add( 0) as *const __m128i);

            Self::new_([a, b, c], KEYED_HASH)
        }
    }

    #[inline]
    pub fn new_derive_key<S: AsRef<[u8]>>(context: S) -> Self {
        let context = context.as_ref();

        unsafe {
            let a = _mm_loadu_si128(IV.as_ptr().add(0) as *const __m128i);
            let b = _mm_loadu_si128(IV.as_ptr().add(4) as *const __m128i);
            let c = a;

            let mut context_key = [0u8; Self::KEY_LEN];
            let mut hasher = Self::new_([a, b, c], DERIVE_KEY_CONTEXT);
            hasher.update(context);
            hasher.finalize(&mut context_key);

            let a = _mm_loadu_si128(context_key.as_ptr().add( 0) as *const __m128i);
            let b = _mm_loadu_si128(context_key.as_ptr().add(16) as *const __m128i);

            Self::new_([a, b, c], DERIVE_KEY_MATERIAL)
        }
    }

    #[inline]
    fn new_(initial_state: [__m128i; 3], initial_flags: u32) -> Self {
        unsafe {
            let zero = _mm_setzero_si128();
            Self {
                initial_flags,
                initial_state,
                
                buf: Self::BLOCK_ZERO,
                offset: 0,

                chunk_len: 0,
                chunk_counter: 0u64,
                chunk_state: initial_state,
                
                stack_len: 0,
                stack: [[zero; 2]; 54],
            }
        }
    }
    
    unsafe fn process_block(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        if self.chunk_len == Self::CHUNK_LAST_BLOCK_START {
            // NOTE: 当前 Chunk 的最后一个 BLOCK.
            let state   = &mut self.chunk_state;
            let counter = self.chunk_counter;
            let blen    = Self::BLOCK_LEN as u32;
            let flags   = if self.chunk_len == 0 { self.initial_flags | CHUNK_START | CHUNK_END } else { self.initial_flags | CHUNK_END };
            
            transform_block(state, block, counter, blen, flags);

            let mut chaining_value = [ self.chunk_state[0], self.chunk_state[1] ];

            // NOTE: 重置 Chunk State.
            self.chunk_len      = 0;
            self.chunk_state    = self.initial_state.clone();
            self.chunk_counter += 1; // WARN: 是否使用 wrapping_add 来避免当 输入的数据超出设计范围时的 Panic ?

            // Chainning Value Stack
            let mut total_chunks   = self.chunk_counter;

            while total_chunks & 1 == 0 {
                self.stack_len -= 1;
                let [va, vb] = self.stack[self.stack_len];
                
                let mut state = self.initial_state.clone();
                let words     = [ va, vb, chaining_value[0], chaining_value[1] ];
                let counter   = 0u64;                         // Counter always 0 for parent nodes.
                let blen      = Self::BLOCK_LEN as u32;       // Always BLOCK_LEN (64) for parent nodes.
                let flags     = self.initial_flags | PARENT;

                transform_words(&mut state, &words, counter, blen, flags);

                chaining_value[0] = state[0];
                chaining_value[1] = state[1];

                total_chunks >>= 1;
            }

            self.stack[self.stack_len] = chaining_value;
            self.stack_len += 1;
        } else {
            let state   = &mut self.chunk_state;
            let counter = self.chunk_counter;
            let blen    = Self::BLOCK_LEN as u32;
            let flags   = if self.chunk_len == 0 { self.initial_flags | CHUNK_START | CHUNK_END } else { self.initial_flags | CHUNK_END };

            transform_block(state, block, counter, blen, flags);

            self.chunk_len += Self::BLOCK_LEN;
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;
        while i < data.len() {
            if self.offset == Self::BLOCK_LEN   {
                // The block buffer is full, compress input bytes into the current chunk state.
                unsafe {
                    let block = core::slice::from_raw_parts(self.buf.as_ptr(), Self::BLOCK_LEN);
                    self.process_block(block);
                    // NOTE: 清空缓冲区
                    self.buf    = Self::BLOCK_ZERO;
                    self.offset = 0;
                }
            }

            // Copy input bytes into the block buffer.
            let rlen = data.len() - i;
            let n = core::cmp::min(rlen, Self::BLOCK_LEN - self.offset);
            self.buf[self.offset..self.offset + n].copy_from_slice(&data[i..i + n]);
            self.offset += n;
            i += n;

            // if self.offset < Self::BLOCK_LEN {
            //     self.buf[self.offset] = data[i];
            //     self.offset += 1;
            //     i += 1;
            // }
        }
    }
    
    #[inline]
    pub fn finalize(self, digest: &mut [u8]) {
        unsafe {
            let m0 = _mm_loadu_si128(self.buf.as_ptr().add( 0) as *const __m128i);
            let m1 = _mm_loadu_si128(self.buf.as_ptr().add(16) as *const __m128i);
            let m2 = _mm_loadu_si128(self.buf.as_ptr().add(32) as *const __m128i);
            let m3 = _mm_loadu_si128(self.buf.as_ptr().add(48) as *const __m128i);

            let mut state   = self.chunk_state.clone();
            let mut words   = [m0, m1, m2, m3];
            let mut counter = self.chunk_counter;
            let mut blen    = self.offset as u32;
            let mut flags   = if self.chunk_len == 0 { self.initial_flags | CHUNK_START | CHUNK_END } else { self.initial_flags | CHUNK_END };

            let mut index = self.stack_len;

            while index > 0 {
                index -= 1;

                transform_words(&mut state, &words, counter, blen, flags);

                let [ va ,vb ] = self.stack[index];
                let vc = state[0];
                let vd = state[1];

                // NOTE: 重置状态
                state     = self.initial_state.clone();
                words     = [ va, vb, vc, vd ];
                counter   = 0u64;                         // Counter always 0 for parent nodes.
                blen      = Self::BLOCK_LEN as u32;       // Always BLOCK_LEN (64) for parent nodes.
                flags     = self.initial_flags | PARENT;
            }
            
            // ROOT
            flags = flags | ROOT;

            let [ va ,vb, vc ] = state;
            Self::root(va, vb, vc, &words, blen, flags, digest);
        }
    }
    
    #[inline]
    unsafe fn root(va: __m128i, vb: __m128i, vc: __m128i, words: &[__m128i; 4], blen: u32, flags: u32,  digest: &mut [u8]) {
        let olen = digest.len();

        if olen == 32 {
            // BLAKE3-256
            let counter = 0u64;
            let mut state = [ va, vb, vc ];

            transform_words(&mut state, &words, counter, blen, flags);

            _mm_storeu_si128(digest.as_mut_ptr().add( 0) as *mut __m128i, state[0]);
            _mm_storeu_si128(digest.as_mut_ptr().add(16) as *mut __m128i, state[1]);
        } else if olen == 64 {
            // BLAKE3-512
            let counter = 0u64;
            let mut state = [ va, vb, vc, _mm_setzero_si128() ];

            transform_root_node(&mut state, &words, counter, blen, flags);

            _mm_storeu_si128(digest.as_mut_ptr().add( 0) as *mut __m128i, state[0]);
            _mm_storeu_si128(digest.as_mut_ptr().add(16) as *mut __m128i, state[1]);
            _mm_storeu_si128(digest.as_mut_ptr().add(32) as *mut __m128i, state[2]);
            _mm_storeu_si128(digest.as_mut_ptr().add(48) as *mut __m128i, state[3]);
        } else {
            // Any
            let state = [ va, vb, vc, _mm_setzero_si128() ];
            let mut counter = 0u64;

            let mut out_blocks = digest.chunks_exact_mut(Self::BLOCK_LEN);

            for out_block in &mut out_blocks {
                let mut hash = state.clone();

                transform_root_node(&mut hash, &words, counter, blen, flags);

                _mm_storeu_si128(out_block.as_mut_ptr().add( 0) as *mut __m128i, hash[0]);
                _mm_storeu_si128(out_block.as_mut_ptr().add(16) as *mut __m128i, hash[1]);
                _mm_storeu_si128(out_block.as_mut_ptr().add(32) as *mut __m128i, hash[2]);
                _mm_storeu_si128(out_block.as_mut_ptr().add(48) as *mut __m128i, hash[3]);
                // WARN: 在 64 位硬件平台上，counter 永远不会出现溢出的情况。
                //       在 32 位硬件平台上，当要输出的 Digest 长度足够大时，counter 会溢出。
                counter += 1;
            }

            // Last digest
            let rem  = out_blocks.into_remainder();
            let rlen = rem.len();
            if rlen > 0 {
                let mut hash = state.clone();

                transform_root_node(&mut hash, &words, counter, blen, flags);

                let mut buf = Self::BLOCK_ZERO;
                _mm_storeu_si128(buf.as_mut_ptr().add( 0) as *mut __m128i, hash[0]);
                _mm_storeu_si128(buf.as_mut_ptr().add(16) as *mut __m128i, hash[1]);
                _mm_storeu_si128(buf.as_mut_ptr().add(32) as *mut __m128i, hash[2]);
                _mm_storeu_si128(buf.as_mut_ptr().add(48) as *mut __m128i, hash[3]);
                rem.copy_from_slice(&buf[..rlen]);
            }
        }
    }

    pub fn oneshot_hash<T: AsRef<[u8]>>(data: T, digest: &mut [u8]) {
        unsafe {
            let va = _mm_loadu_si128(IV.as_ptr().add(0) as *const __m128i);
            let vb = _mm_loadu_si128(IV.as_ptr().add(4) as *const __m128i);
            let vc = va;

            let initial_state = [ va, vb, vc ];
            let initial_flags = 0u32;

            Self::oneshot_inner(initial_state, initial_flags, data, digest);
        }
    }

    pub fn oneshot_keyed_hash<K: AsRef<[u8]>, T: AsRef<[u8]>>(key: K, data: T, digest: &mut [u8]) {
        let key = key.as_ref();

        debug_assert_eq!(key.len(), Self::KEY_LEN);

        unsafe {
            let va = _mm_loadu_si128(key.as_ptr().add( 0) as *const __m128i);
            let vb = _mm_loadu_si128(key.as_ptr().add(16) as *const __m128i);
            let vc = _mm_loadu_si128( IV.as_ptr().add( 0) as *const __m128i);

            let initial_state = [ va, vb, vc ];
            let initial_flags = KEYED_HASH;

            Self::oneshot_inner(initial_state, initial_flags, data, digest);
        }
    }

    pub fn oneshot_derive_key<S: AsRef<[u8]>, T: AsRef<[u8]>>(context: S, data: T, digest: &mut [u8]) {
        unsafe {
            let va = _mm_loadu_si128(IV.as_ptr().add(0) as *const __m128i);
            let vb = _mm_loadu_si128(IV.as_ptr().add(4) as *const __m128i);
            let vc = va;

            let initial_state = [ va, vb, vc ];
            let initial_flags = DERIVE_KEY_CONTEXT;

            let mut context_key = [0u8; Self::KEY_LEN];
            Self::oneshot_inner(initial_state, initial_flags, context, &mut context_key);


            let va = _mm_loadu_si128(context_key.as_ptr().add( 0) as *const __m128i);
            let vb = _mm_loadu_si128(context_key.as_ptr().add(16) as *const __m128i);

            let initial_state = [ va, vb, vc ];
            let initial_flags = DERIVE_KEY_MATERIAL;

            Self::oneshot_inner(initial_state, initial_flags, data, digest);
        }
    }

    #[inline]
    unsafe fn oneshot_inner<T: AsRef<[u8]>>(initial_state: [__m128i; 3], initial_flags: u32, data: T, digest: &mut [u8]) {
        let data = data.as_ref();
        let ilen = data.len();

        if ilen <= Self::CHUNK_LEN {
            // NOTE: 快速计算小数据。
            let va = _mm_loadu_si128(IV.as_ptr().add(0) as *const __m128i);
            let vb = _mm_loadu_si128(IV.as_ptr().add(4) as *const __m128i);
            let vc = va;

            let initial_flags = 0u32;
            let mut state = [ va, vb, vc ];
            let mut chunk_len = 0usize;

            let mut rlen = ilen;
            let mut ptr = data.as_ptr();
            while rlen > Self::BLOCK_LEN {
                let block = core::slice::from_raw_parts(ptr, Self::BLOCK_LEN);
                let counter   = 0;
                let blen      = Self::BLOCK_LEN as u32;
                let flags     = if chunk_len == 0 { initial_flags | CHUNK_START } else { initial_flags };

                transform_block(&mut state, block, counter, blen, flags);

                ptr        = ptr.add(Self::BLOCK_LEN);
                rlen      -= Self::BLOCK_LEN;
                chunk_len += Self::BLOCK_LEN;
            }

            let mut last_block = Self::BLOCK_ZERO;
            if rlen > 0 {
                let rem = core::slice::from_raw_parts(ptr, rlen);
                last_block[..rlen].copy_from_slice(rem);
            }

            let m0 = _mm_loadu_si128(last_block.as_ptr().add( 0) as *const __m128i);
            let m1 = _mm_loadu_si128(last_block.as_ptr().add(16) as *const __m128i);
            let m2 = _mm_loadu_si128(last_block.as_ptr().add(32) as *const __m128i);
            let m3 = _mm_loadu_si128(last_block.as_ptr().add(48) as *const __m128i);

            // ROOT
            let blen  = rlen as u32;
            let flags = if chunk_len == 0 { initial_flags | CHUNK_START | CHUNK_END | ROOT  } else { initial_flags | CHUNK_END | ROOT };
            let words = [m0, m1, m2, m3];

            let [ va ,vb, vc ] = state;
            
            Self::root(va, vb, vc, &words, blen, flags, digest);
        } else {
            // NOTE: 长度大于 1 个 Chunk 大小的数据会略慢。
            let mut m = Self::new_(initial_state, initial_flags);

            // NOTE: 手动 .update 避免数据复制。
            let mut rlen = ilen;
            let mut ptr = data.as_ptr();
            while rlen > Self::BLOCK_LEN {
                let block = core::slice::from_raw_parts(ptr, Self::BLOCK_LEN);
                m.process_block(block);
                ptr = ptr.add(Self::BLOCK_LEN);
                rlen -= Self::BLOCK_LEN;
            }

            if rlen > 0 {
                let rem = core::slice::from_raw_parts(ptr, rlen);
                m.buf[..rlen].copy_from_slice(rem);
                m.offset = rlen;
            }

            m.finalize(digest);
        }
    }
}



