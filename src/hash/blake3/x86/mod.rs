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
    initial_flags: u32,                // 初始 FLAG
    initial_state: [__m128i; 4],       // Chunk 的初始状态数据

    buf: [u8; Blake3::BLOCK_LEN],      // block
    offset: usize,                     // block_len
    
    chunk_state: [__m128i; 4],         // Chunk Chainning Value
    chunk_len: usize,                  // Chunk 内部总共已完成计算的输入数据大小
    chunk_counter: u64,                // 已计算完毕的 Chunk 数量

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
            let d = _mm_setzero_si128();

            let initial_state = [a, b, c, d];

            Self::new_(initial_state, 0)
        }
    }

    #[inline]
    pub fn with_keyed(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), Self::KEY_LEN);

        unsafe {
            let a = _mm_loadu_si128(key.as_ptr().add( 0) as *const __m128i);
            let b = _mm_loadu_si128(key.as_ptr().add(16) as *const __m128i);
            let c = _mm_loadu_si128(IV.as_ptr().add( 0) as *const __m128i);
            let d = _mm_setzero_si128();

            let initial_state = [a, b, c, d];

            Self::new_(initial_state, KEYED_HASH)
        }
    }

    #[inline]
    pub fn new_derive_key<S: AsRef<[u8]>>(context: S) -> Self {
        let context = context.as_ref();

        unsafe {
            let a = _mm_loadu_si128(IV.as_ptr().add(0) as *const __m128i);
            let b = _mm_loadu_si128(IV.as_ptr().add(4) as *const __m128i);
            let c = a;
            let d = _mm_setzero_si128();

            let initial_state = [a, b, c, d];
            
            let mut hasher = Self::new_(initial_state, DERIVE_KEY_CONTEXT);
            hasher.update(context);

            let mut context_key = [0u8; Self::KEY_LEN];
            hasher.finalize(&mut context_key);

            let a = _mm_loadu_si128(context_key.as_ptr().add( 0) as *const __m128i);
            let b = _mm_loadu_si128(context_key.as_ptr().add(16) as *const __m128i);

            let initial_state = [a, b, c, d];

            Self::new_(initial_state, DERIVE_KEY_MATERIAL)
        }
    }

    #[inline]
    fn new_(initial_state: [__m128i; 4], initial_flags: u32) -> Self {
        unsafe {
            let zero = _mm_setzero_si128();
            Self {
                initial_flags,
                initial_state,
                
                buf: Self::BLOCK_ZERO,
                offset: 0,

                chunk_state: initial_state,
                chunk_len: 0,
                chunk_counter: 0,

                stack: [[zero; 2]; 54],
                stack_len: 0,
            }
        }
    }

    unsafe fn process_block(&mut self) {
        debug_assert_eq!(self.offset, Self::BLOCK_LEN);

        if self.chunk_len == Self::CHUNK_LAST_BLOCK_START {
            // NOTE: 当前 Chunk 的最后一个 BLOCK.
            let block     = &self.buf;
            let counter   = self.chunk_counter;
            let blen      = Self::BLOCK_LEN as u32;
            let flags     = if self.chunk_len == 0 { self.initial_flags | CHUNK_START | CHUNK_END } else { self.initial_flags | CHUNK_END };

            chaining_value_transform(&mut self.chunk_state, &block, counter, flags, blen);

            let mut chaining_value = [ self.chunk_state[0], self.chunk_state[1] ];

            self.buf            = Self::BLOCK_ZERO;
            self.offset         = 0;
            self.chunk_len      = 0;
            self.chunk_state    = self.initial_state.clone();
            self.chunk_counter += 1; // WARN: 是否使用 wrapping_add 来避免当 输入的数据超出设计范围时的 Panic ?
            
            // Chainning Value Stack
            let mut total_chunks = self.chunk_counter;
                
            while total_chunks & 1 == 0 {
                self.stack_len -= 1;
                let left_child = self.stack[self.stack_len];
                
                let words     = [ left_child[0], left_child[1], chaining_value[0], chaining_value[1] ];
                let block     = core::mem::transmute(words);  // NOTE: 此处的转换不会有安全问题。
                let counter   = 0u64;                         // Counter always 0 for parent nodes.
                let blen      = Self::BLOCK_LEN as u32;       // Always BLOCK_LEN (64) for parent nodes.
                let flags     = self.initial_flags | PARENT;

                let mut state = self.initial_state.clone();   // ParentNode 使用初始 state.
                chaining_value_transform(&mut state, &block, counter, flags, blen);
                chaining_value[0] = state[0];
                chaining_value[1] = state[1];

                total_chunks >>= 1;
            }

            self.stack[self.stack_len] = chaining_value;
            self.stack_len += 1;
        } else {
            let block     = &self.buf;
            let counter   = self.chunk_counter;
            let blen      = Self::BLOCK_LEN as u32;
            let flags     = if self.chunk_len == 0 { self.initial_flags | CHUNK_START } else { self.initial_flags };

            chaining_value_transform(&mut self.chunk_state, &block, counter, flags, blen);

            self.buf        = Self::BLOCK_ZERO;
            self.offset     = 0;
            self.chunk_len += Self::BLOCK_LEN;
            self.chunk_state[2] = self.initial_state[2]; // NOTE: 复位 IV 前半部分（也就是 VA）。
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;
        while i < data.len() {
            if self.offset == Self::BLOCK_LEN   {
                // The block buffer is full, compress input bytes into the current chunk state.
                unsafe { self.process_block(); }
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

    // #[inline]
    pub fn finalize(self, digest: &mut [u8]) {
        unsafe {
            let mut block     = self.buf;
            let mut counter   = self.chunk_counter;
            let mut blen      = self.offset as u32;
            let mut flags     = if self.chunk_len == 0 { self.initial_flags | CHUNK_START | CHUNK_END } else { self.initial_flags | CHUNK_END };
            let mut state     = self.chunk_state;

            let mut index = self.stack_len;

            while index > 0 {
                index -= 1;

                let left_child  = self.stack[index];

                chaining_value_transform(&mut state, &block, counter, flags, blen);

                let words = [ left_child[0], left_child[1], state[0], state[1] ];

                block     = core::mem::transmute(words);  // NOTE: 此处的转换不会有安全问题。
                counter   = 0u64;                         // Counter always 0 for parent nodes.
                blen      = Self::BLOCK_LEN as u32;       // Always BLOCK_LEN (64) for parent nodes.
                flags     = self.initial_flags | PARENT;
                state     = self.initial_state.clone();
            }
            
            // ROOT
            counter = 0u64;
            flags   = flags | ROOT;

            if digest.len() == 32 {
                // BLAKE3-256
                chaining_value_transform(&mut state, &block, counter, flags, blen);
                
                _mm_storeu_si128(digest.as_mut_ptr().add( 0) as *mut __m128i, state[0]);
                _mm_storeu_si128(digest.as_mut_ptr().add(16) as *mut __m128i, state[1]);
            } else if digest.len() == 64 {
                // BLAKE3-512
                root_transform(&mut state, &block, counter, flags, blen);

                _mm_storeu_si128(digest.as_mut_ptr().add( 0) as *mut __m128i, state[0]);
                _mm_storeu_si128(digest.as_mut_ptr().add(16) as *mut __m128i, state[1]);
                _mm_storeu_si128(digest.as_mut_ptr().add(32) as *mut __m128i, state[2]);
                _mm_storeu_si128(digest.as_mut_ptr().add(48) as *mut __m128i, state[3]);
            } else {
                for out_block in digest.chunks_mut(Self::BLOCK_LEN) {
                    let mut hash = state.clone();
                    root_transform(&mut hash, &block, counter, flags, blen);

                    let mut keystream = [0u8; 64];
                    _mm_storeu_si128(keystream.as_mut_ptr().add( 0) as *mut __m128i, hash[0]);
                    _mm_storeu_si128(keystream.as_mut_ptr().add(16) as *mut __m128i, hash[1]);
                    _mm_storeu_si128(keystream.as_mut_ptr().add(32) as *mut __m128i, hash[2]);
                    _mm_storeu_si128(keystream.as_mut_ptr().add(48) as *mut __m128i, hash[3]);
                    
                    let olen = out_block.len();
                    out_block.copy_from_slice(&keystream[..olen]);
                    
                    // WARN: 是否使用 wrapping_add 来避免当 输入的数据超出设计范围时的 Panic ?
                    counter += 1;
                }
            }
        }
    }

    pub(crate) fn oneshot_hash_inner<T: AsRef<[u8]>>(data: T, digest: &mut [u8]) {
        let data = data.as_ref();
        let ilen = data.len();
        
        unsafe {
            if ilen <= Self::CHUNK_LEN {
                // NOTE: 当输入数据 <= CHUNK_LEN 时，避免 CV-STACK 的开销。
                let n = ilen / Self::BLOCK_LEN;
                let r = ilen % Self::BLOCK_LEN;

                let chunks: &[u8];
                let remainder: &[u8];
                
                if r > 0 {
                    chunks = data;
                    remainder = &data[ilen - r..];
                } else {
                    if n > 0 {
                        // NOTE: last_block 是一个完整的 block.
                        debug_assert!(ilen >= Self::BLOCK_LEN);
                        let clen = ilen - Self::BLOCK_LEN;
                        chunks = &data[..clen];
                        remainder = &data[clen..];
                    } else {
                        // Empty input ( Last Block is all zero.)
                        chunks = data;
                        remainder = data;
                    }
                };

                let a = _mm_loadu_si128(IV.as_ptr().add(0) as *const __m128i);
                let b = _mm_loadu_si128(IV.as_ptr().add(4) as *const __m128i);
                let c = a;
                let d = _mm_setzero_si128();

                let initial_flags = 0u32;

                let mut state = [a, b, c, d];
                let mut chunk_len = 0usize;
                let mut buf = [0u8; 64];

                for chunk in chunks.chunks_exact(Self::BLOCK_LEN) {
                    buf.copy_from_slice(chunk);

                    let block     = core::mem::transmute(buf);
                    let counter   = 0;
                    let blen      = Self::BLOCK_LEN as u32;
                    let flags     = if chunk_len == 0 { initial_flags | CHUNK_START } else { initial_flags };

                    chaining_value_transform(&mut state, &block, counter, flags, blen);

                    chunk_len += Self::BLOCK_LEN;
                    state[2]   = c; // NOTE: 复位 IV 前半部分（也就是 VA）。
                }


                let rlen = remainder.len();
                let mut last_block = [0u8; 64];

                if remainder.len() > 0 {
                    last_block[..rlen].copy_from_slice(remainder);
                }

                let block     = &last_block;
                let blen      = rlen as u32;
                let flags     = if chunk_len == 0 { initial_flags | CHUNK_START | CHUNK_END  } else { initial_flags | CHUNK_END };

                // ROOT
                let counter = 0u64;
                let flags = flags | ROOT;

                if digest.len() == 32 {
                    // BLAKE3-256
                    chaining_value_transform(&mut state, &block, counter, flags, blen);
                    
                    _mm_storeu_si128(digest.as_mut_ptr().add( 0) as *mut __m128i, state[0]);
                    _mm_storeu_si128(digest.as_mut_ptr().add(16) as *mut __m128i, state[1]);
                } else if digest.len() == 64 {
                    // BLAKE3-512
                    root_transform(&mut state, &block, counter, flags, blen);

                    _mm_storeu_si128(digest.as_mut_ptr().add( 0) as *mut __m128i, state[0]);
                    _mm_storeu_si128(digest.as_mut_ptr().add(16) as *mut __m128i, state[1]);
                    _mm_storeu_si128(digest.as_mut_ptr().add(32) as *mut __m128i, state[2]);
                    _mm_storeu_si128(digest.as_mut_ptr().add(48) as *mut __m128i, state[3]);
                } else {
                    let mut counter = 0u64;

                    for out_block in digest.chunks_mut(Self::BLOCK_LEN) {
                        let mut hash = state.clone();
                        root_transform(&mut hash, &block, counter, flags, blen);

                        let mut keystream = [0u8; 64];
                        _mm_storeu_si128(keystream.as_mut_ptr().add( 0) as *mut __m128i, hash[0]);
                        _mm_storeu_si128(keystream.as_mut_ptr().add(16) as *mut __m128i, hash[1]);
                        _mm_storeu_si128(keystream.as_mut_ptr().add(32) as *mut __m128i, hash[2]);
                        _mm_storeu_si128(keystream.as_mut_ptr().add(48) as *mut __m128i, hash[3]);
                        
                        let olen = out_block.len();
                        out_block.copy_from_slice(&keystream[..olen]);
                        
                        // WARN: 是否使用 wrapping_add 来避免当 输入的数据超出设计范围时的 Panic ?
                        counter += 1;
                    }
                }
                return ();
            }

            // NOTE: 长度大于 1 个 Chunk 大小的数据会略慢。
            let mut m = Self::new();
            m.update(data);
            m.finalize(digest);
        }
    }
}



