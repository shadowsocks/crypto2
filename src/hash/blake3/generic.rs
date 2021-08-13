#![allow(unused_mut, dead_code)]

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

// Table 2: Permutational key schedule for BLAKE3’s keyed permutation.
// 2,  6,  3, 10, 7,  0,  4, 13, 
// 1, 11, 12,  5, 9, 14, 15,  8, 
const SIGMA: [[u8; 16]; 7] = [
    [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15], 
    [ 2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8], 
    [ 3,  4, 10, 12, 13,  2,  7, 14,  6,  5,  9,  0, 11, 15,  8,  1], 
    [10,  7, 12,  9, 14,  3, 13, 15,  4,  0, 11,  2,  5,  8,  1,  6], 
    [12, 13,  9, 11, 15, 10, 14,  8,  7,  2,  5,  3,  0,  1,  6,  4], 
    [ 9, 14, 11,  5,  8, 12, 15,  1, 13,  3,  0, 10,  2,  6,  4,  7], 
    [11, 15,  5,  0,  1,  9,  8,  6, 14, 10,  2, 12,  3,  4,  7, 13], 
];

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 
];


// The mixing function, G, which mixes either a column or a diagonal.
macro_rules! G {
    ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {
        $a = $a.wrapping_add($b).wrapping_add($mx);
        $d = ($d ^ $a).rotate_right(16);

        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_right(12);

        $a = $a.wrapping_add($b).wrapping_add($my);
        $d = ($d ^ $a).rotate_right(8);

        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_right(7);
    }
}

macro_rules! ROUND {
    ($state:tt, $m:tt, $sigma:expr) => {
        // Mix the columns
        G!($state[ 0], $state[ 4], $state[ 8], $state[12],  $m[$sigma[ 0] as usize], $m[$sigma[ 1] as usize]);
        G!($state[ 1], $state[ 5], $state[ 9], $state[13],  $m[$sigma[ 2] as usize], $m[$sigma[ 3] as usize]);
        G!($state[ 2], $state[ 6], $state[10], $state[14],  $m[$sigma[ 4] as usize], $m[$sigma[ 5] as usize]);
        G!($state[ 3], $state[ 7], $state[11], $state[15],  $m[$sigma[ 6] as usize], $m[$sigma[ 7] as usize]);
        // Mix the diagonals
        G!($state[ 0], $state[ 5], $state[10], $state[15],  $m[$sigma[ 8] as usize], $m[$sigma[ 9] as usize]);
        G!($state[ 1], $state[ 6], $state[11], $state[12],  $m[$sigma[10] as usize], $m[$sigma[11] as usize]);
        G!($state[ 2], $state[ 7], $state[ 8], $state[13],  $m[$sigma[12] as usize], $m[$sigma[13] as usize]);
        G!($state[ 3], $state[ 4], $state[ 9], $state[14],  $m[$sigma[14] as usize], $m[$sigma[15] as usize]);
    }
}



#[inline]
fn u32x16_from_le_bytes(bytes: &[u8]) -> [u32; 16] {
    let mut m = [0u32; 16];
    m[ 0] = u32::from_le_bytes([bytes[ 0], bytes[ 1], bytes[ 2], bytes[ 3] ]);
    m[ 1] = u32::from_le_bytes([bytes[ 4], bytes[ 5], bytes[ 6], bytes[ 7] ]);
    m[ 2] = u32::from_le_bytes([bytes[ 8], bytes[ 9], bytes[10], bytes[11] ]);
    m[ 3] = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15] ]);
    m[ 4] = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19] ]);
    m[ 5] = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23] ]);
    m[ 6] = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27] ]);
    m[ 7] = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31] ]);
    m[ 8] = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35] ]);
    m[ 9] = u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39] ]);
    m[10] = u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43] ]);
    m[11] = u32::from_le_bytes([bytes[44], bytes[45], bytes[46], bytes[47] ]);
    m[12] = u32::from_le_bytes([bytes[48], bytes[49], bytes[50], bytes[51] ]);
    m[13] = u32::from_le_bytes([bytes[52], bytes[53], bytes[54], bytes[55] ]);
    m[14] = u32::from_le_bytes([bytes[56], bytes[57], bytes[58], bytes[59] ]);
    m[15] = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63] ]);
    m
}

#[inline]
fn u32x16_to_le_bytes(words: &[u32]) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    bytes[ 0.. 4].copy_from_slice(&words[ 0].to_le_bytes());
    bytes[ 4.. 8].copy_from_slice(&words[ 1].to_le_bytes());
    bytes[ 8..12].copy_from_slice(&words[ 2].to_le_bytes());
    bytes[12..16].copy_from_slice(&words[ 3].to_le_bytes());
    bytes[16..20].copy_from_slice(&words[ 4].to_le_bytes());
    bytes[20..24].copy_from_slice(&words[ 5].to_le_bytes());
    bytes[24..28].copy_from_slice(&words[ 6].to_le_bytes());
    bytes[28..32].copy_from_slice(&words[ 7].to_le_bytes());
    bytes[32..36].copy_from_slice(&words[ 8].to_le_bytes());
    bytes[36..40].copy_from_slice(&words[ 9].to_le_bytes());
    bytes[40..44].copy_from_slice(&words[10].to_le_bytes());
    bytes[44..48].copy_from_slice(&words[11].to_le_bytes());
    bytes[48..52].copy_from_slice(&words[12].to_le_bytes());
    bytes[52..56].copy_from_slice(&words[13].to_le_bytes());
    bytes[56..60].copy_from_slice(&words[14].to_le_bytes());
    bytes[60..64].copy_from_slice(&words[15].to_le_bytes());
    bytes
}

fn transform_half(chaining_value: &[u32; 8], block: &[u32; 16], counter: u64, flags: u32, blen: u32) -> [u32; 8] {
    let mut out = [0u32; 8];
    let state = transform(chaining_value, block, counter, flags, blen);
    out.copy_from_slice(&state[..8]);
    out
}

fn transform_full(chaining_value: &[u32; 8], block: &[u32; 16], counter: u64, flags: u32, blen: u32) -> [u32; 16] {
    transform(chaining_value, block, counter, flags, blen)
}


#[inline]
fn transform(chaining_value: &[u32; 8], block: &[u32; 16], counter: u64, flags: u32, blen: u32) -> [u32; 16] {
    let mut v = [0u32; 16];
    let m = block;

    v[..8].copy_from_slice(&chaining_value[..]);

    v[ 8] = IV[0];
    v[ 9] = IV[1];
    v[10] = IV[2];
    v[11] = IV[3];
    v[12] = counter as u32;         // T0
    v[13] = (counter >> 32) as u32; // T1
    v[14] = blen;                   // F0
    v[15] = flags;                  // F1

    // 7 Rounds
    ROUND!(v, m, SIGMA[0]);
    ROUND!(v, m, SIGMA[1]);
    ROUND!(v, m, SIGMA[2]);
    ROUND!(v, m, SIGMA[3]);
    ROUND!(v, m, SIGMA[4]);
    ROUND!(v, m, SIGMA[5]);
    ROUND!(v, m, SIGMA[6]);

    v[0] ^= v[ 8]; v[ 8] ^= chaining_value[0];
    v[1] ^= v[ 9]; v[ 9] ^= chaining_value[1];
    v[2] ^= v[10]; v[10] ^= chaining_value[2];
    v[3] ^= v[11]; v[11] ^= chaining_value[3];
    v[4] ^= v[12]; v[12] ^= chaining_value[4];
    v[5] ^= v[13]; v[13] ^= chaining_value[5];
    v[6] ^= v[14]; v[14] ^= chaining_value[6];
    v[7] ^= v[15]; v[15] ^= chaining_value[7];

    v
}


struct Node {
    key_words: [u32; 8],
    block_words: [u32; 16],
    block_len: u32,
    counter: u64,
    flags: u32,
}

impl Node {
    pub fn chaining_value(&self) -> [u32; 8] {
        transform_half(&self.key_words, &self.block_words, self.counter, self.flags, self.block_len)
    }

    pub fn root(&mut self, digest: &mut [u8]) {
        let flags = self.flags | ROOT;
        let mut counter = 0u64;

        for out_block in digest.chunks_mut(Blake3::BLOCK_LEN) {
            let state = transform_full(&self.key_words, &self.block_words, counter, flags, self.block_len);
            let stream = u32x16_to_le_bytes(&state);

            let olen = out_block.len();
            out_block.copy_from_slice(&stream[..olen]);
            
            // WARN: 是否使用 wrapping_add 来避免当 输入的数据超出设计范围时的 Panic ?
            counter += 1;
        }
    }
}

#[derive(Clone)]
pub struct Blake3 {
    key: [u32; 8],
    flags: u32,

    buffer: [u8; Blake3::BLOCK_LEN], // block
    offset: usize, // block_len

    chunk_block_counter: usize,
    chunk_counter: u64,
    chunk_chaining_value: [u32; 8],
    chunk_len: usize,

    stack: [[u32; 8]; 54],
    stack_len: usize,
}

impl Blake3 {
    pub const BLOCK_LEN: usize  = 64;
    pub const KEY_LEN: usize    = 32;
    pub const CHUNK_LEN: usize  = 1024;

    const BLOCK_ZERO: [u8; Self::BLOCK_LEN] = [0u8; Self::BLOCK_LEN];
    const CHUNK_LAST_BLOCK_START: usize = Self::CHUNK_LEN - Self::BLOCK_LEN; // 1024 - 64


    #[inline]
    pub fn new() -> Self {
        Self::new_(IV, 0)
    }

    #[inline]
    pub fn with_keyed(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), Self::KEY_LEN);

        let mut iv = [0u32; 8];
        iv[ 0] = u32::from_le_bytes([key[ 0], key[ 1], key[ 2], key[ 3] ]);
        iv[ 1] = u32::from_le_bytes([key[ 4], key[ 5], key[ 6], key[ 7] ]);
        iv[ 2] = u32::from_le_bytes([key[ 8], key[ 9], key[10], key[11] ]);
        iv[ 3] = u32::from_le_bytes([key[12], key[13], key[14], key[15] ]);
        iv[ 4] = u32::from_le_bytes([key[16], key[17], key[18], key[19] ]);
        iv[ 5] = u32::from_le_bytes([key[20], key[21], key[22], key[23] ]);
        iv[ 6] = u32::from_le_bytes([key[24], key[25], key[26], key[27] ]);
        iv[ 7] = u32::from_le_bytes([key[28], key[29], key[30], key[31] ]);

        Self::new_(iv, KEYED_HASH)
    }

    #[inline]
    pub fn new_derive_key<S: AsRef<[u8]>>(context: S) -> Self {
        let context = context.as_ref();

        let mut hasher = Self::new_(IV, DERIVE_KEY_CONTEXT);
        hasher.update(context);

        let mut context_key = [0u8; Self::KEY_LEN];
        hasher.finalize(&mut context_key);

        let mut iv = [0u32; 8];
        iv[ 0] = u32::from_le_bytes([context_key[ 0], context_key[ 1], context_key[ 2], context_key[ 3] ]);
        iv[ 1] = u32::from_le_bytes([context_key[ 4], context_key[ 5], context_key[ 6], context_key[ 7] ]);
        iv[ 2] = u32::from_le_bytes([context_key[ 8], context_key[ 9], context_key[10], context_key[11] ]);
        iv[ 3] = u32::from_le_bytes([context_key[12], context_key[13], context_key[14], context_key[15] ]);
        iv[ 4] = u32::from_le_bytes([context_key[16], context_key[17], context_key[18], context_key[19] ]);
        iv[ 5] = u32::from_le_bytes([context_key[20], context_key[21], context_key[22], context_key[23] ]);
        iv[ 6] = u32::from_le_bytes([context_key[24], context_key[25], context_key[26], context_key[27] ]);
        iv[ 7] = u32::from_le_bytes([context_key[28], context_key[29], context_key[30], context_key[31] ]);

        Self::new_(iv, DERIVE_KEY_MATERIAL)
    }

    #[inline]
    fn new_(key: [u32; 8], flags: u32) -> Self {
        Self {
            key,
            flags,

            buffer: Self::BLOCK_ZERO,
            offset: 0,

            chunk_block_counter: 0,
            chunk_counter: 0,
            chunk_chaining_value: key,
            chunk_len: 0,

            stack: [[0u32; 8]; 54],
            stack_len: 0,
        }
    }

    fn process_block(&mut self) {
        // debug_assert_eq!(block.len(), Self::BLOCK_LEN);
        debug_assert_eq!(self.offset, Self::BLOCK_LEN);

        // Current chunk is complete, finalize it and reset the chunk state.
        if self.chunk_len == Self::CHUNK_LAST_BLOCK_START {
            let block_words = u32x16_from_le_bytes(&self.buffer);
            let counter = self.chunk_counter;
            let blen    = Self::BLOCK_LEN as u32;
            let flags   = if self.chunk_block_counter == 0 { self.flags | CHUNK_START | CHUNK_END } else { self.flags | CHUNK_END };

            // NOTE: 由于 CHUNK_LEN 是 BLOCK_LEN 的倍数，所以此处的 block_len ( buffer offset ) 会为 0;
            //       同时，由于 buffer 会被清空，所以 block words 也会为 zero block.
            let mut new_cv = transform_half(&self.chunk_chaining_value, &block_words, counter, flags, blen);

            // WARN: 是否使用 wrapping_add 来避免当 输入的数据超出设计范围时的 Panic ?
            self.chunk_counter += 1;
            self.chunk_chaining_value = self.key;

            self.chunk_len           = 0;
            self.chunk_block_counter = 0;

            self.offset = 0;
            self.buffer = Self::BLOCK_ZERO;

            let mut total_chunks = self.chunk_counter;
            
            while total_chunks & 1 == 0 {
                self.stack_len -= 1;
                let left_child = self.stack[self.stack_len];

                let mut block_words = [0u32; 16];
                block_words[0.. 8].copy_from_slice(&left_child);
                block_words[8..16].copy_from_slice(&new_cv);

                // NOTE: 
                //      1. Counter always 0 for parent nodes.
                //      2. Always BLOCK_LEN (64) for parent nodes.
                let counter = 0u64;
                let blen = Self::BLOCK_LEN as u32;
                new_cv = transform_half(&self.key, &block_words, counter, self.flags | PARENT, blen);

                total_chunks >>= 1;
            }

            self.stack[self.stack_len] = new_cv;
            self.stack_len += 1;
        } else {
            let words = u32x16_from_le_bytes(&self.buffer);
            let flags = if self.chunk_block_counter == 0 { self.flags | CHUNK_START } else { self.flags };
            let blen = Self::BLOCK_LEN as u32;
            self.chunk_chaining_value = transform_half(&self.chunk_chaining_value, &words, self.chunk_counter, flags, blen);

            self.chunk_len           += Self::BLOCK_LEN;
            self.chunk_block_counter += 1;

            self.offset = 0;
            self.buffer = Self::BLOCK_ZERO;
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;
        while i < data.len() {
            // The block buffer is full, compress input bytes into the current chunk state.
            if self.offset == Self::BLOCK_LEN   {
                self.process_block();
            }

            // Copy input bytes into the block buffer.
            let rlen = data.len() - i;
            let n = core::cmp::min(rlen, Self::BLOCK_LEN - self.offset);
            self.buffer[self.offset..self.offset + n].copy_from_slice(&data[i..i + n]);
            self.offset += n;
            i += n;

            // if self.offset < Self::BLOCK_LEN {
            //     self.buffer[self.offset] = data[i];
            //     self.offset += 1;
            //     i += 1;
            // }
        }
    }

    #[inline]
    pub fn finalize(mut self, digest: &mut [u8]) {
        let block_words = u32x16_from_le_bytes(&self.buffer);
        let flags = if self.chunk_block_counter == 0 { self.flags | CHUNK_START | CHUNK_END  } else { self.flags | CHUNK_END };
        let mut node  = Node {
            key_words: self.chunk_chaining_value,
            block_words: block_words,
            block_len: self.offset as u32,
            counter: self.chunk_counter,
            flags,
        };

        let mut index = self.stack_len;
        while index > 0 {
            index -= 1;

            let left_child  = self.stack[index];
            let right_child = node.chaining_value();

            let mut block_words = [0u32; 16];
            block_words[0.. 8].copy_from_slice(&left_child);
            block_words[8..16].copy_from_slice(&right_child);

            // NOTE: 
            //      1. Counter always 0 for parent nodes.
            //      2. Always BLOCK_LEN (64) for parent nodes.
            node = Node {
                key_words: self.key,
                block_words: block_words,
                block_len: Self::BLOCK_LEN as u32,
                counter: 0,
                flags: self.flags | PARENT,
            };
        }

        node.root(digest);
    }

    pub(crate) fn oneshot_hash_inner<T: AsRef<[u8]>>(data: T, digest: &mut [u8]) {
        let mut hasher = Self::new();
        hasher.update(data.as_ref());
        hasher.finalize(digest);
    }
}
