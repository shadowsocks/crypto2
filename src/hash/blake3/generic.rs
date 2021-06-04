#![allow(unused_mut, dead_code)]

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 
];

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
    ($state:tt, $m:tt) => {
        // Mix the columns
        G!($state[ 0], $state[ 4], $state[ 8], $state[12],  $m[ 0], $m[ 1]);
        G!($state[ 1], $state[ 5], $state[ 9], $state[13],  $m[ 2], $m[ 3]);
        G!($state[ 2], $state[ 6], $state[10], $state[14],  $m[ 4], $m[ 5]);
        G!($state[ 3], $state[ 7], $state[11], $state[15],  $m[ 6], $m[ 7]);
        // Mix the diagonals
        G!($state[ 0], $state[ 5], $state[10], $state[15],  $m[ 8], $m[ 9]);
        G!($state[ 1], $state[ 6], $state[11], $state[12],  $m[10], $m[11]);
        G!($state[ 2], $state[ 7], $state[ 8], $state[13],  $m[12], $m[13]);
        G!($state[ 3], $state[ 4], $state[ 9], $state[14],  $m[14], $m[15]);
    }
}

macro_rules! ROUND_AND_SHUFFLE {
    ($state:tt, $m:tt, $m_copy:tt) => {
        ROUND!($state, $m);

        // Table 2: Permutational key schedule for BLAKE3’s keyed permutation.
        // 2,  6,  3, 10, 7,  0,  4, 13, 
        // 1, 11, 12,  5, 9, 14, 15,  8, 
        $m_copy[ 0] = $m[ 2];
        $m_copy[ 1] = $m[ 6];
        $m_copy[ 2] = $m[ 3];
        $m_copy[ 3] = $m[10];
        $m_copy[ 4] = $m[ 7];
        $m_copy[ 5] = $m[ 0];
        $m_copy[ 6] = $m[ 4];
        $m_copy[ 7] = $m[13];
        $m_copy[ 8] = $m[ 1];
        $m_copy[ 9] = $m[11];
        $m_copy[10] = $m[12];
        $m_copy[11] = $m[ 5];
        $m_copy[12] = $m[ 9];
        $m_copy[13] = $m[14];
        $m_copy[14] = $m[15];
        $m_copy[15] = $m[ 8];
    }
}

macro_rules! ROUNDS {
    ($state:tt, $m:tt, $m_copy:tt) => {
        // println!("        state: {:?}", &$state);
        // Round-1
        ROUND_AND_SHUFFLE!($state, $m, $m_copy);

        // println!("        state: {:?}", &$state);
        // Round-2
        ROUND_AND_SHUFFLE!($state, $m_copy, $m);

        // Round-3
        ROUND_AND_SHUFFLE!($state, $m, $m_copy);
        // Round-4
        ROUND_AND_SHUFFLE!($state, $m_copy, $m);

        // Round-5
        ROUND_AND_SHUFFLE!($state, $m, $m_copy);
        // Round-6
        ROUND_AND_SHUFFLE!($state, $m_copy, $m);
        
        // Round-7
        ROUND!($state, $m);
    }
}

#[inline]
fn u32x8_from_le_bytes(bytes: &[u8]) -> [u32; 8] {
    let mut m = [0u32; 8];
    m[ 0] = u32::from_le_bytes([bytes[ 0], bytes[ 1], bytes[ 2], bytes[ 3] ]);
    m[ 1] = u32::from_le_bytes([bytes[ 4], bytes[ 5], bytes[ 6], bytes[ 7] ]);
    m[ 2] = u32::from_le_bytes([bytes[ 8], bytes[ 9], bytes[10], bytes[11] ]);
    m[ 3] = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15] ]);
    m[ 4] = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19] ]);
    m[ 5] = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23] ]);
    m[ 6] = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27] ]);
    m[ 7] = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31] ]);
    m
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

#[inline]
fn transform(chaining_value: &[u32; 8], block: &[u32; 16], block_len: usize, counter: u64, flags: u32) -> [u32; 16] {
    let mut m = block.clone();
    let mut v = [0u32; 16];
    let mut m_copy = [0u32; 16];

    v[..8].copy_from_slice(&chaining_value[..]);

    v[ 8] = IV[0];
    v[ 9] = IV[1];
    v[10] = IV[2];
    v[11] = IV[3];
    v[12] = counter as u32;         // ^ T0
    v[13] = (counter >> 32) as u32; // ^ T1
    v[14] = block_len as u32;
    v[15] = flags;

    // 7 Rounds
    ROUNDS!(v, m, m_copy);

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


#[cfg(test)]
#[bench]
fn bench_blake3_transform(b: &mut test::Bencher) {
    let key   = [7u32; 8];
    let block = [9u32; 16];
    let block_len = 64;
    let counter = 1;
    let flags = 4;

    b.iter(|| {
        transform(&key, &block, block_len, counter, flags)
    })
}



#[cfg(test)]
#[bench]
fn bench_blake3_u32x16_from_le_bytes(b: &mut test::Bencher) {
    let bytes = [1u8; 64];

    b.iter(|| {
        u32x16_from_le_bytes(&bytes)
    })
}


// 2.5 Parent Node Chaining Values
// 
// Each parent node has exactly two children, 
// each either a chunk or another parent node. 
// 
// The chaining value of each parent node is given by a single call to the compression function. 
// The input chaining value h0 ... h7 is the key words k0 ... k7. 
// The message words m0 ... m7 are the chaining value of the left child, 
// and the message words m8 ... m15 are the chaining value of the right child.
#[derive(Clone)]
struct ParentNode {
    key_words: [u32; 8],
    block_words: [u32; 16],
    flags: u32,
}

impl ParentNode {
    pub fn new(key_words: [u32; 8], left_child: &[u32; 8], right_child: &[u32; 8], flags: u32) -> Self {
        let mut block_words = [0u32; 16];
        block_words[0.. 8].copy_from_slice(left_child);
        block_words[8..16].copy_from_slice(right_child);

        Self {
            key_words,
            block_words,
            flags: flags | PARENT,
        }
    }

    pub fn chaining_value(self) -> [u32; 8] {
        // NOTE: 
        //      1. Counter always 0 for parent nodes.
        //      2. Always BLOCK_LEN (64) for parent nodes.
        let out = transform(&self.key_words, &self.block_words, Blake3::BLOCK_LEN, 0, self.flags);
        let mut cv = [0u32; 8];
        cv.copy_from_slice(&out[..8]);
        cv
    }

    pub fn root_node(&self) -> RootNode {
        RootNode {
            key_words: self.key_words,
            block_words: self.block_words,
            block_len: Blake3::BLOCK_LEN,
            flags: self.flags,
        }
    }
}


#[derive(Clone)]
struct RootNode {
    key_words: [u32; 8],
    block_words: [u32; 16],
    block_len: usize,
    flags: u32,
}

impl RootNode {
    pub fn root(mut self, out_slice: &mut [u8]) {
        let flags       = self.flags | ROOT;

        let mut counter = 0u64;
        for out_block in out_slice.chunks_mut(Blake3::BLOCK_LEN) {
            let state = transform(&self.key_words, &self.block_words, self.block_len, counter, flags);
            let stream = u32x16_to_le_bytes(&state);

            let olen = out_block.len();
            out_block.copy_from_slice(&stream[..olen]);
            // if out_block.len() == Blake3::BLOCK_LEN {
            //     out_block.copy_from_slice(&stream);
            // } else {
                
            // }
            
            counter += 1;
        }
    }
}

struct Node {
    key_words: [u32; 8],
    block_words: [u32; 16],
    block_len: usize,
    counter: u64,
    flags: u32,
}

impl Node {
    pub fn chaining_value(&self) -> [u32; 8] {
        let out = transform(&self.key_words, &self.block_words, self.block_len, self.counter, self.flags);
        let mut cv = [0u32; 8];
        cv.copy_from_slice(&out[..8]);
        cv
    }

    pub fn root(&mut self, digest: &mut [u8]) {
        // let mut node = RootNode {
        //     key_words: self.key_words,
        //     block_words: self.block_words,
        //     block_len: self.block_len,
        //     flags: self.flags,
        // };
        // node.root(digest);

        let flags       = self.flags | ROOT;

        let mut counter = 0u64;
        for out_block in digest.chunks_mut(Blake3::BLOCK_LEN) {
            let state = transform(&self.key_words, &self.block_words, self.block_len, counter, flags);
            let stream = u32x16_to_le_bytes(&state);

            let olen = out_block.len();
            out_block.copy_from_slice(&stream[..olen]);
            // if out_block.len() == Blake3::BLOCK_LEN {
            //     out_block.copy_from_slice(&stream);
            // } else {
                
            // }
            
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
    pub const DIGEST_LEN: usize = 32;

    pub const KEY_LEN: usize    = 32;
    pub const CHUNK_LEN: usize  = 1024;

    const BLOCK_ZERO: [u8; Self::BLOCK_LEN] = [0u8; Self::BLOCK_LEN];


    pub fn new() -> Self {
        Self::new_(IV, 0)
    }

    pub fn with_keyed(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), Self::KEY_LEN);

        Self::new_(u32x8_from_le_bytes(key), KEYED_HASH)
    }

    pub fn new_derive_key<S: AsRef<[u8]>>(context: S) -> Self {
        let context = context.as_ref();

        let mut hasher = Self::new_(IV, DERIVE_KEY_CONTEXT);
        hasher.update(context);

        let mut context_key = [0u8; Self::KEY_LEN];
        hasher.finalize(&mut context_key);

        let key_words = u32x8_from_le_bytes(&context_key);

        Self::new_(key_words, DERIVE_KEY_MATERIAL)
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

    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;
        while i < data.len() {
            // the block buffer is full, compress input bytes into the current chunk state.
            if self.offset == Self::BLOCK_LEN   {
                // current chunk is complete, finalize it and reset the chunk state.
                const LEN: usize = 1024 - 64;
                if self.chunk_len == LEN {
                    let block_words = u32x16_from_le_bytes(&self.buffer);
                    let block_len   = Self::BLOCK_LEN;
                    let counter     = self.chunk_counter;
                    let flags = if self.chunk_block_counter == 0 { self.flags | CHUNK_START | CHUNK_END } else { self.flags | CHUNK_END };

                    // NOTE: 由于 CHUNK_LEN 是 BLOCK_LEN 的倍数，所以此处的 block_len ( buffer offset ) 会为 0;
                    //       同时，由于 buffer 会被清空，所以 block words 也会为 zero block.
                    let state = transform(&self.chunk_chaining_value, &block_words, block_len, counter, flags);
                    
                    let mut new_cv = [0u32; 8];
                    new_cv.copy_from_slice(&state[..8]);

                    // wrapping_add ?
                    self.chunk_counter += 1;
                    self.chunk_chaining_value = self.key;

                    self.chunk_len           = 0;
                    self.chunk_block_counter = 0;

                    self.offset = 0;
                    self.buffer = Self::BLOCK_ZERO;

                    
                    let mut total_chunks = self.chunk_counter;
                    // let mut new_cv = right_child;
                    
                    while total_chunks & 1 == 0 {
                        self.stack_len -= 1;

                        let left_child = self.stack[self.stack_len];
                        // let right_child = new_cv;
                        // new_cv = ParentNode::new(self.key, &left_child, &new_cv, self.flags).chaining_value();
                        let mut block_words = [0u32; 16];
                        block_words[0.. 8].copy_from_slice(&left_child);
                        block_words[8..16].copy_from_slice(&new_cv);

                        // NOTE: 
                        //      1. Counter always 0 for parent nodes.
                        //      2. Always BLOCK_LEN (64) for parent nodes.
                        let out = transform(&self.key, &block_words, Blake3::BLOCK_LEN, 0, self.flags | PARENT);
                        // let mut cv = [0u32; 8];
                        new_cv.copy_from_slice(&out[..8]);

                        total_chunks >>= 1;
                    }

                    self.stack[self.stack_len] = new_cv;
                    self.stack_len += 1;
                } else {
                    let flags = if self.chunk_block_counter == 0 { self.flags | CHUNK_START } else { self.flags };
                    let words = u32x16_from_le_bytes(&self.buffer);
                    let state = transform(&self.chunk_chaining_value, &words, Self::BLOCK_LEN, self.chunk_counter, flags);

                    self.chunk_chaining_value.copy_from_slice(&state[..8]);
                    self.chunk_len           += Self::BLOCK_LEN;
                    self.chunk_block_counter += 1;

                    self.offset = 0;
                    self.buffer = Self::BLOCK_ZERO;
                }
            }

            // Copy input bytes into the block buffer.            
            if self.offset < Self::BLOCK_LEN {
                self.buffer[self.offset] = data[i];
                self.offset += 1;
                i += 1;
            }
        }
    }

    pub fn finalize(mut self, digest: &mut [u8]) {
        let block_words = u32x16_from_le_bytes(&self.buffer);
        let flags = if self.chunk_block_counter == 0 { self.flags | CHUNK_START | CHUNK_END  } else { self.flags | CHUNK_END };
        let mut node  = Node {
            key_words: self.chunk_chaining_value,
            block_words: block_words,
            block_len: self.offset,
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

            node = Node {
                key_words: self.key,
                block_words: block_words,
                block_len: Self::BLOCK_LEN,
                counter: 0,
                flags: self.flags | PARENT,
            };
        }

        node.root(digest);
    }
}
