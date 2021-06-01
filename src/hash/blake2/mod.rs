// BLAKE2: simpler, smaller, fast as MD5
// https://www.blake2.net/blake2.pdf
// 
// The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)
// https://datatracker.ietf.org/doc/html/rfc7693
// 
// BLAKE2 comes in two basic flavors:
// 
//     o  BLAKE2b (or just BLAKE2) is optimized for 64-bit platforms and
//        produces digests of any size between 1 and 64 bytes.
// 
//     o  BLAKE2s is optimized for 8- to 32-bit platforms and produces
//        digests of any size between 1 and 32 bytes.
// 
// Both BLAKE2b and BLAKE2s are believed to be highly secure and perform
// well on any platform, software, or hardware.  BLAKE2 does not require
// a special "HMAC" (Hashed Message Authentication Code) construction
// for keyed message authentication as it has a built-in keying mechanism.
// 
// 
// 2.1.  Parameters
// https://datatracker.ietf.org/doc/html/rfc7693#section-2.1
// 
//    The following table summarizes various parameters and their ranges:
// 
//                             | BLAKE2b          | BLAKE2s          |
//               --------------+------------------+------------------+
//                Bits in word | w = 64           | w = 32           |
//                Rounds in F  | r = 12           | r = 10           |
//                Block bytes  | bb = 128         | bb = 64          |
//                Hash bytes   | 1 <= nn <= 64    | 1 <= nn <= 32    |
//                Key bytes    | 0 <= kk <= 64    | 0 <= kk <= 32    |
//                Input bytes  | 0 <= ll < 2**128 | 0 <= ll < 2**64  |
//               --------------+------------------+------------------+
//                G Rotation   | (R1, R2, R3, R4) | (R1, R2, R3, R4) |
//                 constants = | (32, 24, 16, 63) | (16, 12,  8,  7) |
//               --------------+------------------+------------------+




// static const uint64_t blake2b_IV[8] =
// {
//   0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
//   0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
//   0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
//   0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
// };

// typedef struct blake2b_state__ {
//     uint64_t h[8];
//     uint64_t t[2];
//     uint64_t f[2];
//     uint8_t  buf[BLAKE2B_BLOCKBYTES];
//     size_t   buflen;
//     size_t   outlen;
//     uint8_t  last_node;
// } blake2b_state;

// enum blake2b_constant {
//     BLAKE2B_BLOCKBYTES = 128,
//     BLAKE2B_OUTBYTES   = 64,
//     BLAKE2B_KEYBYTES   = 64,
//     BLAKE2B_SALTBYTES  = 16,
//     BLAKE2B_PERSONALBYTES = 16
// };

// BLAKE2_PACKED(struct blake2b_param__ {
//     uint8_t  digest_length; /* 1 */
//     uint8_t  key_length;    /* 2 */
//     uint8_t  fanout;        /* 3 */
//     uint8_t  depth;         /* 4 */
//     uint32_t leaf_length;   /* 8 */
//     uint32_t node_offset;   /* 12 */
//     uint32_t xof_length;    /* 16 */
//     uint8_t  node_depth;    /* 17 */
//     uint8_t  inner_length;  /* 18 */
//     uint8_t  reserved[14];  /* 32 */
//     uint8_t  salt[BLAKE2B_SALTBYTES]; /* 48 */
//     uint8_t  personal[BLAKE2B_PERSONALBYTES];  /* 64 */
// });
// 
// typedef struct blake2b_param__ blake2b_param;


pub struct Blake2bParam {
    data: [u64; 8],
}

impl Blake2bParam {
    pub fn digest_length(&self) -> u8 {
        todo!()
    }

    pub fn key_length(&self) -> u8 {
        todo!()
    }
}

impl Blake2bParam {
    pub const fn digest_len(&self) -> u8 {
        self.data[0].to_le_bytes()[0]
    }
}



const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 
];

const SIGMA: [[u8; 16]; 12] = [
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
    [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
    [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
    [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
    [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
    [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
    [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
    [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
    [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 ],
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
];

// pub const BLAKE2B_BLOCKBYTES : usize = 128;
// pub const BLAKE2B_OUTBYTES : usize = 64;
// pub const BLAKE2B_KEYBYTES : usize = 64;
// pub const BLAKE2B_SALTBYTES : usize = 16;
// pub const BLAKE2B_PERSONALBYTES : usize = 16;
// 
// pub const BLAKE2S_BLOCKBYTES : usize = 64;
// pub const BLAKE2S_OUTBYTES : usize = 32;
// pub const BLAKE2S_KEYBYTES : usize = 32;
// pub const BLAKE2S_SALTBYTES : usize = 8;
// pub const BLAKE2S_PERSONALBYTES : usize = 8;






/// BLAKE2b-224
pub fn blake2b_224<T: AsRef<[u8]>>(data: T) -> [u8; Blake2b224::DIGEST_LEN] {
    Blake2b224::oneshot(data)
}

/// BLAKE2b-256
pub fn blake2b_256<T: AsRef<[u8]>>(data: T) -> [u8; Blake2b256::DIGEST_LEN] {
    Blake2b256::oneshot(data)
}

/// BLAKE2b-384
pub fn blake2b_384<T: AsRef<[u8]>>(data: T) -> [u8; Blake2b384::DIGEST_LEN] {
    Blake2b384::oneshot(data)
}

/// BLAKE2b-512
pub fn blake2b_512<T: AsRef<[u8]>>(data: T) -> [u8; Blake2b512::DIGEST_LEN] {
    Blake2b512::oneshot(data)
}


#[derive(Clone)]
pub struct Blake2b224 {
    inner: Blake2b,
}

impl Blake2b224 {
    pub const BLOCK_LEN: usize  = Blake2b::BLOCK_LEN;
    pub const DIGEST_LEN: usize = 28;


    #[inline]
    pub fn new() -> Self {
        Self { inner: Blake2b::new(b"", 28) }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let mut digest = [0u8; Self::DIGEST_LEN];
        self.inner.finalize(&mut digest);
        digest
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}

#[derive(Clone)]
pub struct Blake2b256 {
    inner: Blake2b,
}

impl Blake2b256 {
    pub const BLOCK_LEN: usize  = Blake2b::BLOCK_LEN;
    pub const DIGEST_LEN: usize = 32;


    #[inline]
    pub fn new() -> Self {
        Self { inner: Blake2b::new(b"", 32) }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let mut digest = [0u8; Self::DIGEST_LEN];
        self.inner.finalize(&mut digest);
        digest
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}

#[derive(Clone)]
pub struct Blake2b384 {
    inner: Blake2b,
}

impl Blake2b384 {
    pub const BLOCK_LEN: usize  = Blake2b::BLOCK_LEN;
    pub const DIGEST_LEN: usize = 48;


    #[inline]
    pub fn new() -> Self {
        Self { inner: Blake2b::new(b"", 48) }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let mut digest = [0u8; Self::DIGEST_LEN];
        self.inner.finalize(&mut digest);
        digest
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}


#[derive(Clone)]
pub struct Blake2b512 {
    inner: Blake2b,
}

impl Blake2b512 {
    pub const BLOCK_LEN: usize  = Blake2b::BLOCK_LEN;
    pub const DIGEST_LEN: usize = 64;


    #[inline]
    pub fn new() -> Self {
        Self { inner: Blake2b::new(b"", 64) }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let mut digest = [0u8; Self::DIGEST_LEN];
        self.inner.finalize(&mut digest);
        digest
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}

////////////////////// 2s ////////////////////////////
/// BLAKE2b-224
pub fn blake2s_224<T: AsRef<[u8]>>(data: T) -> [u8; Blake2s224::DIGEST_LEN] {
    Blake2s224::oneshot(data)
}

/// BLAKE2s-256
pub fn blake2s_256<T: AsRef<[u8]>>(data: T) -> [u8; Blake2s256::DIGEST_LEN] {
    Blake2s256::oneshot(data)
}

#[derive(Clone)]
pub struct Blake2s224 {
    inner: Blake2s,
}

impl Blake2s224 {
    pub const BLOCK_LEN: usize  = Blake2s::BLOCK_LEN;
    pub const DIGEST_LEN: usize = 28;


    #[inline]
    pub fn new() -> Self {
        Self { inner: Blake2s::new(b"", 28) }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let mut digest = [0u8; Self::DIGEST_LEN];
        self.inner.finalize(&mut digest);
        digest
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}

#[derive(Clone)]
pub struct Blake2s256 {
    inner: Blake2s,
}

impl Blake2s256 {
    pub const BLOCK_LEN: usize  = Blake2s::BLOCK_LEN;
    pub const DIGEST_LEN: usize = 32;


    #[inline]
    pub fn new() -> Self {
        Self { inner: Blake2s::new(b"", 32) }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let mut digest = [0u8; Self::DIGEST_LEN];
        self.inner.finalize(&mut digest);
        digest
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}


#[derive(Clone)]
pub struct Blake2b {
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,

    state: [u64; 8],

    t0: u64,
    t1: u64,
    f0: u64,
    f1: u64,
    last_node: u8,

    hlen: usize,
}

impl Blake2b {
    pub const BLOCK_LEN: usize  = 128;
    
    // block length in bytes: 1 <= nn <= 64
    pub const H_MIN: usize =  1;
    pub const H_MAX: usize = 64;
    
    // key length in bytes: 0 <= kk <= 64
    pub const K_MIN: usize =  0;
    pub const K_MAX: usize = 64;

    // input bytes: 0 <= ll < 2**128
    pub const M_MIN: u128 = 0;
    pub const M_MAX: u128 = u128::MAX;

    pub const ROUNDS: usize = 12; // Rounds in F

    //                        (R1, R2, R3, R4)
    // G Rotation constants = (32, 24, 16, 63)
    const R1: u32 = 32;
    const R2: u32 = 24;
    const R3: u32 = 16;
    const R4: u32 = 63;


    pub fn new(key: &[u8], hlen: usize) -> Self {
        let klen = key.len();

        assert!(hlen >= Self::H_MIN && hlen <= Self::H_MAX);
        assert!(klen >= Self::K_MIN && klen <= Self::K_MAX);

        // parameter block
        let p1 = u64::from_le_bytes([
            hlen as u8, klen as u8, 1, 1, // digest_length, key_length, fanout, depth
            0, 0, 0, 0,                   // leaf_length
        ]);

        // IV XOR ParamBlock
        let s1 = BLAKE2B_IV[0] ^ p1;
        let state: [u64; 8] = [
            // H
            s1,          BLAKE2B_IV[1], 
            BLAKE2B_IV[2], BLAKE2B_IV[3],
            BLAKE2B_IV[4], BLAKE2B_IV[5], 
            BLAKE2B_IV[6], BLAKE2B_IV[7],
        ];

        let mut hasher = Self {
            buffer: [0u8; Self::BLOCK_LEN],
            offset: 0,

            state: state,
            t0: 0,
            t1: 0,
            f0: 0,
            f1: 0,
            last_node: 0,

            hlen,
        };

        if klen > 0 {
            let mut block = [0u8; Self::BLOCK_LEN];
            block[..klen].copy_from_slice(&key);

            hasher.update(&block);
        }

        hasher
    }
    
    pub const fn digest_len(&self) -> usize {
        self.hlen
    }

    #[inline]
    fn transform(state: &mut [u64; 8], block: &[u8], t0: u64, t1: u64, f0: u64, f1: u64) {
        debug_assert_eq!(state.len(), 8);
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        let mut m = [0u64; 16];
        let mut v = [0u64; 16];

        for i in 0usize..16 {
            let pos = i * 8;
            m[i] = u64::from_le_bytes([
                block[pos + 0],
                block[pos + 1], 
                block[pos + 2], 
                block[pos + 3], 
                block[pos + 4], 
                block[pos + 5], 
                block[pos + 6], 
                block[pos + 7], 
            ]);
        }

        v[..8].copy_from_slice(&state[..]);

        v[ 8] = BLAKE2B_IV[0];
        v[ 9] = BLAKE2B_IV[1];
        v[10] = BLAKE2B_IV[2];
        v[11] = BLAKE2B_IV[3];
        v[12] = BLAKE2B_IV[4] ^ t0;
        v[13] = BLAKE2B_IV[5] ^ t1;
        v[14] = BLAKE2B_IV[6] ^ f0;
        v[15] = BLAKE2B_IV[7] ^ f1;

        macro_rules! G {
            ($r:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
                $a = $a.wrapping_add($b).wrapping_add(m[SIGMA[$r][2 * $i + 0] as usize]);
                $d = ($d ^ $a).rotate_right(Self::R1); // R1

                $c = $c.wrapping_add($d);
                $b = ($b ^ $c).rotate_right(Self::R2); // R2

                $a = $a.wrapping_add($b).wrapping_add(m[SIGMA[$r][2 * $i + 1] as usize]);
                $d = ($d ^ $a).rotate_right(Self::R3); // R3

                $c = $c.wrapping_add($d);
                $b = ($b ^ $c).rotate_right(Self::R4); // R4
            }
        }

        macro_rules! ROUND {
            ($r:tt) => {
                G!($r, 0, v[ 0], v[ 4], v[ 8], v[12]);
                G!($r, 1, v[ 1], v[ 5], v[ 9], v[13]);
                G!($r, 2, v[ 2], v[ 6], v[10], v[14]);
                G!($r, 3, v[ 3], v[ 7], v[11], v[15]);
                G!($r, 4, v[ 0], v[ 5], v[10], v[15]);
                G!($r, 5, v[ 1], v[ 6], v[11], v[12]);
                G!($r, 6, v[ 2], v[ 7], v[ 8], v[13]);
                G!($r, 7, v[ 3], v[ 4], v[ 9], v[14]);
            }
        }

        ROUND!(0);
        ROUND!(1);
        ROUND!(2);
        ROUND!(3);
        ROUND!(4);
        ROUND!(5);
        ROUND!(6);
        ROUND!(7);
        ROUND!(8);
        ROUND!(9);
        ROUND!(10);
        ROUND!(11);

        state[0] = state[0] ^ v[0] ^ v[ 8];
        state[1] = state[1] ^ v[1] ^ v[ 9];
        state[2] = state[2] ^ v[2] ^ v[10];
        state[3] = state[3] ^ v[3] ^ v[11];
        state[4] = state[4] ^ v[4] ^ v[12];
        state[5] = state[5] ^ v[5] ^ v[13];
        state[6] = state[6] ^ v[6] ^ v[14];
        state[7] = state[7] ^ v[7] ^ v[15];
    }

    #[inline]
    fn inc(&mut self, len: usize) {
        // BLAKE2b Block Counter
        self.t0 = self.t0.wrapping_add(len as u64);
        if self.t0 < len as u64 {
            self.t1 = self.t1.wrapping_add(1);
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;
        while i < data.len() {
            if self.offset < Self::BLOCK_LEN {
                self.buffer[self.offset] = data[i];
                self.offset += 1;
                i += 1;
            }
            
            if self.offset == Self::BLOCK_LEN {
                self.inc(Self::BLOCK_LEN);
                
                Self::transform(&mut self.state, &self.buffer, self.t0, self.t1, self.f0, self.f1,);
                self.offset = 0;
            }
        }
    }

    pub fn finalize(mut self, out: &mut [u8]) {
        assert_eq!(out.len(), self.hlen);
        assert_eq!(self.f0 != 0, false);

        self.inc(self.offset);

        self.f0 = u64::MAX;
        // self.f1 = u64::MAX;

        // Padding
        while self.offset < Self::BLOCK_LEN {
            self.buffer[self.offset] = 0;
            self.offset += 1;
        }

        Self::transform(&mut self.state, &self.buffer, self.t0, self.t1, self.f0, self.f1);

        let mut hash = [0u8; Self::H_MAX];
        hash[ 0.. 8].copy_from_slice(&self.state[0].to_le_bytes());
        hash[ 8..16].copy_from_slice(&self.state[1].to_le_bytes());
        hash[16..24].copy_from_slice(&self.state[2].to_le_bytes());
        hash[24..32].copy_from_slice(&self.state[3].to_le_bytes());
        hash[32..40].copy_from_slice(&self.state[4].to_le_bytes());
        hash[40..48].copy_from_slice(&self.state[5].to_le_bytes());
        hash[48..56].copy_from_slice(&self.state[6].to_le_bytes());
        hash[56..64].copy_from_slice(&self.state[7].to_le_bytes());

        out.copy_from_slice(&hash[..self.hlen]);
    }
}


#[derive(Clone)]
pub struct Blake2s {
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,

    state: [u32; 8],

    t0: u32,
    t1: u32,
    f0: u32,
    f1: u32,
    last_node: u8,

    hlen: usize,
}

impl Blake2s {
    pub const BLOCK_LEN: usize  = 64;
    
    pub const H_MIN: usize =  1;
    pub const H_MAX: usize = 32;
    
    pub const K_MIN: usize =  0;
    pub const K_MAX: usize = 32;

    pub const M_MIN: u64 = 0;
    pub const M_MAX: u64 = u64::MAX;

    pub const ROUNDS: usize = 10; // Rounds in F

    //                        (R1, R2, R3, R4)
    // G Rotation constants = (16, 12,  8,  7)
    const R1: u32 = 16;
    const R2: u32 = 12;
    const R3: u32 =  8;
    const R4: u32 =  7;


    pub fn new(key: &[u8], hlen: usize) -> Self {
        let klen = key.len();

        assert!(hlen >= Self::H_MIN && hlen <= Self::H_MAX);
        assert!(klen >= Self::K_MIN && klen <= Self::K_MAX);

        // parameter block
        // digest_length, key_length, fanout, depth
        let p1 = u32::from_le_bytes([ hlen as u8, klen as u8, 1, 1]);

        // IV XOR ParamBlock
        let s1 = BLAKE2S_IV[0] ^ p1;
        let state: [u32; 8] = [
            // H
            s1,          BLAKE2S_IV[1], 
            BLAKE2S_IV[2], BLAKE2S_IV[3],
            BLAKE2S_IV[4], BLAKE2S_IV[5], 
            BLAKE2S_IV[6], BLAKE2S_IV[7],
        ];

        let mut hasher = Self {
            buffer: [0u8; Self::BLOCK_LEN],
            offset: 0,
            state,
            t0: 0,
            t1: 0,
            f0: 0,
            f1: 0,
            last_node: 0,
            hlen,
        };

        if klen > 0 {
            let mut block = [0u8; Self::BLOCK_LEN];
            block[..klen].copy_from_slice(&key);

            hasher.update(&block);
        }

        hasher
    }
    
    pub const fn digest_len(&self) -> usize {
        self.hlen
    }

    #[inline]
    fn transform(state: &mut [u32; 8], block: &[u8], t0: u32, t1: u32, f0: u32, f1: u32) {
        debug_assert_eq!(state.len(), 8);
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        let mut m = [0u32; 16];
        let mut v = [0u32; 16];

        for i in 0usize..16 {
            let pos = i * 4;
            m[i] = u32::from_le_bytes([
                block[pos + 0],
                block[pos + 1], 
                block[pos + 2], 
                block[pos + 3], 
            ]);
        }

        v[..8].copy_from_slice(&state[..]);

        v[ 8] = BLAKE2S_IV[0];
        v[ 9] = BLAKE2S_IV[1];
        v[10] = BLAKE2S_IV[2];
        v[11] = BLAKE2S_IV[3];
        v[12] = BLAKE2S_IV[4] ^ t0;
        v[13] = BLAKE2S_IV[5] ^ t1;
        v[14] = BLAKE2S_IV[6] ^ f0;
        v[15] = BLAKE2S_IV[7] ^ f1;

        macro_rules! G {
            ($r:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
                $a = $a.wrapping_add($b).wrapping_add(m[SIGMA[$r][2 * $i + 0] as usize]);
                $d = ($d ^ $a).rotate_right(Self::R1); // R1

                $c = $c.wrapping_add($d);
                $b = ($b ^ $c).rotate_right(Self::R2); // R2

                $a = $a.wrapping_add($b).wrapping_add(m[SIGMA[$r][2 * $i + 1] as usize]);
                $d = ($d ^ $a).rotate_right(Self::R3); // R3

                $c = $c.wrapping_add($d);
                $b = ($b ^ $c).rotate_right(Self::R4); // R4
            }
        }

        macro_rules! ROUND {
            ($r:tt) => {
                G!($r, 0, v[ 0], v[ 4], v[ 8], v[12]);
                G!($r, 1, v[ 1], v[ 5], v[ 9], v[13]);
                G!($r, 2, v[ 2], v[ 6], v[10], v[14]);
                G!($r, 3, v[ 3], v[ 7], v[11], v[15]);
                G!($r, 4, v[ 0], v[ 5], v[10], v[15]);
                G!($r, 5, v[ 1], v[ 6], v[11], v[12]);
                G!($r, 6, v[ 2], v[ 7], v[ 8], v[13]);
                G!($r, 7, v[ 3], v[ 4], v[ 9], v[14]);
            }
        }

        ROUND!(0);
        ROUND!(1);
        ROUND!(2);
        ROUND!(3);
        ROUND!(4);
        ROUND!(5);
        ROUND!(6);
        ROUND!(7);
        ROUND!(8);
        ROUND!(9);

        state[0] = state[0] ^ v[0] ^ v[ 8];
        state[1] = state[1] ^ v[1] ^ v[ 9];
        state[2] = state[2] ^ v[2] ^ v[10];
        state[3] = state[3] ^ v[3] ^ v[11];
        state[4] = state[4] ^ v[4] ^ v[12];
        state[5] = state[5] ^ v[5] ^ v[13];
        state[6] = state[6] ^ v[6] ^ v[14];
        state[7] = state[7] ^ v[7] ^ v[15];
    }

    #[inline]
    fn inc(&mut self, len: usize) {
        // BLAKE2b Block Counter
        self.t0 = self.t0.wrapping_add(len as u32);
        if self.t0 < len as u32 {
            self.t1 = self.t1.wrapping_add(1);
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;
        while i < data.len() {
            if self.offset < Self::BLOCK_LEN {
                self.buffer[self.offset] = data[i];
                self.offset += 1;
                i += 1;
            }
            
            if self.offset == Self::BLOCK_LEN {
                self.inc(Self::BLOCK_LEN);
                
                Self::transform(&mut self.state, &self.buffer, self.t0, self.t1, self.f0, self.f1,);
                self.offset = 0;
            }
        }
    }

    pub fn finalize(mut self, out: &mut [u8]) {
        assert_eq!(out.len(), self.hlen);
        assert_eq!(self.f0 != 0, false);

        self.inc(self.offset);

        self.f0 = u32::MAX;
        // self.f1 = u32::MAX;

        // Padding
        while self.offset < Self::BLOCK_LEN {
            self.buffer[self.offset] = 0;
            self.offset += 1;
        }

        Self::transform(&mut self.state, &self.buffer, self.t0, self.t1, self.f0, self.f1);

        let mut hash = [0u8; Self::H_MAX]; // 32
        hash[ 0.. 4].copy_from_slice(&self.state[0].to_le_bytes());
        hash[ 4.. 8].copy_from_slice(&self.state[1].to_le_bytes());
        hash[ 8..12].copy_from_slice(&self.state[2].to_le_bytes());
        hash[12..16].copy_from_slice(&self.state[3].to_le_bytes());
        hash[16..20].copy_from_slice(&self.state[4].to_le_bytes());
        hash[20..24].copy_from_slice(&self.state[5].to_le_bytes());
        hash[24..28].copy_from_slice(&self.state[6].to_le_bytes());
        hash[28..32].copy_from_slice(&self.state[7].to_le_bytes());

        out.copy_from_slice(&hash[..self.hlen]);
    }
}

#[test]
fn test_blake2b() {
    use crate::encoding::hex;

    // Appendix A.  Example of BLAKE2b Computation
    // https://datatracker.ietf.org/doc/html/rfc7693#appendix-A
    assert_eq!(&blake2b_512(b"abc"), &[
        0xBA, 0x80, 0xA5, 0x3F, 0x98, 0x1C, 0x4D, 0x0D, 0x6A, 0x27, 0x97, 0xB6, 0x9F, 0x12, 0xF6, 0xE9,
        0x4C, 0x21, 0x2F, 0x14, 0x68, 0x5A, 0xC4, 0xB7, 0x4B, 0x12, 0xBB, 0x6F, 0xDB, 0xFF, 0xA2, 0xD1,
        0x7D, 0x87, 0xC5, 0x39, 0x2A, 0xAB, 0x79, 0x2D, 0xC2, 0x52, 0xD5, 0xDE, 0x45, 0x33, 0xCC, 0x95,
        0x18, 0xD3, 0x8A, 0xA8, 0xDB, 0xF1, 0x92, 0x5A, 0xB9, 0x23, 0x86, 0xED, 0xD4, 0x00, 0x99, 0x23,
    ]);

    // Example digests
    // https://en.wikipedia.org/wiki/BLAKE_(hash_function)#Example_digests
    assert_eq!(&blake2b_384(b""),
            &hex::decode("b32811423377f52d7862286ee1a72ee5\
                          40524380fda1724a6f25d7978c6fd324\
                          4a6caf0498812673c5e05ef583825100").unwrap()[..]);
    assert_eq!(&blake2b_512(b""),
            &hex::decode("786a02f742015903c6c6fd852552d272\
                          912f4740e15847618a86e217f71f5419\
                          d25e1031afee585313896444934eb04b\
                          903a685b1448b755d56f701afe9be2ce").unwrap()[..]);
    assert_eq!(&blake2b_512(b"The quick brown fox jumps over the lazy dog"),
            &hex::decode("a8add4bdddfd93e4877d2746e62817b1\
                          16364a1fa7bc148d95090bc7333b3673\
                          f82401cf7aa2e4cb1ecd90296e3f14cb\
                          5413f8ed77be73045b13914cdcd6a918").unwrap()[..]);
    assert_eq!(&blake2b_512(b"The quick brown fox jumps over the lazy dof"),
            &hex::decode("ab6b007747d8068c02e25a6008db8a77\
                          c218d94f3b40d2291a7dc8a62090a744\
                          c082ea27af01521a102e42f480a31e98\
                          44053f456b4b41e8aa78bbe5c12957bb").unwrap()[..]);
}

#[test]
fn test_blake2s() {
    use crate::encoding::hex;

    // Appendix A.  Example of BLAKE2b Computation
    // https://datatracker.ietf.org/doc/html/rfc7693#appendix-A
    assert_eq!(&blake2s_256(b"abc"), &[
        0x50, 0x8C, 0x5E, 0x8C, 0x32, 0x7C, 0x14, 0xE2, 0xE1, 0xA7, 0x2B, 0xA3, 0x4E, 0xEB, 0x45, 0x2F,
        0x37, 0x45, 0x8B, 0x20, 0x9E, 0xD6, 0x3A, 0x29, 0x4D, 0x99, 0x9B, 0x4C, 0x86, 0x67, 0x59, 0x82,
    ]);

    // Example digests
    // https://en.wikipedia.org/wiki/BLAKE_(hash_function)#Example_digests
    assert_eq!(&blake2s_224(b""),
            &hex::decode("1fa1291e65248b37b3433475b2a0dd63\
                          d54a11ecc4e3e034e7bc1ef4").unwrap()[..]);
    assert_eq!(&blake2s_256(b""),
            &hex::decode("69217a3079908094e11121d042354a7c\
                          1f55b6482ca1a51e1b250dfd1ed0eef9").unwrap()[..]);
}