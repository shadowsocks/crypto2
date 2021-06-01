use super::SIGMA;
// enum blake2b_constant {
//     BLAKE2B_BLOCKBYTES = 128,
//     BLAKE2B_OUTBYTES   = 64,
//     BLAKE2B_KEYBYTES   = 64,
//     BLAKE2B_SALTBYTES  = 16,
//     BLAKE2B_PERSONALBYTES = 16
// };
// 
// typedef struct blake2b_state__ {
//     uint64_t h[8];
//     uint64_t t[2];
//     uint64_t f[2];
//     uint8_t  buf[BLAKE2B_BLOCKBYTES];
//     size_t   buflen;
//     size_t   outlen;
//     uint8_t  last_node;
// } blake2b_state;
// 
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

const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];


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

macro_rules! impl_blake2b_fixed_output {
    ($name:tt, $hlen:tt) => {
        #[derive(Clone)]
        pub struct $name {
            inner: Blake2b,
        }

        impl $name {
            pub const BLOCK_LEN: usize  = Blake2b::BLOCK_LEN;
            pub const DIGEST_LEN: usize = $hlen;


            #[inline]
            pub fn new() -> Self {
                Self { inner: Blake2b::new(b"", $hlen) }
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
    }
}

impl_blake2b_fixed_output!(Blake2b224, 28);
impl_blake2b_fixed_output!(Blake2b256, 32);
impl_blake2b_fixed_output!(Blake2b384, 48);
impl_blake2b_fixed_output!(Blake2b512, 64);


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