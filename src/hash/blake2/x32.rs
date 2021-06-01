use super::SIGMA;
// BLAKE2S_BLOCKBYTES = 64,
// BLAKE2S_OUTBYTES   = 32,
// BLAKE2S_KEYBYTES   = 32,
// BLAKE2S_SALTBYTES  = 8,
// BLAKE2S_PERSONALBYTES = 8
// 
// BLAKE2_PACKED(struct blake2s_param__ {
//     uint8_t  digest_length; // 1
//     uint8_t  key_length;    // 2
//     uint8_t  fanout;        // 3
//     uint8_t  depth;         // 4
//     uint32_t leaf_length;   // 8
//     uint32_t node_offset;   // 12
//     uint16_t xof_length;    // 14
//     uint8_t  node_depth;    // 15
//     uint8_t  inner_length;  // 16
//     // uint8_t  reserved[0];
//     uint8_t  salt[BLAKE2S_SALTBYTES];         // 24
//     uint8_t  personal[BLAKE2S_PERSONALBYTES]; // 32
// });
// typedef struct blake2s_param__ blake2s_param;
// 
// typedef struct blake2s_state__ {
//     uint32_t h[8];
//     uint32_t t[2];
//     uint32_t f[2];
//     uint8_t  buf[BLAKE2S_BLOCKBYTES];
//     size_t   buflen;
//     size_t   outlen;
//     uint8_t  last_node;
// } blake2s_state;


const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 
];


/// BLAKE2s-224
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