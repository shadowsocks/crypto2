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
const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];


mod generic;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2",
))]
mod x86;


use self::generic::transform;


/// BLAKE2b-224
pub fn blake2b_224<T: AsRef<[u8]>>(data: T) -> [u8; Blake2b224::DIGEST_LEN] {
    Blake2b224::oneshot(data)
}

/// BLAKE2b-256
pub fn blake2b_256<T: AsRef<[u8]>>(data: T) -> [u8; Blake2b256::DIGEST_LEN] {
    // Blake2b256::oneshot(data)

    // NOTE: 后续所有的 摘要函数 的 oneshot 都应该避免使用 流式写法。（流式写法在 Update 时的 Copy 非常低效，在大部分场景里面也无必要）
    let data = data.as_ref();

    // parameter block
    let hlen = 32;
    let p1 = u64::from_le_bytes([
        hlen, 0, 1, 1, // digest_length, key_length, fanout, depth
        0, 0, 0, 0,                   // leaf_length
    ]);

    // IV XOR ParamBlock
    let s1 = BLAKE2B_IV[0] ^ p1;
    let mut state: [u64; 8] = [
        // H
        s1,          BLAKE2B_IV[1], 
        BLAKE2B_IV[2], BLAKE2B_IV[3],
        BLAKE2B_IV[4], BLAKE2B_IV[5], 
        BLAKE2B_IV[6], BLAKE2B_IV[7],
    ];


    let mut block_counter = 0u128;
    
    let chunks = data.chunks_exact(Blake2b::BLOCK_LEN);
    let rem = chunks.remainder();

    for chunk in chunks {
        block_counter = block_counter.wrapping_add(Blake2b::BLOCK_LEN as u128);
        transform(&mut state, chunk, block_counter, 0);
    }

    let rlen = rem.len();
    
    let mut block = [0u8; Blake2b::BLOCK_LEN];
    if rlen > 0 {
        block[..rlen].copy_from_slice(&rem);
    }

    block_counter = block_counter.wrapping_add(rlen as u128);
    transform(&mut state, &block, block_counter, u64::MAX as u128);

    // let mut hash = [0u8; Blake2b::H_MAX]; // 64
    let mut hash = [0u8; 32];
    hash[ 0.. 8].copy_from_slice(&state[0].to_le_bytes());
    hash[ 8..16].copy_from_slice(&state[1].to_le_bytes());
    hash[16..24].copy_from_slice(&state[2].to_le_bytes());
    hash[24..32].copy_from_slice(&state[3].to_le_bytes());
    // hash[32..40].copy_from_slice(&state[4].to_le_bytes());
    // hash[40..48].copy_from_slice(&state[5].to_le_bytes());
    // hash[48..56].copy_from_slice(&state[6].to_le_bytes());
    // hash[56..64].copy_from_slice(&state[7].to_le_bytes());

    hash
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
    block_counter: u128, // T0, T1
    hlen: usize,
}

impl Blake2b {
    pub const BLOCK_LEN: usize  = 128;
    
    pub const H_MIN: usize =  1;
    pub const H_MAX: usize = 64;
    
    pub const K_MIN: usize =  0;
    pub const K_MAX: usize = 64;

    pub const M_MIN: u128 = 0;
    pub const M_MAX: u128 = u128::MAX;

    pub const ROUNDS: usize = 12; // Rounds in F


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
            state,
            block_counter: 0,
            hlen,
        };

        if klen > 0 {
            let mut block = [0u8; Self::BLOCK_LEN];
            block[..klen].copy_from_slice(&key);

            hasher.update(&block);
        }

        hasher
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
                self.block_counter = self.block_counter.wrapping_add(Self::BLOCK_LEN as u128);
                
                transform(&mut self.state, &self.buffer, self.block_counter, 0);

                self.offset = 0;
            }
        }
    }

    pub fn finalize(mut self, out: &mut [u8]) {
        assert_eq!(out.len(), self.hlen);

        self.block_counter = self.block_counter.wrapping_add(self.offset as u128);

        // Padding
        while self.offset < Self::BLOCK_LEN {
            self.buffer[self.offset] = 0;
            self.offset += 1;
        }

        transform(&mut self.state, &self.buffer, self.block_counter, u64::MAX as u128);

        let mut hash = [0u8; Self::H_MAX]; // 32
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