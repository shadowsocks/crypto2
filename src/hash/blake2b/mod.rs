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
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const BLAKE2B_224_IV: [u64; 8] = [
    0x6a09e667f2bdc914,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];
const BLAKE2B_256_IV: [u64; 8] = [
    0x6a09e667f2bdc928,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];
const BLAKE2B_384_IV: [u64; 8] = [
    0x6a09e667f2bdc938,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];
const BLAKE2B_512_IV: [u64; 8] = [
    0x6a09e667f2bdc948,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2",
))]
#[path = "./x86/mod.rs"]
mod platform;

// #[cfg(all(target_arch = "aarch64", target_feature = "crypto"))]
// #[path = "./aarch64.rs"]
// mod platform;

#[cfg(not(any(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx2",
    ),
    all(target_arch = "aarch64", target_feature = "crypto")
)))]
#[path = "./generic.rs"]
mod platform;

// // #[path = "./generic.rs"]
// #[path = "./x86/mod.rs"]
// mod platform;

pub use self::platform::*;

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

/// BLAKE2b-224
#[derive(Clone)]
pub struct Blake2b224 {
    inner: Blake2b,
}

impl Blake2b224 {
    pub const BLOCK_LEN: usize = Blake2b::BLOCK_LEN;
    pub const DIGEST_LEN: usize = 28;

    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Blake2b::new(BLAKE2B_224_IV, b""),
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let h = self.inner.finalize();

        let mut digest = [0u8; Self::DIGEST_LEN];
        digest[..Self::DIGEST_LEN].copy_from_slice(&h[..Self::DIGEST_LEN]);
        digest
    }

    #[inline]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let h = Blake2b::oneshot_hash(BLAKE2B_224_IV, data);

        let mut out = [0u8; Self::DIGEST_LEN];
        out.copy_from_slice(&h[..Self::DIGEST_LEN]);
        out
    }
}

/// BLAKE2b-256
#[derive(Clone)]
pub struct Blake2b256 {
    inner: Blake2b,
}

impl Blake2b256 {
    pub const BLOCK_LEN: usize = Blake2b::BLOCK_LEN;
    pub const DIGEST_LEN: usize = 32;

    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Blake2b::new(BLAKE2B_256_IV, b""),
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let h = self.inner.finalize();

        let mut digest = [0u8; Self::DIGEST_LEN];
        digest[..Self::DIGEST_LEN].copy_from_slice(&h[..Self::DIGEST_LEN]);
        digest
    }

    #[inline]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let h = Blake2b::oneshot_hash(BLAKE2B_256_IV, data);

        let mut out = [0u8; Self::DIGEST_LEN];
        out.copy_from_slice(&h[..Self::DIGEST_LEN]);
        out
    }
}

/// BLAKE2b-384
#[derive(Clone)]
pub struct Blake2b384 {
    inner: Blake2b,
}

impl Blake2b384 {
    pub const BLOCK_LEN: usize = Blake2b::BLOCK_LEN;
    pub const DIGEST_LEN: usize = 48;

    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Blake2b::new(BLAKE2B_384_IV, b""),
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let h = self.inner.finalize();

        let mut digest = [0u8; Self::DIGEST_LEN];
        digest[..Self::DIGEST_LEN].copy_from_slice(&h[..Self::DIGEST_LEN]);
        digest
    }

    #[inline]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let h = Blake2b::oneshot_hash(BLAKE2B_384_IV, data);

        let mut out = [0u8; Self::DIGEST_LEN];
        out.copy_from_slice(&h[..Self::DIGEST_LEN]);
        out
    }
}

/// BLAKE2b-512
#[derive(Clone)]
pub struct Blake2b512 {
    inner: Blake2b,
}

impl Blake2b512 {
    pub const BLOCK_LEN: usize = Blake2b::BLOCK_LEN;
    pub const DIGEST_LEN: usize = 64;

    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Blake2b::new(BLAKE2B_512_IV, b""),
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        self.inner.finalize()
    }

    #[inline]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        Blake2b::oneshot_hash(BLAKE2B_512_IV, data)
    }
}

#[test]
fn test_blake2b() {
    use crate::encoding::hex;

    // Appendix A.  Example of BLAKE2b Computation
    // https://datatracker.ietf.org/doc/html/rfc7693#appendix-A
    assert_eq!(
        &blake2b_512(b"abc"),
        &[
            0xBA, 0x80, 0xA5, 0x3F, 0x98, 0x1C, 0x4D, 0x0D, 0x6A, 0x27, 0x97, 0xB6, 0x9F, 0x12,
            0xF6, 0xE9, 0x4C, 0x21, 0x2F, 0x14, 0x68, 0x5A, 0xC4, 0xB7, 0x4B, 0x12, 0xBB, 0x6F,
            0xDB, 0xFF, 0xA2, 0xD1, 0x7D, 0x87, 0xC5, 0x39, 0x2A, 0xAB, 0x79, 0x2D, 0xC2, 0x52,
            0xD5, 0xDE, 0x45, 0x33, 0xCC, 0x95, 0x18, 0xD3, 0x8A, 0xA8, 0xDB, 0xF1, 0x92, 0x5A,
            0xB9, 0x23, 0x86, 0xED, 0xD4, 0x00, 0x99, 0x23,
        ]
    );

    // Example digests
    // https://en.wikipedia.org/wiki/BLAKE_(hash_function)#Example_digests
    assert_eq!(
        &blake2b_384(b""),
        &hex::decode(
            "b32811423377f52d7862286ee1a72ee5\
                          40524380fda1724a6f25d7978c6fd324\
                          4a6caf0498812673c5e05ef583825100"
        )
        .unwrap()[..]
    );
    assert_eq!(
        &blake2b_512(b""),
        &hex::decode(
            "786a02f742015903c6c6fd852552d272\
                          912f4740e15847618a86e217f71f5419\
                          d25e1031afee585313896444934eb04b\
                          903a685b1448b755d56f701afe9be2ce"
        )
        .unwrap()[..]
    );
    assert_eq!(
        &blake2b_512(b"The quick brown fox jumps over the lazy dog"),
        &hex::decode(
            "a8add4bdddfd93e4877d2746e62817b1\
                          16364a1fa7bc148d95090bc7333b3673\
                          f82401cf7aa2e4cb1ecd90296e3f14cb\
                          5413f8ed77be73045b13914cdcd6a918"
        )
        .unwrap()[..]
    );
    assert_eq!(
        &blake2b_512(b"The quick brown fox jumps over the lazy dof"),
        &hex::decode(
            "ab6b007747d8068c02e25a6008db8a77\
                          c218d94f3b40d2291a7dc8a62090a744\
                          c082ea27af01521a102e42f480a31e98\
                          44053f456b4b41e8aa78bbe5c12957bb"
        )
        .unwrap()[..]
    );
}
