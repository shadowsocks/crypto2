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
const BLAKE2S_IV: [u32; 8]     = [ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ];
// IV XOR ParamBlock
const BLAKE2S_224_IV: [u32; 8] = [ 0x6b08e67b, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ];
// IV XOR ParamBlock
const BLAKE2S_256_IV: [u32; 8] = [ 0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ];


#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2",
))]
#[path = "./x86/mod.rs"]
mod platform;

// #[cfg(all(target_arch = "aarch64", target_feature = "crypto"))]
// #[path = "./aarch64.rs"]
// mod platform;

#[cfg(not(any(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2",
    ),
    all(target_arch = "aarch64", target_feature = "crypto")
)))]
#[path = "./generic.rs"]
mod platform;

pub use self::platform::*;



/// BLAKE2s-224
pub fn blake2s_224<T: AsRef<[u8]>>(data: T) -> [u8; Blake2s224::DIGEST_LEN] {
    Blake2s224::oneshot(data)
}

/// BLAKE2s-256
pub fn blake2s_256<T: AsRef<[u8]>>(data: T) -> [u8; Blake2s256::DIGEST_LEN] {
    Blake2s256::oneshot(data)
}


/// BLAKE2s-224
#[derive(Clone)]
pub struct Blake2s224 {
    inner: Blake2s
}

impl Blake2s224 {
    pub const BLOCK_LEN: usize  = Blake2s::BLOCK_LEN;
    pub const DIGEST_LEN: usize = 28;

    
    #[inline]
    pub fn new() -> Self {
        Self { inner: Blake2s::new(BLAKE2S_224_IV, b"") }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let h = self.inner.finalize();

        let mut digest = [0u8; Self::DIGEST_LEN];
        digest[..Self::DIGEST_LEN].copy_from_slice(&h);
        digest
    }

    #[inline]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        // let mut m = Self::new();
        // m.update(data.as_ref());
        // m.finalize()
        // Blake2s::oneshot_hash()

        let h = Blake2s::oneshot_hash(BLAKE2S_224_IV, data);

        let mut out = [0u8; 28];
        out.copy_from_slice(&h[..28]);
        out
    }
}

/// BLAKE2s-256
#[derive(Clone)]
pub struct Blake2s256 {
    inner: Blake2s
}

impl Blake2s256 {
    pub const BLOCK_LEN: usize  = Blake2s::BLOCK_LEN;
    pub const DIGEST_LEN: usize = 32;


    #[inline]
    pub fn new() -> Self {
        Self { inner: Blake2s::new(BLAKE2S_256_IV, b"") }
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
        Blake2s::oneshot_hash(BLAKE2S_256_IV, data)
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