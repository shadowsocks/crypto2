// FIPS-180-2 compliant SHA-256 implementation
//
// The SHA-256 Secure Hash Standard was published by NIST in 2002.
// <http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf>
use core::convert::TryFrom;


#[allow(dead_code)]
mod generic;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;
#[cfg(target_arch = "aarch64")]
mod aarch64;

// Round constants
const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 
];

const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];


/// SHA2-224
pub fn sha224<T: AsRef<[u8]>>(data: T) -> [u8; Sha224::DIGEST_LEN] {
    Sha224::oneshot(data)
}

/// SHA2-256
pub fn sha256<T: AsRef<[u8]>>(data: T) -> [u8; Sha256::DIGEST_LEN] {
    Sha256::oneshot(data)
}


// NOTE: 直接使用 SHA-NI 来加速。
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sha"))]
#[inline]
fn transform(state: &mut [u32; 8], block: &[u8]) {
    x86::transform(state, block)
}

// NOTE: 当编译时，没有开启 `+sha` 指令时，通过 Runtime 来判断
//       这样，会有性能损失。后面需要考虑是否有更好的方式。
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "sha")))]
#[inline]
fn transform(state: &mut [u32; 8], block: &[u8]) {
    if is_x86_feature_detected!("sha") {
        x86::transform(state, block)
    } else {
        generic::transform(state, block)
    }
}


#[cfg(all(target_arch = "aarch64", target_feature = "crypto"))]
#[inline]
fn transform(state: &mut [u32; 8], block: &[u8]) {
    aarch64::transform(state, block)
}
#[cfg(all(target_arch = "aarch64", not(target_feature = "crypto")))]
#[inline]
fn transform(state: &mut [u32; 8], block: &[u8]) {
    generic::transform(state, block)
}


// Other platform (e.g: MIPS)
#[cfg(all(
    not(any(target_arch = "x86", target_arch = "x86_64")),
    not(target_arch = "aarch64"),
))]
#[inline]
fn transform(state: &mut [u32; 8], block: &[u8]) {
    generic::transform(state, block)
}


/// A 224-bit One-way Hash Function: SHA-224
/// 
/// <https://tools.ietf.org/html/rfc3874>
#[derive(Clone)]
pub struct Sha224 {
    inner: Sha256,
}

impl Sha224 {
    pub const BLOCK_LEN: usize  = 64;
    pub const DIGEST_LEN: usize = 28;


    pub fn new() -> Self {
        const SHA_224_INITIAL_STATE: [u32; 8] = [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4, 
        ];

        Self {
            inner: Sha256 {
                buffer: [0u8; 64],
                state: SHA_224_INITIAL_STATE,
                len: 0,
            }
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let mut digest = [0u8; Self::DIGEST_LEN];
        digest.copy_from_slice(&self.inner.finalize()[..Self::DIGEST_LEN]);
        digest
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}


/// SHA2-256
#[derive(Clone)]
pub struct Sha256 {
    buffer: [u8; 64],
    state: [u32; 8],
    len: usize,      // in bytes.
}

impl Sha256 {
    pub const BLOCK_LEN: usize  = 64;
    pub const DIGEST_LEN: usize = 32;


    pub fn new() -> Self {
        Self {
            buffer: [0u8; 64],
            state: INITIAL_STATE,
            len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut n = self.len % Self::BLOCK_LEN;
        if n != 0 {
            let mut i = 0usize;
            loop {
                if n == 64 || i >= data.len() {
                    break;
                }
                self.buffer[n] = data[i];
                n += 1;
                i += 1;
                self.len += 1;
            }

            if self.len % Self::BLOCK_LEN != 0 {
                return ();
            } else {
                transform(&mut self.state, &self.buffer);

                let data = &data[i..];
                if data.len() > 0 {
                    return self.update(data);
                }
            }
        }

        if data.len() < 64 {
            self.buffer[..data.len()].copy_from_slice(data);
            self.len += data.len();
        } else if data.len() == 64 {
            transform(&mut self.state, data);
            self.len += 64;
        } else if data.len() > 64 {
            let blocks = data.len() / 64;
            for i in 0..blocks {
                transform(&mut self.state, &data[i*64..i*64+64]);
                self.len += 64;
            }
            let data = &data[blocks*64..];
            if data.len() > 0 {
                self.buffer[..data.len()].copy_from_slice(data);
                self.len += data.len();
            }
        } else {
            unreachable!()
        }
    }

    pub fn finalize(mut self) -> [u8; Self::DIGEST_LEN] {
        let len_bits = u64::try_from(self.len).unwrap() * 8;
        let n = self.len % Self::BLOCK_LEN;
        if n == 0 {
            let mut block = [0u8; 64];
            block[0] = 0x80;
            block[56..].copy_from_slice(&len_bits.to_be_bytes());
            transform(&mut self.state, &block);
        } else {
            self.buffer[n] = 0x80;
            for i in n+1..64 {
                self.buffer[i] = 0;
            }
            if 64 - n - 1 >= 8 {
                self.buffer[56..].copy_from_slice(&len_bits.to_be_bytes());
                transform(&mut self.state, &self.buffer);
            } else {
                transform(&mut self.state, &self.buffer);
                let mut block = [0u8; 64];
                block[56..].copy_from_slice(&len_bits.to_be_bytes());
                transform(&mut self.state, &block);
            }
        }

        let mut output = [0u8; 32];

        output[ 0.. 4].copy_from_slice(&self.state[0].to_be_bytes());
        output[ 4.. 8].copy_from_slice(&self.state[1].to_be_bytes());
        output[ 8..12].copy_from_slice(&self.state[2].to_be_bytes());
        output[12..16].copy_from_slice(&self.state[3].to_be_bytes());
        output[16..20].copy_from_slice(&self.state[4].to_be_bytes());
        output[20..24].copy_from_slice(&self.state[5].to_be_bytes());
        output[24..28].copy_from_slice(&self.state[6].to_be_bytes());
        output[28..32].copy_from_slice(&self.state[7].to_be_bytes());

        output
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}


#[test]
fn test_sha224() {
    // 3.  Test Vectors
    // https://tools.ietf.org/html/rfc3874#section-3

    // 3.1.  Test Vector #1
    let state = [
        0x23097d22u32, 0x3405d822, 0x8642a477, 0xbda255b3,
        0x2aadbce4, 0xbda0b3f7, 0xe36c9da7, 
    ];
    let mut digest = [0u8; Sha224::DIGEST_LEN];
    digest[ 0.. 4].copy_from_slice(&state[0].to_be_bytes());
    digest[ 4.. 8].copy_from_slice(&state[1].to_be_bytes());
    digest[ 8..12].copy_from_slice(&state[2].to_be_bytes());
    digest[12..16].copy_from_slice(&state[3].to_be_bytes());
    digest[16..20].copy_from_slice(&state[4].to_be_bytes());
    digest[20..24].copy_from_slice(&state[5].to_be_bytes());
    digest[24..28].copy_from_slice(&state[6].to_be_bytes());
    assert_eq!(sha224(b"abc"), digest);


    // 3.2.  Test Vector #2
    let state = [
        0x75388b16u32, 0x512776cc, 0x5dba5da1, 0xfd890150, 
        0xb0c6455c, 0xb4f58b19, 0x52522525, 
    ];
    let mut digest = [0u8; Sha224::DIGEST_LEN];
    digest[ 0.. 4].copy_from_slice(&state[0].to_be_bytes());
    digest[ 4.. 8].copy_from_slice(&state[1].to_be_bytes());
    digest[ 8..12].copy_from_slice(&state[2].to_be_bytes());
    digest[12..16].copy_from_slice(&state[3].to_be_bytes());
    digest[16..20].copy_from_slice(&state[4].to_be_bytes());
    digest[20..24].copy_from_slice(&state[5].to_be_bytes());
    digest[24..28].copy_from_slice(&state[6].to_be_bytes());
    assert_eq!(sha224(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), digest);

    // 3.3.  Test Vector #3
    let state = [
        0x20794655u32, 0x980c91d8, 0xbbb4c1ea, 0x97618a4b, 
        0xf03f4258, 0x1948b2ee, 0x4ee7ad67, 
    ];
    let mut digest = [0u8; Sha224::DIGEST_LEN];
    digest[ 0.. 4].copy_from_slice(&state[0].to_be_bytes());
    digest[ 4.. 8].copy_from_slice(&state[1].to_be_bytes());
    digest[ 8..12].copy_from_slice(&state[2].to_be_bytes());
    digest[12..16].copy_from_slice(&state[3].to_be_bytes());
    digest[16..20].copy_from_slice(&state[4].to_be_bytes());
    digest[20..24].copy_from_slice(&state[5].to_be_bytes());
    digest[24..28].copy_from_slice(&state[6].to_be_bytes());
    let msg = vec![b'a'; 1000_000];
    assert_eq!(sha224(&msg), digest);
}

#[test]
fn test_sha256_one_block_message() {
    let msg = b"abc";
    let digest = [
        186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35, 
        176, 3, 97, 163, 150, 23, 122, 156, 180, 16, 255, 97, 242, 0, 21, 173,
    ];
    assert_eq!(Sha256::oneshot(&msg), digest);
}
#[test]
fn test_sha256_multi_block_message() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let digest = [
        36, 141, 106, 97, 210, 6, 56, 184, 229, 192, 38, 147, 12, 62, 96, 57, 
        163, 60, 228, 89, 100, 255, 33, 103, 246, 236, 237, 212, 25, 219, 6, 193,
    ];
    assert_eq!(Sha256::oneshot(&msg[..]), digest);
}
#[test]
fn test_sha256_long_message() {
    let msg = vec![b'a'; 1000_000];
    let digest = [
        205, 199, 110, 92, 153, 20, 251, 146, 129, 161, 199, 226, 132, 215, 62, 
        103, 241, 128, 154, 72, 164, 151, 32, 14, 4, 109, 57, 204, 199, 17, 44, 208,
    ];
    assert_eq!(Sha256::oneshot(&msg), digest);
}

#[test]
fn test_transform_block() {
    let mut state = INITIAL_STATE;
    let data = [0u8; 64];

    transform(&mut state, &data);
    assert_eq!(state, [3663108286, 398046313, 1647531929, 2006957770, 2363872401, 3235013187, 3137272298, 406301144]);
}