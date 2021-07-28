// FIPS-180-2 compliant SHA-256 implementation
//
// The SHA-256 Secure Hash Standard was published by NIST in 2002.
// <http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf>
use core::convert::TryFrom;


#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sha"))]
#[path = "./x86.rs"]
mod platform;

// FEAT_SHA1 & FEAT_SHA256 (SHA1 & SHA2-256 instructions)
#[cfg(all(target_arch = "aarch64", target_feature = "sha2"))]
#[path = "./aarch64.rs"]
mod platform;

#[cfg(all(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sha")),
    not(all(target_arch = "aarch64", target_feature = "sha2")),
))]
#[path = "./generic.rs"]
mod platform;

use self::platform::transform;


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


    #[inline]
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
                offset: 0,
            }
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let mut digest = [0u8; Self::DIGEST_LEN];
        digest.copy_from_slice(&self.inner.finalize()[..Self::DIGEST_LEN]);
        digest
    }

    #[inline]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}


/// SHA2-256
#[derive(Clone)]
pub struct Sha256 {
    buffer: [u8; Self::BLOCK_LEN],
    state: [u32; 8],
    len: u64,      // in bytes.
    offset: usize,
}

impl Sha256 {
    pub const BLOCK_LEN: usize  = 64;
    pub const DIGEST_LEN: usize = 32;

    const BLOCK_LEN_BITS: u64   = Self::BLOCK_LEN as u64 * 8;
    const MLEN_SIZE: usize      = core::mem::size_of::<u64>();
    const MLEN_SIZE_BITS: u64   = Self::MLEN_SIZE as u64 * 8;
    const MAX_PAD_LEN: usize    = Self::BLOCK_LEN + Self::MLEN_SIZE as usize;


    #[inline]
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; 64],
            state: INITIAL_STATE,
            len: 0,
            offset: 0,
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        if self.offset == 0 {
            let chunks = data.chunks_exact(Self::BLOCK_LEN);
            let rem = chunks.remainder();
            let rlen = rem.len();

            for chunk in chunks {
                transform(&mut self.state, &chunk);
                self.len += Self::BLOCK_LEN as u64;
            }

            if rlen > 0 {
                self.buffer[..rlen].copy_from_slice(rem);
                self.offset = rlen;
            }

            return ();
        }

        let mut i = 0usize;
        while i < data.len() {
            if self.offset < Self::BLOCK_LEN {
                self.buffer[self.offset] = data[i];
                self.offset += 1;
                i += 1;
            }
            
            if self.offset == Self::BLOCK_LEN {
                transform(&mut self.state, &self.buffer);
                self.offset = 0;
                self.len += Self::BLOCK_LEN as u64;
            }
        }
    }

    #[inline]
    pub fn finalize(mut self) -> [u8; Self::DIGEST_LEN] {
        // 5. PREPROCESSING 
        //   5.1 Padding the Message 
        //     5.1.1 SHA-1 and SHA-256 
        //     5.1.2 SHA-384 and SHA-512 
        // https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf
        // 
        //                                  423 bits   64 bits or 128 bits
        //                                  -------  -----------
        // 01100001  01100010  01100011  1  00...00  00...011000
        // --------  --------  --------              -----------
        //    "a"      "b"      "c"                   L = 24 bits （大端序）
        // 
        let mlen = self.len + self.offset as u64;  // in bytes
        let mlen_bits = mlen * 8;                  // in bits
        
        // pad len, in bits
        let plen_bits = Self::BLOCK_LEN_BITS - (mlen_bits + Self::MLEN_SIZE_BITS + 1) % Self::BLOCK_LEN_BITS + 1;
        // pad len, in bytes
        let plen = plen_bits / 8;
        debug_assert_eq!(plen_bits % 8, 0);
        debug_assert!(plen > 1);
        debug_assert_eq!((mlen + plen + Self::MLEN_SIZE as u64) % Self::BLOCK_LEN as u64, 0);
        
        // NOTE: MAX_PAD_LEN 是一个很小的数字，所以这里可以安全的 unwrap.
        let plen = usize::try_from(plen).unwrap();

        let mut padding: [u8; Self::MAX_PAD_LEN] = [0u8; Self::MAX_PAD_LEN];
        padding[0] = 0x80;

        let mlen_octets: [u8; Self::MLEN_SIZE] = mlen_bits.to_be_bytes();
        padding[plen..plen + Self::MLEN_SIZE].copy_from_slice(&mlen_octets);
        
        let data = &padding[..plen + Self::MLEN_SIZE];
        self.update(data);

        // NOTE: 数据填充完毕后，此时已经处理的消息应该是 BLOCK_LEN 的倍数，因此，offset 此时已被清零。
        debug_assert_eq!(self.offset, 0);

        
        let mut output = [0u8; Self::DIGEST_LEN];
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
    
    #[inline]
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