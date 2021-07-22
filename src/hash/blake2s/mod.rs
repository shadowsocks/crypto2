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
const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 
];


mod generic;
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2",
))]
mod x86;


#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2",
))]
use self::x86::transform;


/// BLAKE2s-224
pub fn blake2s_224<T: AsRef<[u8]>>(data: T) -> [u8; Blake2s224::DIGEST_LEN] {
    Blake2s224::oneshot(data)
}

/// BLAKE2s-256
pub fn blake2s_256<T: AsRef<[u8]>>(data: T) -> [u8; Blake2s256::DIGEST_LEN] {
    // Blake2s256::oneshot(data)
    
    // NOTE: 后续所有的 摘要函数 的 oneshot 都应该避免使用 流式写法。（流式写法在 Update 时的 Copy 非常低效，在大部分场景里面也无必要）
    let data = data.as_ref();

    // parameter block
    // digest_length, key_length, fanout, depth
    let p1 = u32::from_le_bytes([32, 0, 1, 1]);

    // IV XOR ParamBlock
    let s1 = BLAKE2S_IV[0] ^ p1;
    let mut state: [u32; 8] = [
        // H
        s1,          BLAKE2S_IV[1], 
        BLAKE2S_IV[2], BLAKE2S_IV[3],
        BLAKE2S_IV[4], BLAKE2S_IV[5], 
        BLAKE2S_IV[6], BLAKE2S_IV[7],
    ];

    let mut block_counter = 0u64;
    
    let chunks = data.chunks_exact(Blake2s256::BLOCK_LEN);
    let rem = chunks.remainder();

    for chunk in chunks {
        block_counter = block_counter.wrapping_add(Blake2s256::BLOCK_LEN as u64);
        transform(&mut state, chunk, block_counter, 0);
    }

    let rlen = rem.len();
    
    let mut block = [0u8; Blake2s256::BLOCK_LEN];
    if rlen > 0 {
        block[..rlen].copy_from_slice(&rem);
    }

    block_counter = block_counter.wrapping_add(rlen as u64);
    transform(&mut state, &block, block_counter, u32::MAX as u64);

    let mut hash = [0u8; Blake2s::H_MAX]; // 32
    hash[ 0.. 4].copy_from_slice(&state[0].to_le_bytes());
    hash[ 4.. 8].copy_from_slice(&state[1].to_le_bytes());
    hash[ 8..12].copy_from_slice(&state[2].to_le_bytes());
    hash[12..16].copy_from_slice(&state[3].to_le_bytes());
    hash[16..20].copy_from_slice(&state[4].to_le_bytes());
    hash[20..24].copy_from_slice(&state[5].to_le_bytes());
    hash[24..28].copy_from_slice(&state[6].to_le_bytes());
    hash[28..32].copy_from_slice(&state[7].to_le_bytes());

    hash
}

macro_rules! impl_blake2s_fixed_output {
    ($name:tt, $hlen:tt) => {
        #[derive(Clone)]
        pub struct $name {
            inner: Blake2s,
        }

        impl $name {
            pub const BLOCK_LEN: usize  = Blake2s::BLOCK_LEN;
            pub const DIGEST_LEN: usize = $hlen;


            #[inline]
            pub fn new() -> Self {
                Self { inner: Blake2s::new(b"", $hlen) }
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

// BLAKE2s-224 ( Digest length 224-bits )
impl_blake2s_fixed_output!(Blake2s224, 28);
// BLAKE2s-256 ( Digest length 256-bits )
impl_blake2s_fixed_output!(Blake2s256, 32);


#[derive(Clone)]
pub struct Blake2s {
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
    state: [u32; 8],
    block_counter: u64, // T0, T1
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
                self.block_counter = self.block_counter.wrapping_add(Self::BLOCK_LEN as u64);
                
                transform(&mut self.state, &self.buffer, self.block_counter, 0);
                self.offset = 0;
            }
        }
    }

    pub fn finalize(mut self, out: &mut [u8]) {
        assert_eq!(out.len(), self.hlen);

        self.block_counter = self.block_counter.wrapping_add(self.offset as u64);

        // Padding
        while self.offset < Self::BLOCK_LEN {
            self.buffer[self.offset] = 0;
            self.offset += 1;
        }

        transform(&mut self.state, &self.buffer, self.block_counter, u32::MAX as u64);

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