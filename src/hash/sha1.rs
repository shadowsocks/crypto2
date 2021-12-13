// FIPS-180-1 compliant SHA-1 implementation
//
// The SHA-1 standard was published by NIST in 1993.
// https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf
//
// ❗️ SHA1算法在2005年后被证实存在弱点，可以被加以破解。
// ‼️ SHA1算法在2017年被证实无法防止碰撞攻击，因此不适用于安全性认证。
use core::convert::TryFrom;

// NOTE: 虽然在 X86 和 AArch64 架构上，有很多款芯片都支持对 SHA1 加速，
//       但是考虑到 SHA1 已经被证实存在弱点，所以这里不再对 SHA1 的代码
//       做任何性能方面的改进，以减轻代码维护工作。
//
// 如果你需要更好的性能，建议参考 `noloader/SHA-Intrinsics` 的代码自行实现：
//      https://github.com/noloader/SHA-Intrinsics/blob/master/sha1-arm.c
//      https://github.com/noloader/SHA-Intrinsics/blob/master/sha1-x86.c
//
const K1: u32 = 0x5a827999;
const K2: u32 = 0x6ed9eba1;
const K3: u32 = 0x8f1bbcdc;
const K4: u32 = 0xca62c1d6;

const INITIAL_STATE: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// SHA1
pub fn sha1<T: AsRef<[u8]>>(data: T) -> [u8; Sha1::DIGEST_LEN] {
    Sha1::oneshot(data)
}

/// SHA1
#[derive(Clone)]
pub struct Sha1 {
    buffer: [u8; Self::BLOCK_LEN],
    state: [u32; 5],
    len: u64, // in bytes.
    offset: usize,
}

impl Sha1 {
    pub const BLOCK_LEN: usize = 64;
    pub const DIGEST_LEN: usize = 20;

    const BLOCK_LEN_BITS: u64 = Self::BLOCK_LEN as u64 * 8;
    const MLEN_SIZE: usize = core::mem::size_of::<u64>();
    const MLEN_SIZE_BITS: u64 = Self::MLEN_SIZE as u64 * 8;
    const MAX_PAD_LEN: usize = Self::BLOCK_LEN + Self::MLEN_SIZE as usize;

    pub fn new() -> Self {
        Self {
            buffer: [0u8; 64],
            state: INITIAL_STATE,
            len: 0,
            offset: 0,
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
                transform(&mut self.state, &self.buffer);
                self.offset = 0;
                self.len += Self::BLOCK_LEN as u64;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; Self::DIGEST_LEN] {
        let mlen = self.len + self.offset as u64; // in bytes
        let mlen_bits = mlen * 8; // in bits

        // pad len, in bits
        let plen_bits = Self::BLOCK_LEN_BITS
            - (mlen_bits + Self::MLEN_SIZE_BITS + 1) % Self::BLOCK_LEN_BITS
            + 1;
        // pad len, in bytes
        let plen = plen_bits / 8;
        debug_assert_eq!(plen_bits % 8, 0);
        debug_assert!(plen > 1);
        debug_assert_eq!(
            (mlen + plen + Self::MLEN_SIZE as u64) % Self::BLOCK_LEN as u64,
            0
        );

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
        output[0..4].copy_from_slice(&self.state[0].to_be_bytes());
        output[4..8].copy_from_slice(&self.state[1].to_be_bytes());
        output[8..12].copy_from_slice(&self.state[2].to_be_bytes());
        output[12..16].copy_from_slice(&self.state[3].to_be_bytes());
        output[16..20].copy_from_slice(&self.state[4].to_be_bytes());
        output
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}

// https://github.com/B-Con/crypto-algorithms/blob/master/sha1.c
#[inline]
fn transform(state: &mut [u32; 5], block: &[u8]) {
    debug_assert_eq!(state.len(), 5);
    debug_assert_eq!(block.len(), Sha1::BLOCK_LEN);

    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4 + 0],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    for i in 0..20 {
        let t = a
            .rotate_left(5)
            .wrapping_add((b & c) ^ (!b & d))
            .wrapping_add(e)
            .wrapping_add(K1)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for i in 20..40 {
        let t = a
            .rotate_left(5)
            .wrapping_add(b ^ c ^ d)
            .wrapping_add(e)
            .wrapping_add(K2)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for i in 40..60 {
        let t = a
            .rotate_left(5)
            .wrapping_add((b & c) ^ (b & d) ^ (c & d))
            .wrapping_add(e)
            .wrapping_add(K3)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for i in 60..80 {
        let t = a
            .rotate_left(5)
            .wrapping_add(b ^ c ^ d)
            .wrapping_add(e)
            .wrapping_add(K4)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[test]
fn test_sha1_one_block_message() {
    let msg = b"abc";
    let digest = [
        169, 153, 62, 54, 71, 6, 129, 106, 186, 62, 37, 113, 120, 80, 194, 108, 156, 208, 216, 157,
    ];

    assert_eq!(sha1(&msg[..]), digest);
}
#[test]
fn test_sha1_multi_block_message() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let digest = [
        132, 152, 62, 68, 28, 59, 210, 110, 186, 174, 74, 161, 249, 81, 41, 229, 229, 70, 112, 241,
    ];
    assert_eq!(sha1(&msg[..]), digest);
}
#[test]
fn test_sha1_long_message() {
    let msg = vec![b'a'; 1000_000];
    let digest = [
        52, 170, 151, 60, 212, 196, 218, 164, 246, 30, 235, 43, 219, 173, 39, 49, 101, 52, 1, 111,
    ];
    assert_eq!(sha1(&msg), digest);
}
