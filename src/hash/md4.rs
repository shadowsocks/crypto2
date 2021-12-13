// The MD4 Message-Digest Algorithm
// <https://tools.ietf.org/html/rfc1320>
use core::convert::TryFrom;

const INITIAL_STATE: [u32; 4] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];

pub fn md4<T: AsRef<[u8]>>(data: T) -> [u8; Md4::DIGEST_LEN] {
    Md4::oneshot(data)
}

#[derive(Clone)]
pub struct Md4 {
    buffer: [u8; Self::BLOCK_LEN],
    state: [u32; 4],
    len: u64, // in bytes.
    offset: usize,
}

impl Md4 {
    pub const BLOCK_LEN: usize = 64;
    pub const DIGEST_LEN: usize = 16;

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

        let mlen_octets: [u8; Self::MLEN_SIZE] = mlen_bits.to_le_bytes();
        padding[plen..plen + Self::MLEN_SIZE].copy_from_slice(&mlen_octets);

        let data = &padding[..plen + Self::MLEN_SIZE];
        self.update(data);

        // NOTE: 数据填充完毕后，此时已经处理的消息应该是 BLOCK_LEN 的倍数，因此，offset 此时已被清零。
        debug_assert_eq!(self.offset, 0);

        let mut output = [0u8; Self::DIGEST_LEN];
        output[0..4].copy_from_slice(&self.state[0].to_le_bytes());
        output[4..8].copy_from_slice(&self.state[1].to_le_bytes());
        output[8..12].copy_from_slice(&self.state[2].to_le_bytes());
        output[12..16].copy_from_slice(&self.state[3].to_le_bytes());
        output
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}

macro_rules! F {
    ($x:expr, $y:expr, $z:expr) => {
        (($x) & ($y)) | (!($x) & ($z))
    };
}
macro_rules! G {
    ($x:expr, $y:expr, $z:expr) => {
        (($x) & ($y)) | (($x) & ($z)) | (($y) & ($z))
    };
}
macro_rules! H {
    ($x:expr, $y:expr, $z:expr) => {
        ($x) ^ ($y) ^ ($z)
    };
}

macro_rules! FF {
    ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
        $a.wrapping_add(F!($b, $c, $d))
            .wrapping_add($k)
            .rotate_left($s)
    };
}
macro_rules! GG {
    ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
        $a.wrapping_add(G!($b, $c, $d))
            .wrapping_add($k)
            .wrapping_add(0x5A827999)
            .rotate_left($s)
    };
}
macro_rules! HH {
    ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
        $a.wrapping_add(H!($b, $c, $d))
            .wrapping_add($k)
            .wrapping_add(0x6ED9EBA1)
            .rotate_left($s)
    };
}

#[inline]
fn transform(state: &mut [u32; 4], block: &[u8]) {
    debug_assert_eq!(state.len(), 4);
    debug_assert_eq!(block.len(), Md4::BLOCK_LEN);

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    // load block to data
    let mut data = [0u32; 16];
    for i in 0usize..16 {
        let idx = i * 4;
        data[i] = u32::from_le_bytes([
            block[idx + 0],
            block[idx + 1],
            block[idx + 2],
            block[idx + 3],
        ]);
    }

    // round 1
    for &i in &[0usize, 4, 8, 12] {
        a = FF!(a, b, c, d, data[i], 3);
        d = FF!(d, a, b, c, data[i + 1], 7);
        c = FF!(c, d, a, b, data[i + 2], 11);
        b = FF!(b, c, d, a, data[i + 3], 19);
    }

    // round 2
    for i in 0..4 {
        a = GG!(a, b, c, d, data[i], 3);
        d = GG!(d, a, b, c, data[i + 4], 5);
        c = GG!(c, d, a, b, data[i + 8], 9);
        b = GG!(b, c, d, a, data[i + 12], 13);
    }

    // round 3
    for &i in &[0usize, 2, 1, 3] {
        a = HH!(a, b, c, d, data[i], 3);
        d = HH!(d, a, b, c, data[i + 8], 9);
        c = HH!(c, d, a, b, data[i + 4], 11);
        b = HH!(b, c, d, a, data[i + 12], 15);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

#[test]
fn test_md4() {
    // A.5 Test suite
    // <https://tools.ietf.org/html/rfc1320#appendix-A.5>
    assert_eq!(
        &md4(""),
        &hex::decode("31d6cfe0d16ae931b73c59d7e0c089c0").unwrap()[..]
    );
    assert_eq!(
        &md4("a"),
        &hex::decode("bde52cb31de33e46245e05fbdbd6fb24").unwrap()[..]
    );
    assert_eq!(
        &md4("abc"),
        &hex::decode("a448017aaf21d8525fc10ae87aa6729d").unwrap()[..]
    );
    assert_eq!(
        &md4("message digest"),
        &hex::decode("d9130a8164549fe818874806e1c7014b").unwrap()[..]
    );
    assert_eq!(
        &md4("abcdefghijklmnopqrstuvwxyz"),
        &hex::decode("d79e1c308aa5bbcdeea8ed63df412da9").unwrap()[..]
    );
    assert_eq!(
        &md4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
        &hex::decode("043f8582f241db351ce627e153e7f0e4").unwrap()[..]
    );
    assert_eq!(
        &md4("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
        &hex::decode("e33b4ddc9c38f2199c3e7b164fcc0536").unwrap()[..]
    );
}
