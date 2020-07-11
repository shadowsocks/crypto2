// The MD4 Message-Digest Algorithm
// https://tools.ietf.org/html/rfc1320
use core::convert::TryFrom;


const INITIAL_STATE: [u32; 4] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];


pub fn md4<T: AsRef<[u8]>>(data: T) -> [u8; Md4::DIGEST_LEN] {
    Md4::oneshot(data)
}

#[derive(Clone)]
pub struct Md4 {
    buffer: [u8; 64],
    state: [u32; 4],
    len: usize,      // in bytes.
}

impl Md4 {
    pub const BLOCK_LEN: usize  = 64;
    pub const DIGEST_LEN: usize = 16;

    
    pub fn new() -> Self {
        Self {
            buffer: [0u8; 64],
            state: INITIAL_STATE,
            len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        // TODO:
        // Unlike Sha1 and Sha2, the length value in MD5 is defined as
        // the length of the message mod 2^64 - ie: integer overflow is OK.
        if data.len() == 0 {
            return ();
        }

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
        // last_block
        let len_bits = u64::try_from(self.len).unwrap() * 8;
        let n = self.len % Self::BLOCK_LEN;
        if n == 0 {
            let mut block = [0u8; 64];
            block[0] = 0x80;
            block[56..].copy_from_slice(&len_bits.to_le_bytes());
            transform(&mut self.state, &block);
        } else {
            self.buffer[n] = 0x80;
            for i in n+1..64 {
                self.buffer[i] = 0;
            }
            if 64 - n - 1 >= 8 {
                self.buffer[56..].copy_from_slice(&len_bits.to_le_bytes());
                transform(&mut self.state, &self.buffer);
            } else {
                transform(&mut self.state, &self.buffer);
                let mut block = [0u8; 64];
                block[56..].copy_from_slice(&len_bits.to_le_bytes());
                transform(&mut self.state, &block);
            }
        }

        let mut output = [0u8; Self::DIGEST_LEN];
        output[ 0.. 4].copy_from_slice(&self.state[0].to_le_bytes());
        output[ 4.. 8].copy_from_slice(&self.state[1].to_le_bytes());
        output[ 8..12].copy_from_slice(&self.state[2].to_le_bytes());
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
    ($x:expr, $y:expr, $z:expr) => (
        ( ($x) & ($y) ) | ( !($x) & ($z) )
    )
}
macro_rules! G {
    ($x:expr, $y:expr, $z:expr) => (
        (($x) & ($y)) | (($x) & ($z)) | (($y) & ($z))
    )
}
macro_rules! H {
    ($x:expr, $y:expr, $z:expr) => (
        ($x) ^ ($y) ^ ($z)
    )
}

macro_rules! FF {
    ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => (
        $a.wrapping_add(F!($b, $c, $d)).wrapping_add($k).rotate_left($s)
    )
}
macro_rules! GG {
    ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => (
        $a.wrapping_add(G!($b, $c, $d)).wrapping_add($k).wrapping_add(0x5A827999).rotate_left($s)
    )
}
macro_rules! HH {
    ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => (
        $a.wrapping_add(H!($b, $c, $d)).wrapping_add($k).wrapping_add(0x6ED9EBA1).rotate_left($s)
    )
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
    // https://tools.ietf.org/html/rfc1320#appendix-A.5
    assert_eq!(&md4(""),
        &hex::decode("31d6cfe0d16ae931b73c59d7e0c089c0").unwrap()[..]);
    assert_eq!(&md4("a"),
        &hex::decode("bde52cb31de33e46245e05fbdbd6fb24").unwrap()[..]);
    assert_eq!(&md4("abc"),
        &hex::decode("a448017aaf21d8525fc10ae87aa6729d").unwrap()[..]);
    assert_eq!(&md4("message digest"),
        &hex::decode("d9130a8164549fe818874806e1c7014b").unwrap()[..]);
    assert_eq!(&md4("abcdefghijklmnopqrstuvwxyz"),
        &hex::decode("d79e1c308aa5bbcdeea8ed63df412da9").unwrap()[..]);
    assert_eq!(&md4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
        &hex::decode("043f8582f241db351ce627e153e7f0e4").unwrap()[..]);
    assert_eq!(&md4("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
        &hex::decode("e33b4ddc9c38f2199c3e7b164fcc0536").unwrap()[..]);
}