// The MD5 Message-Digest Algorithm
// https://tools.ietf.org/html/rfc1321
// 
// https://people.csail.mit.edu/rivest/Md5.c
// 
// ❗️ MD5算法在1996年后被证实存在弱点，可以被加以破解。
// ‼️ MD5算法在2004年被证实无法防止碰撞攻击，因此不适用于安全性认证。
use core::convert::TryFrom;

// Use binary integer part of the sines of integers (Radians) as constants:
//    for i from 0 to 63 do
//        K[i] := floor(232 × abs (sin(i + 1)))
//    end for
// precomputed table
#[allow(dead_code)]
const K64: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

// s specifies the per-round shift amounts
const S11: u32 = 7;
const S12: u32 = 12;
const S13: u32 = 17;
const S14: u32 = 22;

const S21: u32 = 5;
const S22: u32 = 9;
const S23: u32 = 14;
const S24: u32 = 20;

const S31: u32 = 4;
const S32: u32 = 11;
const S33: u32 = 16;
const S34: u32 = 23;

const S41: u32 = 6;
const S42: u32 = 10;
const S43: u32 = 15;
const S44: u32 = 21;

#[allow(dead_code)]
const S64: [u32; 64] = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
];

// Initialize variables
const INITIAL_STATE: [u32; 4] = [ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 ];


pub fn md5<T: AsRef<[u8]>>(data: T) -> [u8; Md5::DIGEST_LEN] {
    Md5::oneshot(data)
}

#[derive(Clone)]
pub struct Md5 {
    buffer: [u8; Self::BLOCK_LEN],
    state: [u32; 4],
    len: usize,      // in bytes.
}

impl Md5 {
    pub const BLOCK_LEN: usize  = 64;
    pub const DIGEST_LEN: usize = 16;


    pub fn new() -> Self {
        Self {
            buffer: [0u8; Self::BLOCK_LEN],
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
    ($b:expr, $c:expr, $d:expr) => (
        ( ($b) & ($c) ) | ( !($b) & ($d) )
    )
}
macro_rules! G {
    ($b:expr, $c:expr, $d:expr) => (
        ( ($b) & ($d) ) | ( ($c) & !($d) )
    )
}
macro_rules! H {
    ($b:expr, $c:expr, $d:expr) => (
        ($b) ^ ($c) ^ ($d)
    )
}
macro_rules! I {
    ($b:expr, $c:expr, $d:expr) => (
        ($c) ^ ( ($b) | !($d) )
    )
}
macro_rules! FF {
    ($a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $s:expr, $ac:expr) => (
        ($a) = ($a).wrapping_add(F!($b, $c, $d))
                    .wrapping_add($x)
                    .wrapping_add($ac)
                    .rotate_left($s)
                    .wrapping_add($b);
    )
}
macro_rules! GG {
    ($a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $s:expr, $ac:expr) => (
        ($a) = ($a).wrapping_add(G!($b, $c, $d))
                    .wrapping_add($x)
                    .wrapping_add($ac)
                    .rotate_left($s)
                    .wrapping_add($b);
    )
}
macro_rules! HH {
    ($a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $s:expr, $ac:expr) => (
        ($a) = ($a).wrapping_add(H!($b, $c, $d))
                    .wrapping_add($x)
                    .wrapping_add($ac)
                    .rotate_left($s)
                    .wrapping_add($b);
    )
}
macro_rules! II {
    ($a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $s:expr, $ac:expr) => (
        ($a) = ($a).wrapping_add(I!($b, $c, $d))
                    .wrapping_add($x)
                    .wrapping_add($ac)
                    .rotate_left($s)
                    .wrapping_add($b);
    )
}

#[inline]
fn transform(state: &mut [u32; 4], block: &[u8]) {
    debug_assert_eq!(state.len(), 4);
    debug_assert_eq!(block.len(), Md5::BLOCK_LEN);

    let mut w = [0u32; 16];
    for i in 0..16 {
        w[i] = u32::from_le_bytes([
            block[i*4 + 0], block[i*4 + 1],
            block[i*4 + 2], block[i*4 + 3],
        ]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    // Round 1
    FF!{a, b, c, d, w[ 0], S11, 0xd76aa478}; /* 1 */
    FF!(d, a, b, c, w[ 1], S12, 0xe8c7b756); /* 2 */
    FF!(c, d, a, b, w[ 2], S13, 0x242070db); /* 3 */
    FF!(b, c, d, a, w[ 3], S14, 0xc1bdceee); /* 4 */
    FF!(a, b, c, d, w[ 4], S11, 0xf57c0faf); /* 5 */
    FF!(d, a, b, c, w[ 5], S12, 0x4787c62a); /* 6 */
    FF!(c, d, a, b, w[ 6], S13, 0xa8304613); /* 7 */
    FF!(b, c, d, a, w[ 7], S14, 0xfd469501); /* 8 */
    FF!(a, b, c, d, w[ 8], S11, 0x698098d8); /* 9 */
    FF!(d, a, b, c, w[ 9], S12, 0x8b44f7af); /* 10 */
    FF!(c, d, a, b, w[10], S13, 0xffff5bb1); /* 11 */
    FF!(b, c, d, a, w[11], S14, 0x895cd7be); /* 12 */
    FF!(a, b, c, d, w[12], S11, 0x6b901122); /* 13 */
    FF!(d, a, b, c, w[13], S12, 0xfd987193); /* 14 */
    FF!(c, d, a, b, w[14], S13, 0xa679438e); /* 15 */
    FF!(b, c, d, a, w[15], S14, 0x49b40821); /* 16 */

    // Round 2
    GG!(a, b, c, d, w[ 1], S21, 0xf61e2562); /* 17 */
    GG!(d, a, b, c, w[ 6], S22, 0xc040b340); /* 18 */
    GG!(c, d, a, b, w[11], S23, 0x265e5a51); /* 19 */
    GG!(b, c, d, a, w[ 0], S24, 0xe9b6c7aa); /* 20 */
    GG!(a, b, c, d, w[ 5], S21, 0xd62f105d); /* 21 */
    GG!(d, a, b, c, w[10], S22,  0x2441453); /* 22 */
    GG!(c, d, a, b, w[15], S23, 0xd8a1e681); /* 23 */
    GG!(b, c, d, a, w[ 4], S24, 0xe7d3fbc8); /* 24 */
    GG!(a, b, c, d, w[ 9], S21, 0x21e1cde6); /* 25 */
    GG!(d, a, b, c, w[14], S22, 0xc33707d6); /* 26 */
    GG!(c, d, a, b, w[ 3], S23, 0xf4d50d87); /* 27 */
    GG!(b, c, d, a, w[ 8], S24, 0x455a14ed); /* 28 */
    GG!(a, b, c, d, w[13], S21, 0xa9e3e905); /* 29 */
    GG!(d, a, b, c, w[ 2], S22, 0xfcefa3f8); /* 30 */
    GG!(c, d, a, b, w[ 7], S23, 0x676f02d9); /* 31 */
    GG!(b, c, d, a, w[12], S24, 0x8d2a4c8a); /* 32 */

    // Round 3
    HH!(a, b, c, d, w[ 5], S31, 0xfffa3942); /* 33 */
    HH!(d, a, b, c, w[ 8], S32, 0x8771f681); /* 34 */
    HH!(c, d, a, b, w[11], S33, 0x6d9d6122); /* 35 */
    HH!(b, c, d, a, w[14], S34, 0xfde5380c); /* 36 */
    HH!(a, b, c, d, w[ 1], S31, 0xa4beea44); /* 37 */
    HH!(d, a, b, c, w[ 4], S32, 0x4bdecfa9); /* 38 */
    HH!(c, d, a, b, w[ 7], S33, 0xf6bb4b60); /* 39 */
    HH!(b, c, d, a, w[10], S34, 0xbebfbc70); /* 40 */
    HH!(a, b, c, d, w[13], S31, 0x289b7ec6); /* 41 */
    HH!(d, a, b, c, w[ 0], S32, 0xeaa127fa); /* 42 */
    HH!(c, d, a, b, w[ 3], S33, 0xd4ef3085); /* 43 */
    HH!(b, c, d, a, w[ 6], S34,  0x4881d05); /* 44 */
    HH!(a, b, c, d, w[ 9], S31, 0xd9d4d039); /* 45 */
    HH!(d, a, b, c, w[12], S32, 0xe6db99e5); /* 46 */
    HH!(c, d, a, b, w[15], S33, 0x1fa27cf8); /* 47 */
    HH!(b, c, d, a, w[ 2], S34, 0xc4ac5665); /* 48 */

    // Round 4
    II!(a, b, c, d, w[ 0], S41, 0xf4292244); /* 49 */
    II!(d, a, b, c, w[ 7], S42, 0x432aff97); /* 50 */
    II!(c, d, a, b, w[14], S43, 0xab9423a7); /* 51 */
    II!(b, c, d, a, w[ 5], S44, 0xfc93a039); /* 52 */
    II!(a, b, c, d, w[12], S41, 0x655b59c3); /* 53 */
    II!(d, a, b, c, w[ 3], S42, 0x8f0ccc92); /* 54 */
    II!(c, d, a, b, w[10], S43, 0xffeff47d); /* 55 */
    II!(b, c, d, a, w[ 1], S44, 0x85845dd1); /* 56 */
    II!(a, b, c, d, w[ 8], S41, 0x6fa87e4f); /* 57 */
    II!(d, a, b, c, w[15], S42, 0xfe2ce6e0); /* 58 */
    II!(c, d, a, b, w[ 6], S43, 0xa3014314); /* 59 */
    II!(b, c, d, a, w[13], S44, 0x4e0811a1); /* 60 */
    II!(a, b, c, d, w[ 4], S41, 0xf7537e82); /* 61 */
    II!(d, a, b, c, w[11], S42, 0xbd3af235); /* 62 */
    II!(c, d, a, b, w[ 2], S43, 0x2ad7d2bb); /* 63 */
    II!(b, c, d, a, w[ 9], S44, 0xeb86d391); /* 64 */

    // let mut f = 0u32;
    // let mut g = 0u32;
    // for i in 0usize..16 {
    //     // F := (B and C) or ((not B) and D)
    //     // g := i
    //     f = F!(b, c, d);
    //     g = u32::try_from(i).unwrap();

    //     // F := F + A + K[i] + M[g]  // M[g] must be a 32-bits block
    //     // A := D
    //     // D := C
    //     // C := B
    //     // B := B + leftrotate(F, s[i])
    //     f = f.wrapping_add(a)
    //             .wrapping_add(K64[i])
    //             .wrapping_add(w[g as usize]);
    //     a = d;
    //     d = c;
    //     c = b;
    //     b = b.wrapping_add(f.rotate_left(S64[i]));
    // }
    // for i in 16usize..32 {
    //     // F := (D and B) or ((not D) and C)
    //     // g := (5×i + 1) mod 16
    //     f = G!(b, c, d);
    //     g = ( 5 * u32::try_from(i).unwrap() + 1 ) % 16;

    //     f = f.wrapping_add(a)
    //             .wrapping_add(K64[i])
    //             .wrapping_add(w[g as usize]);
    //     a = d;
    //     d = c;
    //     c = b;
    //     b = b.wrapping_add(f.rotate_left(S64[i]));
    // }
    // for i in 32usize..48 {
    //     // F := B xor C xor D
    //     // g := (3×i + 5) mod 16
    //     f = H!(b, c, d);
    //     g = ( 3 * u32::try_from(i).unwrap() + 5 ) % 16;

    //     f = f.wrapping_add(a)
    //             .wrapping_add(K64[i])
    //             .wrapping_add(w[g as usize]);
    //     a = d;
    //     d = c;
    //     c = b;
    //     b = b.wrapping_add(f.rotate_left(S64[i]));
    // }
    // for i in 48usize..64 {
    //     // F := C xor (B or (not D))
    //     // g := (7×i) mod 16
    //     f = I!(b, c, d);
    //     g = ( 7 * u32::try_from(i).unwrap() ) % 16;

    //     f = f.wrapping_add(a)
    //             .wrapping_add(K64[i])
    //             .wrapping_add(w[g as usize]);
    //     a = d;
    //     d = c;
    //     c = b;
    //     b = b.wrapping_add(f.rotate_left(S64[i]));
    // }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}


#[test]
fn test_md5() {
    // A.5 Test suite
    // https://tools.ietf.org/html/rfc1321#appendix-A.5
    fn hexdigest(digest: &[u8]) -> String {
        let mut s = String::new();
        for n in digest.iter() {
            s.push_str(format!("{:02x}", n).as_str());
        }
        s
    }

    let suites: &[(&[u8], &str)] = &[
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (b"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
        (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"),
        (b"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"),
    ];
    for suite in suites.iter() {
        let hexdigest = hexdigest(&Md5::oneshot(suite.0));
        assert_eq!(hexdigest, suite.1);
    }
}

#[test]
fn test_md5_one_block_message() {
    let msg = b"abc";
    let digest = [144, 1, 80, 152, 60, 210, 79, 176, 214, 150, 63, 125, 40, 225, 127, 114];
    assert_eq!(Md5::oneshot(msg), digest);
}
#[test]
fn test_md5_multi_block_message() {
    let msg: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let digest = [130, 21, 239, 7, 150, 162, 11, 202, 170, 225, 22, 211, 135, 108, 102, 74];
    assert_eq!(Md5::oneshot(msg), digest);
}
#[test]
fn test_md5_long_message() {
    let msg = vec![b'a'; 1000_000];
    let digest = [119, 7, 214, 174, 78, 2, 124, 112, 238, 162, 169, 53, 194, 41, 111, 33];
    assert_eq!(Md5::oneshot(&msg), digest);
}