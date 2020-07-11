// A Description of the ARIA Encryption Algorithm
// https://tools.ietf.org/html/rfc5794
// 
// Korean Standard Block Cipher Algorithm Block Cipher Algorithm ARIA （韩国技术标准局（KATS））
// http://210.104.33.10/ARIA/index-e.html
// 
// Specification of ARIA
// http://210.104.33.10/ARIA/doc/ARIA-specification-e.pdf
use crate::mem::Zeroize;


const SB1: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const SB2: [u8; 256] = [
    0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
    0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
    0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
    0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
    0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
    0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
    0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
    0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
    0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
    0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
    0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
    0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
    0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
    0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
    0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
    0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81,
];

const SB3: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const SB4: [u8; 256] = [
    0x30, 0x68, 0x99, 0x1b, 0x87, 0xb9, 0x21, 0x78, 0x50, 0x39, 0xdb, 0xe1, 0x72, 0x09, 0x62, 0x3c,
    0x3e, 0x7e, 0x5e, 0x8e, 0xf1, 0xa0, 0xcc, 0xa3, 0x2a, 0x1d, 0xfb, 0xb6, 0xd6, 0x20, 0xc4, 0x8d,
    0x81, 0x65, 0xf5, 0x89, 0xcb, 0x9d, 0x77, 0xc6, 0x57, 0x43, 0x56, 0x17, 0xd4, 0x40, 0x1a, 0x4d,
    0xc0, 0x63, 0x6c, 0xe3, 0xb7, 0xc8, 0x64, 0x6a, 0x53, 0xaa, 0x38, 0x98, 0x0c, 0xf4, 0x9b, 0xed,
    0x7f, 0x22, 0x76, 0xaf, 0xdd, 0x3a, 0x0b, 0x58, 0x67, 0x88, 0x06, 0xc3, 0x35, 0x0d, 0x01, 0x8b,
    0x8c, 0xc2, 0xe6, 0x5f, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1e, 0xe5, 0xe2, 0x54, 0xd8, 0x10, 0xce,
    0x7a, 0xe8, 0x08, 0x2c, 0x12, 0x97, 0x32, 0xab, 0xb4, 0x27, 0x0a, 0x23, 0xdf, 0xef, 0xca, 0xd9,
    0xb8, 0xfa, 0xdc, 0x31, 0x6b, 0xd1, 0xad, 0x19, 0x49, 0xbd, 0x51, 0x96, 0xee, 0xe4, 0xa8, 0x41,
    0xda, 0xff, 0xcd, 0x55, 0x86, 0x36, 0xbe, 0x61, 0x52, 0xf8, 0xbb, 0x0e, 0x82, 0x48, 0x69, 0x9a,
    0xe0, 0x47, 0x9e, 0x5c, 0x04, 0x4b, 0x34, 0x15, 0x79, 0x26, 0xa7, 0xde, 0x29, 0xae, 0x92, 0xd7,
    0x84, 0xe9, 0xd2, 0xba, 0x5d, 0xf3, 0xc5, 0xb0, 0xbf, 0xa4, 0x3b, 0x71, 0x44, 0x46, 0x2b, 0xfc,
    0xeb, 0x6f, 0xd5, 0xf6, 0x14, 0xfe, 0x7c, 0x70, 0x5a, 0x7d, 0xfd, 0x2f, 0x18, 0x83, 0x16, 0xa5,
    0x91, 0x1f, 0x05, 0x95, 0x74, 0xa9, 0xc1, 0x5b, 0x4a, 0x85, 0x6d, 0x13, 0x07, 0x4f, 0x4e, 0x45,
    0xb2, 0x0f, 0xc9, 0x1c, 0xa6, 0xbc, 0xec, 0x73, 0x90, 0x7b, 0xcf, 0x59, 0x8f, 0xa1, 0xf9, 0x2d,
    0xf2, 0xb1, 0x00, 0x94, 0x37, 0x9f, 0xd0, 0x2e, 0x9c, 0x6e, 0x28, 0x3f, 0x80, 0xf0, 0x3d, 0xd3,
    0x25, 0x8a, 0xb5, 0xe7, 0x42, 0xb3, 0xc7, 0xea, 0xf7, 0x4c, 0x11, 0x33, 0x03, 0xa2, 0xac, 0x60,
];

const C1: u128 = 0x517cc1b727220a94fe13abe8fa9a6ee0;
const C2: u128 = 0x6db14acc9e21c820ff28b1d5ef5de2b0;
const C3: u128 = 0xdb92371d2126e9700324977504e8c90e;


macro_rules! FO {
    ($d:expr, $rk:expr) => {
        A!(SL1!($d ^ $rk))
    }
}
macro_rules! FE {
    ($d:expr, $rk:expr) => {
        A!(SL2!($d ^ $rk))
    }
}

macro_rules! SL1 {
    ($a:expr) => {
        {
            let mut octets = $a.to_be_bytes();

            octets[ 0] = SB1[octets[ 0] as usize];
            octets[ 1] = SB2[octets[ 1] as usize];
            octets[ 2] = SB3[octets[ 2] as usize];
            octets[ 3] = SB4[octets[ 3] as usize];

            octets[ 4] = SB1[octets[ 4] as usize];
            octets[ 5] = SB2[octets[ 5] as usize];
            octets[ 6] = SB3[octets[ 6] as usize];
            octets[ 7] = SB4[octets[ 7] as usize];

            octets[ 8] = SB1[octets[ 8] as usize];
            octets[ 9] = SB2[octets[ 9] as usize];
            octets[10] = SB3[octets[10] as usize];
            octets[11] = SB4[octets[11] as usize];

            octets[12] = SB1[octets[12] as usize];
            octets[13] = SB2[octets[13] as usize];
            octets[14] = SB3[octets[14] as usize];
            octets[15] = SB4[octets[15] as usize];

            u128::from_be_bytes(octets)
        }
    }
}
macro_rules! SL2 {
    ($a:expr) => {
        {
            let mut octets = $a.to_be_bytes();

            octets[ 0] = SB3[octets[ 0] as usize];
            octets[ 1] = SB4[octets[ 1] as usize];
            octets[ 2] = SB1[octets[ 2] as usize];
            octets[ 3] = SB2[octets[ 3] as usize];

            octets[ 4] = SB3[octets[ 4] as usize];
            octets[ 5] = SB4[octets[ 5] as usize];
            octets[ 6] = SB1[octets[ 6] as usize];
            octets[ 7] = SB2[octets[ 7] as usize];

            octets[ 8] = SB3[octets[ 8] as usize];
            octets[ 9] = SB4[octets[ 9] as usize];
            octets[10] = SB1[octets[10] as usize];
            octets[11] = SB2[octets[11] as usize];

            octets[12] = SB3[octets[12] as usize];
            octets[13] = SB4[octets[13] as usize];
            octets[14] = SB1[octets[14] as usize];
            octets[15] = SB2[octets[15] as usize];

            u128::from_be_bytes(octets)
        }
    }
}

macro_rules! A {
    ($a:expr) => {
        {
            let [
                x0, x1,  x2,  x3,  x4,  x5,  x6,  x7, 
                x8, x9, x10, x11, x12, x13, x14, x15,
            ] = $a.to_be_bytes();

            let y0  = x3 ^ x4 ^ x6 ^ x8  ^ x9  ^ x13 ^ x14;
            let y1  = x2 ^ x5 ^ x7 ^ x8  ^ x9  ^ x12 ^ x15;
            let y2  = x1 ^ x4 ^ x6 ^ x10 ^ x11 ^ x12 ^ x15;
            let y3  = x0 ^ x5 ^ x7 ^ x10 ^ x11 ^ x13 ^ x14;
            let y4  = x0 ^ x2 ^ x5 ^ x8  ^ x11 ^ x14 ^ x15;
            let y5  = x1 ^ x3 ^ x4 ^ x9  ^ x10 ^ x14 ^ x15;
            let y6  = x0 ^ x2 ^ x7 ^ x9  ^ x10 ^ x12 ^ x13;
            let y7  = x1 ^ x3 ^ x6 ^ x8  ^ x11 ^ x12 ^ x13;
            let y8  = x0 ^ x1 ^ x4 ^ x7  ^ x10 ^ x13 ^ x15;
            let y9  = x0 ^ x1 ^ x5 ^ x6  ^ x11 ^ x12 ^ x14;
            let y10 = x2 ^ x3 ^ x5 ^ x6  ^ x8  ^ x13 ^ x15;
            let y11 = x2 ^ x3 ^ x4 ^ x7  ^ x9  ^ x12 ^ x14;
            let y12 = x1 ^ x2 ^ x6 ^ x7  ^ x9  ^ x11 ^ x12;
            let y13 = x0 ^ x3 ^ x6 ^ x7  ^ x8  ^ x10 ^ x13;
            let y14 = x0 ^ x3 ^ x4 ^ x5  ^ x9  ^ x11 ^ x14;
            let y15 = x1 ^ x2 ^ x4 ^ x5  ^ x8  ^ x10 ^ x15;

            u128::from_be_bytes([
                y0, y1,  y2,  y3,  y4,  y5,  y6,  y7, 
                y8, y9, y10, y11, y12, y13, y14, y15,
            ])
        }
    }
}


#[derive(Clone)]
pub struct Aria128 {
    ek: [u128; Self::NR * 2],
}

impl Zeroize for Aria128 {
    fn zeroize(&mut self) {
        self.ek.zeroize();
    }
}

impl Drop for Aria128 {
    fn drop(&mut self) {
        self.zeroize();
    }
}


impl core::fmt::Debug for Aria128 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Aria128").finish()
    }
}

impl Aria128 {
    pub const KEY_LEN: usize   = 16;
    pub const BLOCK_LEN: usize = 16;

    const NR: usize  = 12;

    const CK1: u128 = C1;
    const CK2: u128 = C2;
    const CK3: u128 = C3;

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        let kl = u128::from_be_bytes([
            key[ 0], key[ 1], key[ 2], key[ 3], 
            key[ 4], key[ 5], key[ 6], key[ 7], 
            key[ 8], key[ 9], key[10], key[11], 
            key[12], key[13], key[14], key[15], 
        ]);
        let kr = 0u128;

        let w0 = kl;
        let w1 = FO!(w0, Self::CK1) ^ kr;
        let w2 = FE!(w1, Self::CK2) ^ w0;
        let w3 = FO!(w2, Self::CK3) ^ w1;
        
        let mut ek = [0u128; Self::NR * 2];

        ek[ 0] = w0 ^ w1.rotate_right(19);
        ek[ 1] = w1 ^ w2.rotate_right(19);
        ek[ 2] = w2 ^ w3.rotate_right(19);
        ek[ 3] = w0.rotate_right(19) ^ w3;
        ek[ 4] = w0 ^ w1.rotate_right(31);
        ek[ 5] = w1 ^ w2.rotate_right(31);
        ek[ 6] = w2 ^ w3.rotate_right(31);
        ek[ 7] = w0.rotate_right(31) ^ w3;
        ek[ 8] = w0 ^ w1.rotate_left(61);
        ek[ 9] = w1 ^ w2.rotate_left(61);
        ek[10] = w2 ^ w3.rotate_left(61);
        ek[11] = w0.rotate_left(61) ^ w3;
        ek[12] = w0 ^ w1.rotate_left(31); // KEY-128

        ek[13] = A!(ek[11]);
        ek[14] = A!(ek[10]);
        ek[15] = A!(ek[ 9]);
        ek[16] = A!(ek[ 8]);
        ek[17] = A!(ek[ 7]);
        ek[18] = A!(ek[ 6]);
        ek[19] = A!(ek[ 5]);
        ek[20] = A!(ek[ 4]);
        ek[21] = A!(ek[ 3]);
        ek[22] = A!(ek[ 2]);
        ek[23] = A!(ek[ 1]);

        Self { ek }
    }

    pub fn encrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        let mut p = u128::from_be_bytes([
            block[ 0], block[ 1], block[ 2], block[ 3], 
            block[ 4], block[ 5], block[ 6], block[ 7], 
            block[ 8], block[ 9], block[10], block[11], 
            block[12], block[13], block[14], block[15], 
        ]);

        p = FO!(p, self.ek[0]);                  // Round 1
        p = FE!(p, self.ek[1]);                  // Round 2
        p = FO!(p, self.ek[2]);                  // Round 3
        p = FE!(p, self.ek[3]);                  // Round 4
        p = FO!(p, self.ek[4]);                  // Round 5
        p = FE!(p, self.ek[5]);                  // Round 6
        p = FO!(p, self.ek[6]);                  // Round 7
        p = FE!(p, self.ek[7]);                  // Round 8
        p = FO!(p, self.ek[8]);                  // Round 9
        p = FE!(p, self.ek[9]);                  // Round 10
        p = FO!(p, self.ek[10]);                 // Round 11
        p = SL2!(p ^ self.ek[11]) ^ self.ek[12]; // Round 12

        block[..Self::BLOCK_LEN].copy_from_slice(&p.to_be_bytes());
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        let mut c = u128::from_be_bytes([
            block[ 0], block[ 1], block[ 2], block[ 3], 
            block[ 4], block[ 5], block[ 6], block[ 7], 
            block[ 8], block[ 9], block[10], block[11], 
            block[12], block[13], block[14], block[15], 
        ]);

        c  = FO!(c, self.ek[12]);                // Round 1
        c  = FE!(c, self.ek[13]);                // Round 2
        c  = FO!(c, self.ek[14]);                // Round 3
        c  = FE!(c, self.ek[15]);                // Round 4
        c  = FO!(c, self.ek[16]);                // Round 5
        c  = FE!(c, self.ek[17]);                // Round 6
        c  = FO!(c, self.ek[18]);                // Round 7
        c  = FE!(c, self.ek[19]);                // Round 8
        c  = FO!(c, self.ek[20]);                // Round 9
        c  = FE!(c, self.ek[21]);                // Round 10
        c  = FO!(c, self.ek[22]);                // Round 11
        c  = SL2!(c ^ self.ek[23]) ^ self.ek[0]; // Round 12

        block[..Self::BLOCK_LEN].copy_from_slice(&c.to_be_bytes());
    }
}





#[derive(Clone)]
pub struct Aria192 {
    ek: [u128; Self::NR * 2],
}

impl Zeroize for Aria192 {
    fn zeroize(&mut self) {
        self.ek.zeroize();
    }
}

impl Drop for Aria192 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for Aria192 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Aria192").finish()
    }
}

impl Aria192 {
    pub const KEY_LEN: usize   = 24;
    pub const BLOCK_LEN: usize = 16;

    const NR: usize  = 14;

    const CK1: u128 = C2;
    const CK2: u128 = C3;
    const CK3: u128 = C1;

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        let kl = u128::from_be_bytes([
            key[ 0], key[ 1], key[ 2], key[ 3], 
            key[ 4], key[ 5], key[ 6], key[ 7], 
            key[ 8], key[ 9], key[10], key[11], 
            key[12], key[13], key[14], key[15], 
        ]);
        let kr = u128::from_be_bytes([
            key[16], key[17], key[18], key[19], 
            key[20], key[21], key[22], key[23], 
            0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 
        ]);

        let w0 = kl;
        let w1 = FO!(w0, Self::CK1) ^ kr;
        let w2 = FE!(w1, Self::CK2) ^ w0;
        let w3 = FO!(w2, Self::CK3) ^ w1;

        let mut ek = [0u128; Self::NR * 2];

        ek[ 0] = w0 ^ w1.rotate_right(19);
        ek[ 1] = w1 ^ w2.rotate_right(19);
        ek[ 2] = w2 ^ w3.rotate_right(19);
        ek[ 3] = w0.rotate_right(19) ^ w3;
        ek[ 4] = w0 ^ w1.rotate_right(31);
        ek[ 5] = w1 ^ w2.rotate_right(31);
        ek[ 6] = w2 ^ w3.rotate_right(31);
        ek[ 7] = w0.rotate_right(31) ^ w3;
        ek[ 8] = w0 ^ w1.rotate_left(61);
        ek[ 9] = w1 ^ w2.rotate_left(61);
        ek[10] = w2 ^ w3.rotate_left(61);
        ek[11] = w0.rotate_left(61) ^ w3;
        ek[12] = w0 ^ w1.rotate_left(31); // KEY-128
        ek[13] = w1 ^ w2.rotate_left(31);
        ek[14] = w2 ^ w3.rotate_left(31); // KEY-192

        ek[15] = A!(ek[13]);
        ek[16] = A!(ek[12]);
        ek[17] = A!(ek[11]);
        ek[18] = A!(ek[10]);
        ek[19] = A!(ek[ 9]);
        ek[20] = A!(ek[ 8]);
        ek[21] = A!(ek[ 7]);
        ek[22] = A!(ek[ 6]);
        ek[23] = A!(ek[ 5]);
        ek[24] = A!(ek[ 4]);
        ek[25] = A!(ek[ 3]);
        ek[26] = A!(ek[ 2]);
        ek[27] = A!(ek[ 1]);

        Self { ek }
    }

    pub fn encrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        let mut p = u128::from_be_bytes([
            block[ 0], block[ 1], block[ 2], block[ 3], 
            block[ 4], block[ 5], block[ 6], block[ 7], 
            block[ 8], block[ 9], block[10], block[11], 
            block[12], block[13], block[14], block[15], 
        ]);
        
        p = FO!(p, self.ek[0]);                  // Round 1
        p = FE!(p, self.ek[1]);                  // Round 2
        p = FO!(p, self.ek[2]);                  // Round 3
        p = FE!(p, self.ek[3]);                  // Round 4
        p = FO!(p, self.ek[4]);                  // Round 5
        p = FE!(p, self.ek[5]);                  // Round 6
        p = FO!(p, self.ek[6]);                  // Round 7
        p = FE!(p, self.ek[7]);                  // Round 8
        p = FO!(p, self.ek[8]);                  // Round 9
        p = FE!(p, self.ek[9]);                  // Round 10
        p = FO!(p, self.ek[10]);                 // Round 11
        p = FE!(p, self.ek[11]);                 // Round 12
        p = FO!(p, self.ek[12]);                 // Round 13
        p = SL2!(p ^ self.ek[13]) ^ self.ek[14]; // Round 14
        
        block[..Self::BLOCK_LEN].copy_from_slice(&p.to_be_bytes());
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        let mut c = u128::from_be_bytes([
            block[ 0], block[ 1], block[ 2], block[ 3], 
            block[ 4], block[ 5], block[ 6], block[ 7], 
            block[ 8], block[ 9], block[10], block[11], 
            block[12], block[13], block[14], block[15], 
        ]);
        
        c = FO!(c, self.ek[14]);                // Round 1
        c = FE!(c, self.ek[15]);                // Round 2
        c = FO!(c, self.ek[16]);                // Round 3
        c = FE!(c, self.ek[17]);                // Round 4
        c = FO!(c, self.ek[18]);                // Round 5
        c = FE!(c, self.ek[19]);                // Round 6
        c = FO!(c, self.ek[20]);                // Round 7
        c = FE!(c, self.ek[21]);                // Round 8
        c = FO!(c, self.ek[22]);                // Round 9
        c = FE!(c, self.ek[23]);                // Round 10
        c = FO!(c, self.ek[24]);                // Round 11
        c = FE!(c, self.ek[25]);                // Round 12
        c = FO!(c, self.ek[26]);                // Round 13
        c = SL2!(c ^ self.ek[27]) ^ self.ek[0]; // Round 14
        
        block[..Self::BLOCK_LEN].copy_from_slice(&c.to_be_bytes());
    }
}


#[derive(Clone)]
pub struct Aria256 {
    ek: [u128; Self::NR * 2],
}

impl Zeroize for Aria256 {
    fn zeroize(&mut self) {
        self.ek.zeroize();
    }
}

impl Drop for Aria256 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for Aria256 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Aria256").finish()
    }
}

impl Aria256 {
    pub const KEY_LEN: usize   = 32;
    pub const BLOCK_LEN: usize = 16;

    const NR: usize  = 16;

    const CK1: u128 = C3;
    const CK2: u128 = C1;
    const CK3: u128 = C2;

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        let kl = u128::from_be_bytes([
            key[ 0], key[ 1], key[ 2], key[ 3], 
            key[ 4], key[ 5], key[ 6], key[ 7], 
            key[ 8], key[ 9], key[10], key[11], 
            key[12], key[13], key[14], key[15], 
        ]);
        let kr = u128::from_be_bytes([
            key[16], key[17], key[18], key[19], 
            key[20], key[21], key[22], key[23], 
            key[24], key[25], key[26], key[27], 
            key[28], key[29], key[30], key[31], 
        ]);

        let w0 = kl;
        let w1 = FO!(w0, Self::CK1) ^ kr;
        let w2 = FE!(w1, Self::CK2) ^ w0;
        let w3 = FO!(w2, Self::CK3) ^ w1;

        let mut ek = [0u128; Self::NR * 2];

        ek[ 0] = w0 ^ w1.rotate_right(19);
        ek[ 1] = w1 ^ w2.rotate_right(19);
        ek[ 2] = w2 ^ w3.rotate_right(19);
        ek[ 3] = w0.rotate_right(19) ^ w3;
        ek[ 4] = w0 ^ w1.rotate_right(31);
        ek[ 5] = w1 ^ w2.rotate_right(31);
        ek[ 6] = w2 ^ w3.rotate_right(31);
        ek[ 7] = w0.rotate_right(31) ^ w3;
        ek[ 8] = w0 ^ w1.rotate_left(61);
        ek[ 9] = w1 ^ w2.rotate_left(61);
        ek[10] = w2 ^ w3.rotate_left(61);
        ek[11] = w0.rotate_left(61) ^ w3;
        ek[12] = w0 ^ w1.rotate_left(31); // KEY-128
        ek[13] = w1 ^ w2.rotate_left(31);
        ek[14] = w2 ^ w3.rotate_left(31); // KEY-192
        ek[15] = w0.rotate_left(31) ^ w3;
        ek[16] = w0 ^ w1.rotate_left(19); // KEY-256

        ek[17] = A!(ek[15]);
        ek[18] = A!(ek[14]);
        ek[19] = A!(ek[13]);
        ek[20] = A!(ek[12]);
        ek[21] = A!(ek[11]);
        ek[22] = A!(ek[10]);
        ek[23] = A!(ek[ 9]);
        ek[24] = A!(ek[ 8]);
        ek[25] = A!(ek[ 7]);
        ek[26] = A!(ek[ 6]);
        ek[27] = A!(ek[ 5]);
        ek[28] = A!(ek[ 4]);
        ek[29] = A!(ek[ 3]);
        ek[30] = A!(ek[ 2]);
        ek[31] = A!(ek[ 1]);

        Self { ek }
    }

    pub fn encrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        let mut p = u128::from_be_bytes([
            block[ 0], block[ 1], block[ 2], block[ 3], 
            block[ 4], block[ 5], block[ 6], block[ 7], 
            block[ 8], block[ 9], block[10], block[11], 
            block[12], block[13], block[14], block[15], 
        ]);
        
        p = FO!(p, self.ek[0]);                  // Round 1
        p = FE!(p, self.ek[1]);                  // Round 2
        p = FO!(p, self.ek[2]);                  // Round 3
        p = FE!(p, self.ek[3]);                  // Round 4
        p = FO!(p, self.ek[4]);                  // Round 5
        p = FE!(p, self.ek[5]);                  // Round 6
        p = FO!(p, self.ek[6]);                  // Round 7
        p = FE!(p, self.ek[7]);                  // Round 8
        p = FO!(p, self.ek[8]);                  // Round 9
        p = FE!(p, self.ek[9]);                  // Round 10
        p = FO!(p, self.ek[10]);                 // Round 11
        p = FE!(p, self.ek[11]);                 // Round 12
        p = FO!(p, self.ek[12]);                 // Round 13
        p = FE!(p, self.ek[13]);                 // Round 14
        p = FO!(p, self.ek[14]);                 // Round 15
        p = SL2!(p ^ self.ek[15]) ^ self.ek[16]; // Round 16

        block[..Self::BLOCK_LEN].copy_from_slice(&p.to_be_bytes());
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        let mut c = u128::from_be_bytes([
            block[ 0], block[ 1], block[ 2], block[ 3], 
            block[ 4], block[ 5], block[ 6], block[ 7], 
            block[ 8], block[ 9], block[10], block[11], 
            block[12], block[13], block[14], block[15], 
        ]);
        
        c = FO!(c, self.ek[16]);                // Round 1
        c = FE!(c, self.ek[17]);                // Round 2
        c = FO!(c, self.ek[18]);                // Round 3
        c = FE!(c, self.ek[19]);                // Round 4
        c = FO!(c, self.ek[20]);                // Round 5
        c = FE!(c, self.ek[21]);                // Round 6
        c = FO!(c, self.ek[22]);                // Round 7
        c = FE!(c, self.ek[23]);                // Round 8
        c = FO!(c, self.ek[24]);                // Round 9
        c = FE!(c, self.ek[25]);                // Round 10
        c = FO!(c, self.ek[26]);                // Round 11
        c = FE!(c, self.ek[27]);                // Round 12
        c = FO!(c, self.ek[28]);                // Round 13
        c = FE!(c, self.ek[29]);                // Round 14
        c = FO!(c, self.ek[30]);                // Round 15
        c = SL2!(c ^ self.ek[31]) ^ self.ek[0]; // Round 16

        block[..Self::BLOCK_LEN].copy_from_slice(&c.to_be_bytes());
    }
}


#[test]
fn test_aria128() {
    // A.1.  128-Bit Key
    // https://tools.ietf.org/html/rfc5794#appendix-A.1
    let key        = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext  = hex::decode("00112233445566778899aabbccddeeff").unwrap();
    let ciphertext = hex::decode("d718fbd6ab644c739da95f3be6451778").unwrap();
    
    let mut cleartext = plaintext.clone();

    let cipher = Aria128::new(&key);

    cipher.encrypt(&mut cleartext);
    assert_eq!(&cleartext[..], &ciphertext[..]);

    cipher.decrypt(&mut cleartext);
    assert_eq!(&cleartext[..], &plaintext[..]);
}

#[test]
fn test_aria192() {
    // A.2.  192-Bit Key
    // https://tools.ietf.org/html/rfc5794#appendix-A.2
    let key        = hex::decode("000102030405060708090a0b0c0d0e0f\
1011121314151617").unwrap();
    let plaintext  = hex::decode("00112233445566778899aabbccddeeff").unwrap();
    let ciphertext = hex::decode("26449c1805dbe7aa25a468ce263a9e79").unwrap();

    let mut cleartext = plaintext.clone();

    let cipher = Aria192::new(&key);

    cipher.encrypt(&mut cleartext);
    assert_eq!(&cleartext[..], &ciphertext[..]);

    cipher.decrypt(&mut cleartext);
    assert_eq!(&cleartext[..], &plaintext[..]);
}

#[test]
fn test_aria256() {
    // A.3.  256-Bit Key
    // https://tools.ietf.org/html/rfc5794#appendix-A.3
    let key        = hex::decode("000102030405060708090a0b0c0d0e0f\
101112131415161718191a1b1c1d1e1f").unwrap();
    let plaintext  = hex::decode("00112233445566778899aabbccddeeff").unwrap();
    let ciphertext = hex::decode("f92bd7c79fb72e2f2b8f80c1972d24fc").unwrap();
    
    let mut cleartext = plaintext.clone();

    let cipher = Aria256::new(&key);

    cipher.encrypt(&mut cleartext);
    assert_eq!(&cleartext[..], &ciphertext[..]);

    cipher.decrypt(&mut cleartext);
    assert_eq!(&cleartext[..], &plaintext[..]);
}