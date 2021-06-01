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
const SIGMA: [[u8; 16]; 12] = [
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
    [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
    [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
    [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
    [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
    [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
    [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
    [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
    [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 ],
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
];


mod x64;
mod x32;

pub use self::x64::*;
pub use self::x32::*;