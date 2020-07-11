// Recommendation for Block Cipher Modes of Operation (ECB/CBC/CFB/OFB/CTR)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
// 
// NOTE: 
// 
// 对于 CBC、CFB 和 OFB 分组模式而言，在对一条 `消息` 进行加密或解密的操作时，
// 需要用户提供：
// 
//  1. 初始向量（IV）
//  2. 密文或明文
// 
// 其中，初始向量（IV）并不要求是机密性的（比如随机生成），
// 因此，初始向量（IV）或生成初始向量（IV）的信息可以和
// 密文一起发送给接收端。
// 
// 
// 
// 对于 CTR 模式，在进行加密或解密操作时，需要用户提供：
//  
//  1. Counter Block
//  2. 密文或明文
// 
// Counter Block 的大小和 Block Cipher 的 BLOCK_SIZE 一样。
// 它的内存布局大概是：
// 
//      IV || Counter
// 
// 但是在标准（NIST-SP-800-38A）里面，确并没有明确 Counter 到底
// 使用多少 位（Bits）来用作 Block 的计数器。
// 一些应用制定了比较明确的规范，如 `RFC-3686` 在 `Section 4` 里面
// 明确规范了 Counter Block 的格式为：
// 
//      NONCE (32-bits) || IV (64-bits) || BlockCounter (32-bit big-endian integer)
// 
// 对于这个问题，本项目的实现是：
// 
//      IV (96-bits) || Counter (32-bits, big-endian)
// 
// 这样，可以很好的兼容不同的内存布局（Layout）。
// 
// 以上资料信息可以在 `Recommendation for Block Cipher Modes of Operation (ECB/CBC/CFB/OFB/CTR)` 的
// 以下章节里面找到：
// 
// *    Appendix B:  Generation of Counter Blocks 
// *    Appendix C:  Generation of Initialization Vectors 
// 
// 
// 
// 对于 AEAD 分组模式，如 CCM、OCB、GCM、GCM-SIV、SIV，进行加解密时，需要用户提供：
// 
// 1. 对每个 Message 而言，具有唯一性的 Nonce。
// 2. 密文或明文
// 
// 跟 IV 不同，IV 并不要求信息的机密性，他甚至可以和密文一起发送。
// 但 NONCE 要求并不是如此，他要求是机密性的。
// 
// 最后，不管是 IV 还是 NONCE，对于不同的消息的加解密时，IV 或 NONCE 不应该是相同的。

mod ecb;
mod cbc;
mod cfb;
mod ofb;
mod ctr;
pub use self::ecb::*;
pub use self::cbc::*;
pub use self::cfb::*;
pub use self::ofb::*;
pub use self::ctr::*;


// AEAD
mod ccm;
mod gcm;
mod ocb;
mod siv;
mod gcm_siv;
pub use self::ccm::*;
pub use self::gcm::*;
pub use self::ocb::*;
pub use self::siv::*;
pub use self::gcm_siv::*;



// IEEE P1619™/D16 Standard for Cryptographic Protection of Data on Block-Oriented Storage Devices 
// http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf
// 
// Recommendation for Block Cipher Modes of Operation:  The XTS-AES Mode for Confidentiality on Storage Devices
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38e.pdf
// 
// Disk encryption theory
// https://en.wikipedia.org/wiki/Disk_encryption_theory
// 
// 
// C code
// https://docs.rs/crate/xtsn/0.1.1/source/src/ccrypto.c
// 
// Rust Code
// https://github.com/pheki/xts-mode/blob/master/src/lib.rs
// 
// C Code
// https://github.com/randombit/botan/blob/master/src/lib/modes/xts/xts.cpp



// 2.  Notation and Basic Operations
// https://tools.ietf.org/html/rfc7253#section-2
// 
// double(S)     If S[1] == 0, then double(S) == (S[2..128] || 0);
//              otherwise, double(S) == (S[2..128] || 0) xor
//              (zeros(120) || 10000111).
// 
// https://github.com/briansmith/ring/issues/517
#[inline]
pub(crate) const fn dbl(s: u128) -> u128 {
    // if s & 0x80000000000000000000000000000000 != 0 {
    //     (s << 1) ^ 0b10000111
    // } else {
    //     s << 1
    // }
    (s << 1) ^ ( (((s as i128) >> 127) as u128) & 0b10000111)
}
