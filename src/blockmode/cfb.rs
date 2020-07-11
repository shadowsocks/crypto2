// 6.3 The Cipher Feedback Mode, (Page-18)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
// 
// NOTE:
// 
// CFB 模式共有 4 子版本：
// 
//      1. CFB1,   the   1-bit CFB mode
//      2. CFB8,   the   8-bit CFB mode
//      3, CFB64,  the  64-bit CFB mode
//      4. CFB128, the 128-bit CFB mode
// 
// 这些 CFB 模式处理的数据需要按照 CFB_BIT_MODE（1/8/64/128） 来进行对齐。
// 考虑到，我们 API 接受的输入数据流为 Byte 序列，而 Byte 数据结构本身是一个
// 针对 Bit 对齐的数据结构。
// 所以在 CFB1 和 CFB8 这两种分组模式下，输入的数据流不需要处理对齐的情况。
// 但是 CFB64 和 CFB128 则需要 Byte 序列的长度分别按照 8 和 16 来进行对齐。
// 
// 综上，CFB1 和 CFB8 可以处理不定长的 Byte 序列，无需做对齐工作，
// 和 CTR/OFB 这些模式类似可以被设计为一个流密码算法。
// 
// CFB64 和 分组大小为 8 byte 的对称分组密码结合时（如 RC2），也可以被当作是一个流密码。
// 
// CFB128 和 分组大小为 16 byte 的对称分组密码结合时（如 AES/Camellia/Aria），也可以被当作是一个流密码。
// 
use crate::mem::Zeroize;
use crate::blockcipher::{
    Sm4,
    Aes128, Aes192, Aes256,
    Camellia128, Camellia192, Camellia256,
    Aria128, Aria192, Aria256,
};


#[derive(Debug, Clone, Copy)]
struct Bits(pub u8);

impl Bits {
    pub fn bit(&self, pos: usize) -> bool {
        assert!(pos < 8);
        let pos = 8 - pos - 1;
        self.0 & 1 << pos != 0
    }

    pub fn set_bit(&mut self, pos: usize, val: bool) {
        assert!(pos < 8);
        let pos = 8 - pos - 1;
        self.0 ^= (0u8.wrapping_sub(val as u8) ^ self.0) & 1 << pos;
    }

    pub fn bit_xor(&mut self, pos: usize, other: u8) {
        let a = self.bit(pos);
        let b = Bits(other).bit(0);
        if a != b {
            self.set_bit(pos, true);
        } else {
            self.set_bit(pos, false);
        }
    }
}

fn left_shift_1(bytes: &mut [u8], bit: bool) {
    let mut last_bit = if bit { 0b0000_0001 } else { 0b0000_0000 };
    for byte in bytes.iter_mut().rev() {
        let b = (*byte & 0b1000_0000) >> 7;
        *byte <<= 1;
        *byte |= last_bit;
        last_bit = b;
    }
}


// NOTE: 考虑到目前流行且安全的 块密码算法（BlockCipher） 的块大小都是 16 Bytes，
//       因此 在和 CFB64 结合时，依然需要手动补齐数据，所以，我们不把它视作一个 `流密码`。
// 
//       当然，如果和 陈旧的 块密码算法 RC2 结合时，那么则不需要手动对齐数据，因为 RC2 的
//       块大小为 8 Bytes，但是目前，我们并不考虑这些陈旧的 块密码算法。
macro_rules! impl_block_cipher_with_cfb64_mode {
    ($name:tt, $cipher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.cipher.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl $name {
            pub const KEY_LEN: usize   = $cipher::KEY_LEN;
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const IV_LEN: usize    = $cipher::BLOCK_LEN;
            pub const B: usize = Self::BLOCK_LEN * 8; // The block size, in bits.
            pub const S: usize = 64;                  // The number of bits in a data segment.
            const SEGMENTS_LEN: usize = Self::S / 8; // 8 bytes


            pub fn new(key: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);
                assert!(Self::S <= Self::B);

                let cipher = $cipher::new(key);
                
                Self { cipher }
            }
            
            pub fn encrypt(&self, iv: &[u8; Self::IV_LEN], segments: &mut [u8]) {
                debug_assert_eq!(iv.len(), Self::IV_LEN);
                assert_eq!(segments.len() * 8 % Self::S, 0);
                if segments.len() < Self::SEGMENTS_LEN {
                    return ();
                }

                let mut last_input_block = iv.clone();
                let mut last_segment = [0u8; Self::SEGMENTS_LEN]; // 8 Bytes

                // First segment data
                let mut output_block = last_input_block.clone();
                self.cipher.encrypt(&mut output_block);
                for i in 0..Self::SEGMENTS_LEN {
                    segments[i] ^= output_block[i];
                    last_segment[i]  = segments[i];
                }

                let data = &mut segments[Self::SEGMENTS_LEN..];
                for segment in data.chunks_mut(Self::SEGMENTS_LEN) {
                    let mut tmp = [0u8; Self::BLOCK_LEN];
                    tmp[0..Self::BLOCK_LEN - Self::SEGMENTS_LEN].copy_from_slice(&last_input_block[Self::SEGMENTS_LEN..]);
                    tmp[Self::BLOCK_LEN - Self::SEGMENTS_LEN..].copy_from_slice(&last_segment);
                    last_input_block = tmp;

                    let mut output_block = last_input_block.clone();
                    self.cipher.encrypt(&mut output_block);
                    for i in 0..Self::S / 8 {
                        segment[i] ^= output_block[i];
                        last_segment[i] = segment[i];
                    }
                }
            }

            pub fn decrypt(&self, iv: &[u8; Self::IV_LEN], segments: &mut [u8]) {
                debug_assert_eq!(iv.len(), Self::IV_LEN);
                assert_eq!(segments.len() * 8 % Self::S, 0);
                if segments.len() < Self::SEGMENTS_LEN {
                    return ();
                }

                let mut last_input_block = iv.clone();
                let mut last_segment = [0u8; Self::S / 8];

                // First segment data
                let mut output_block = last_input_block.clone();
                self.cipher.encrypt(&mut output_block);
                for i in 0..Self::SEGMENTS_LEN {
                    last_segment[i] = segments[i];
                    segments[i] ^= output_block[i];
                }

                let data = &mut segments[Self::SEGMENTS_LEN..];
                for segment in data.chunks_mut(Self::SEGMENTS_LEN) {
                    let mut tmp = [0u8; Self::BLOCK_LEN];
                    tmp[0..Self::BLOCK_LEN - Self::SEGMENTS_LEN].copy_from_slice(&last_input_block[Self::SEGMENTS_LEN..]);
                    tmp[Self::BLOCK_LEN - Self::SEGMENTS_LEN..].copy_from_slice(&last_segment);
                    last_input_block = tmp;

                    let mut output_block = last_input_block.clone();
                    self.cipher.encrypt(&mut output_block);
                    for i in 0..Self::S / 8 {
                        last_segment[i] = segment[i];
                        segment[i] ^= output_block[i];
                    }
                }
            }
        }
    }
}

macro_rules! impl_block_cipher_with_cfb1_mode {
    ($name:tt, $cipher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.cipher.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl $name {
            pub const KEY_LEN: usize   = $cipher::KEY_LEN;
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const IV_LEN: usize    = $cipher::BLOCK_LEN;
            pub const B: usize = Self::BLOCK_LEN * 8; // The block size, in bits.
            pub const S: usize = 1;                   // The number of bits in a data segment.


            pub fn new(key: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);
                assert!(Self::S <= Self::B);
                assert!(Self::BLOCK_LEN <= 16);

                let cipher = $cipher::new(key);
                
                Self { cipher }
            }

            pub fn encrypt_slice(&self, iv: &[u8; Self::IV_LEN], segments: &mut [u8]) {
                debug_assert_eq!(iv.len(), Self::IV_LEN);

                #[allow(unused_assignments)]
                let mut last_segment = false;
                let mut last_input_block = iv.clone();

                for i in 0..segments.len() {
                    for bit_pos in 0..8 {
                        let mut keystream = last_input_block.clone();
                        self.cipher.encrypt(&mut keystream);

                        let mut byte_bits = Bits(segments[i]);
                        byte_bits.bit_xor(bit_pos, keystream[0]);
                        last_segment = byte_bits.bit(bit_pos);
                        segments[i] = byte_bits.0;

                        // left shift 1 bits
                        left_shift_1(&mut last_input_block, last_segment);
                    }
                }
            }

            pub fn decrypt_slice(&self, iv: &[u8; Self::IV_LEN], segments: &mut [u8]) {
                debug_assert_eq!(iv.len(), Self::IV_LEN);

                #[allow(unused_assignments)]
                let mut last_segment = false;
                let mut last_input_block = iv.clone();

                for i in 0..segments.len() {
                    for bit_pos in 0..8 {
                        let mut keystream = last_input_block.clone();
                        self.cipher.encrypt(&mut keystream);

                        let mut byte_bits = Bits(segments[i]);
                        last_segment = byte_bits.bit(bit_pos);
                        byte_bits.bit_xor(bit_pos, keystream[0]);
                        segments[i] = byte_bits.0;

                        // left shift 1 bits
                        left_shift_1(&mut last_input_block, last_segment);
                    }
                }
            }
        }
    }
}

macro_rules! impl_block_cipher_with_cfb8_mode {
    ($name:tt, $cipher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.cipher.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl $name {
            pub const KEY_LEN: usize   = $cipher::KEY_LEN;
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const IV_LEN: usize    = $cipher::BLOCK_LEN;
            pub const B: usize = Self::BLOCK_LEN * 8; // The block size, in bits.
            pub const S: usize = 8;                   // The number of bits in a data segment.
            

            pub fn new(key: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);
                assert!(Self::S <= Self::B);

                let cipher = $cipher::new(key);

                Self { cipher }
            }
            
            pub fn encrypt_slice(&self, iv: &[u8; Self::IV_LEN], segments: &mut [u8]) {
                debug_assert_eq!(iv.len(), Self::IV_LEN);

                #[allow(unused_assignments)]
                let mut last_segment = 0u8;
                let mut last_input_block = iv.clone();

                for i in 0..segments.len() {
                    let mut keystream = last_input_block.clone();
                    self.cipher.encrypt(&mut keystream);

                    segments[i] ^= keystream[0];
                    last_segment = segments[i];

                    // left shift 8 bits
                    let mut tmp = [0u8; Self::BLOCK_LEN];
                    tmp[0..Self::BLOCK_LEN - 1].copy_from_slice(&last_input_block[1..]);
                    tmp[Self::BLOCK_LEN - 1] = last_segment;
                    last_input_block = tmp;
                }
            }

            pub fn decrypt_slice(&self, iv: &[u8; Self::IV_LEN], segments: &mut [u8]) {
                debug_assert_eq!(iv.len(), Self::IV_LEN);

                #[allow(unused_assignments)]
                let mut last_segment = 0u8;
                let mut last_input_block = iv.clone();

                for i in 0..segments.len() {
                    let mut keystream = last_input_block.clone();
                    self.cipher.encrypt(&mut keystream);

                    last_segment = segments[i];
                    segments[i] ^= keystream[0];

                    // left shift 8 bits
                    let mut tmp = [0u8; Self::BLOCK_LEN];
                    tmp[0..Self::BLOCK_LEN - 1].copy_from_slice(&last_input_block[1..]);
                    tmp[Self::BLOCK_LEN - 1] = last_segment;
                    last_input_block = tmp;
                }
            }
        }
    }
}

macro_rules! impl_block_cipher_with_cfb128_mode {
    ($name:tt, $cipher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.cipher.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl $name {
            pub const KEY_LEN: usize   = $cipher::KEY_LEN;
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const IV_LEN: usize    = $cipher::BLOCK_LEN;
            pub const B: usize = Self::BLOCK_LEN * 8; // The block size, in bits.
            pub const S: usize = 128;                 // The number of bits in a data segment.


            pub fn new(key: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);
                assert!(Self::S <= Self::B);

                let cipher = $cipher::new(key);
                
                Self { cipher }
            }
            
            pub fn encrypt_slice(&self, iv: &[u8; Self::IV_LEN], segments: &mut [u8]) {
                debug_assert_eq!(iv.len(), Self::IV_LEN);

                let mut last_input_block = iv.clone();

                for segment in segments.chunks_mut(Self::BLOCK_LEN) {
                    let mut output_block = last_input_block.clone();
                    self.cipher.encrypt(&mut output_block);

                    for i in 0..segment.len() {
                        segment[i] ^= output_block[i];
                        last_input_block[i] = segment[i];
                    }
                }
            }

            pub fn decrypt_slice(&self, iv: &[u8; Self::IV_LEN], segments: &mut [u8]) {
                debug_assert_eq!(iv.len(), Self::IV_LEN);

                let mut last_input_block = iv.clone();

                for segment in segments.chunks_mut(Self::BLOCK_LEN) {
                    let mut output_block = last_input_block.clone();
                    self.cipher.encrypt(&mut output_block);

                    for i in 0..segment.len() {
                        last_input_block[i] = segment[i];
                        segment[i] ^= output_block[i];
                    }
                }
            }
        }
    }
}

impl_block_cipher_with_cfb1_mode!(Sm4Cfb1, Sm4);
impl_block_cipher_with_cfb1_mode!(Aes128Cfb1, Aes128);
impl_block_cipher_with_cfb1_mode!(Aes192Cfb1, Aes192);
impl_block_cipher_with_cfb1_mode!(Aes256Cfb1, Aes256);
impl_block_cipher_with_cfb1_mode!(Camellia128Cfb1, Camellia128);
impl_block_cipher_with_cfb1_mode!(Camellia192Cfb1, Camellia192);
impl_block_cipher_with_cfb1_mode!(Camellia256Cfb1, Camellia256);
impl_block_cipher_with_cfb1_mode!(Aria128Cfb1, Aria128);
impl_block_cipher_with_cfb1_mode!(Aria192Cfb1, Aria192);
impl_block_cipher_with_cfb1_mode!(Aria256Cfb1, Aria256);


impl_block_cipher_with_cfb8_mode!(Sm4Cfb8, Sm4);
impl_block_cipher_with_cfb8_mode!(Aes128Cfb8, Aes128);
impl_block_cipher_with_cfb8_mode!(Aes192Cfb8, Aes192);
impl_block_cipher_with_cfb8_mode!(Aes256Cfb8, Aes256);
impl_block_cipher_with_cfb8_mode!(Camellia128Cfb8, Camellia128);
impl_block_cipher_with_cfb8_mode!(Camellia192Cfb8, Camellia192);
impl_block_cipher_with_cfb8_mode!(Camellia256Cfb8, Camellia256);
impl_block_cipher_with_cfb8_mode!(Aria128Cfb8, Aria128);
impl_block_cipher_with_cfb8_mode!(Aria192Cfb8, Aria192);
impl_block_cipher_with_cfb8_mode!(Aria256Cfb8, Aria256);

impl_block_cipher_with_cfb64_mode!(Sm4Cfb64, Sm4);
impl_block_cipher_with_cfb64_mode!(Aes128Cfb64, Aes128);
impl_block_cipher_with_cfb64_mode!(Aes192Cfb64, Aes192);
impl_block_cipher_with_cfb64_mode!(Aes256Cfb64, Aes256);
impl_block_cipher_with_cfb64_mode!(Camellia128Cfb64, Camellia128);
impl_block_cipher_with_cfb64_mode!(Camellia192Cfb64, Camellia192);
impl_block_cipher_with_cfb64_mode!(Camellia256Cfb64, Camellia256);
impl_block_cipher_with_cfb64_mode!(Aria128Cfb64, Aria128);
impl_block_cipher_with_cfb64_mode!(Aria192Cfb64, Aria192);
impl_block_cipher_with_cfb64_mode!(Aria256Cfb64, Aria256);

impl_block_cipher_with_cfb128_mode!(Sm4Cfb128, Sm4);
impl_block_cipher_with_cfb128_mode!(Aes128Cfb128, Aes128);
impl_block_cipher_with_cfb128_mode!(Aes192Cfb128, Aes192);
impl_block_cipher_with_cfb128_mode!(Aes256Cfb128, Aes256);
impl_block_cipher_with_cfb128_mode!(Camellia128Cfb128, Camellia128);
impl_block_cipher_with_cfb128_mode!(Camellia192Cfb128, Camellia192);
impl_block_cipher_with_cfb128_mode!(Camellia256Cfb128, Camellia256);
impl_block_cipher_with_cfb128_mode!(Aria128Cfb128, Aria128);
impl_block_cipher_with_cfb128_mode!(Aria192Cfb128, Aria192);
impl_block_cipher_with_cfb128_mode!(Aria256Cfb128, Aria256);


#[cfg(test)]
#[bench]
fn bench_aes128_cfb128_enc(b: &mut test::Bencher) {
    let key  = hex::decode("00000000000000000000000000000000").unwrap();
    let ivec = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut iv = [0u8; Aes128Cfb128::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Cfb128::new(&key);
    
    b.bytes = Aes128Cfb128::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([0u8; Aes128Cfb128::BLOCK_LEN]);
        cipher.encrypt_slice(&iv, &mut ciphertext);
        ciphertext
    })
}

#[test]
fn test_aes128_cfb8() {
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let ivec  = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a").unwrap();
    let mut iv = [0u8; Aes128Cfb8::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Cfb8::new(&key);
    let mut ciphertext = plaintext.clone();
    cipher.encrypt_slice(&iv, &mut ciphertext);

    let cipher = Aes128Cfb8::new(&key);
    let mut cleartext = ciphertext.clone();
    cipher.decrypt_slice(&iv, &mut cleartext);

    assert_eq!(&cleartext[..], &plaintext[..]);
}

#[test]
fn test_aes128_cfb64() {
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let ivec  = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a8aae2d8a8a").unwrap();
    let mut iv = [0u8; Aes128Cfb64::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Cfb64::new(&key);
    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&iv, &mut ciphertext);

    let cipher = Aes128Cfb64::new(&key);
    let mut cleartext = ciphertext.clone();
    cipher.decrypt(&iv, &mut cleartext);

    assert_eq!(&cleartext[..], &plaintext[..]);
}

#[test]
fn test_aes128_cfb1_enc() {
    // F.3.1  CFB1-AES128.Encrypt, (Page-36)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let ivec  = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut iv = [0u8; Aes128Cfb1::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Cfb1::new(&key);
// 0110_1011_1100_0001
// 0110_1000_1011_0011
    let plaintext = [0x6b, 0xc1];
    let mut ciphertext = plaintext.clone();
    cipher.encrypt_slice(&iv, &mut ciphertext);
    assert_eq!(&ciphertext[..], &[ 0x68, 0xb3 ]);
}

#[test]
fn test_aes128_cfb1_dec() {
    // F.3.2  CFB1-AES128.Decrypt, (Page-37)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let ivec  = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut iv = [0u8; Aes128Cfb1::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Cfb1::new(&key);

    let ciphertext = [0x68, 0xb3];
    let mut plaintext = ciphertext.clone();
    cipher.decrypt_slice(&iv, &mut plaintext);
    assert_eq!(&plaintext[..], &[ 0x6b, 0xc1 ]);
}

#[test]
fn test_aes128_cfb8_enc() {
    // F.3.7  CFB8-AES128.Encrypt, (Page-46)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let ivec  = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut iv = [0u8; Aes128Cfb8::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Cfb8::new(&key);

    let plaintext = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e];
    let mut ciphertext = plaintext.clone();
    cipher.encrypt_slice(&iv, &mut ciphertext);
    assert_eq!(&ciphertext[..], &[
        0x3b, 0x79, 0x42, 0x4c, 0x9c,
    ]);
}

#[test]
fn test_aes128_cfb8_dec() {
    // F.3.7  CFB8-AES128.Decrypt, (Page-48)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let ivec  = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut iv = [0u8; Aes128Cfb8::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Cfb8::new(&key);

    let ciphertext = [0x3b, 0x79, 0x42, 0x4c, 0x9c];
    let mut plaintext = ciphertext.clone();
    cipher.decrypt_slice(&iv, &mut plaintext);
    assert_eq!(&plaintext[..], &[
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e
    ]);
}

#[test]
fn test_aes128_cfb128_enc() {
    // F.3.13  CFB128-AES128.Encrypt, (Page-57)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let ivec  = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut iv = [0u8; Aes128Cfb128::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Cfb128::new(&key);

    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f24\
").unwrap();

    let mut ciphertext = plaintext.clone();
    cipher.encrypt_slice(&iv, &mut ciphertext);
    assert_eq!(&ciphertext[..], &hex::decode("\
3b3fd92eb72dad20333449f8e83cfb4a\
c8a64537a0b3a93fcde3cdad9f1ce58b\
26751f67a3cbb140b1808cf187a4f4df\
c04b05\
").unwrap()[..] );
}

#[test]
fn test_aes128_cfb128_dec() {
    // F.3.14  CFB128-AES128.Decrypt, (Page-57)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let ivec  = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut iv = [0u8; Aes128Cfb128::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Cfb128::new(&key);

    let ciphertext = hex::decode("\
3b3fd92eb72dad20333449f8e83cfb4a\
c8a64537a0b3a93fcde3cdad9f1ce58b\
26751f67a3cbb140b1808cf187a4f4df\
c04b05\
").unwrap();

    let mut plaintext = ciphertext.clone();
    cipher.decrypt_slice(&iv, &mut plaintext);
    assert_eq!(&plaintext[..], &hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f24\
").unwrap()[..] );
}