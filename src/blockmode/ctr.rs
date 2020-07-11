// 6.5 The Counter Mode, (Page-22)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
use crate::mem::Zeroize;
use crate::blockcipher::{
    Sm4,
    Aes128, Aes192, Aes256,
    Camellia128, Camellia192, Camellia256,
    Aria128, Aria192, Aria256,
};

// NOTE: CTR 分组并没有一个统一的规范，在一些实现里面，它们的 Counter 可能是 32-Bits 的。
//       比如 IPSecs: 
// 
//       4.  Counter Block Format
//       https://tools.ietf.org/html/rfc3686#section-4

macro_rules! impl_block_cipher_with_ctr_mode {
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

            
            pub fn new(key: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);

                let cipher = $cipher::new(key);

                Self { cipher }
            }

            #[inline]
            fn ctr128(counter_block: &mut [u8; Self::BLOCK_LEN]) {
                let octets = u128::from_be_bytes(*counter_block).wrapping_add(1).to_be_bytes();
                counter_block.copy_from_slice(&octets)
            }

            /// Counter Block Format
            /// 
            /// Counter (128-bits, big-endian)
            pub fn encrypt_slice(&self, counter_block: &mut [u8; Self::BLOCK_LEN], plaintext_in_ciphertext_out: &mut [u8]) {
                debug_assert_eq!(counter_block.len(), Self::BLOCK_LEN);
                
                for plaintext in plaintext_in_ciphertext_out.chunks_mut(Self::BLOCK_LEN) {
                    let mut output_block = counter_block.clone();
                    self.cipher.encrypt(&mut output_block);

                    for i in 0..plaintext.len() {
                        plaintext[i] ^= output_block[i];
                    }
                    Self::ctr128(counter_block);
                }
            }
            
            /// Counter Block Format
            /// 
            /// Counter (128-bits, big-endian)
            pub fn decrypt_slice(&self, counter_block: &mut [u8; Self::BLOCK_LEN], ciphertext_in_plaintext_out: &mut [u8]) {
                debug_assert_eq!(counter_block.len(), Self::BLOCK_LEN);
                
                for ciphertext in ciphertext_in_plaintext_out.chunks_mut(Self::BLOCK_LEN) {
                    let mut output_block = counter_block.clone();
                    self.cipher.encrypt(&mut output_block);

                    for i in 0..ciphertext.len() {
                        ciphertext[i] ^= output_block[i];
                    }
                    Self::ctr128(counter_block);
                }
            }
        }
    }
}

impl_block_cipher_with_ctr_mode!(Sm4Ctr, Sm4);
impl_block_cipher_with_ctr_mode!(Aes128Ctr, Aes128);
impl_block_cipher_with_ctr_mode!(Aes192Ctr, Aes192);
impl_block_cipher_with_ctr_mode!(Aes256Ctr, Aes256);
impl_block_cipher_with_ctr_mode!(Camellia128Ctr, Camellia128);
impl_block_cipher_with_ctr_mode!(Camellia192Ctr, Camellia192);
impl_block_cipher_with_ctr_mode!(Camellia256Ctr, Camellia256);
impl_block_cipher_with_ctr_mode!(Aria128Ctr, Aria128);
impl_block_cipher_with_ctr_mode!(Aria192Ctr, Aria192);
impl_block_cipher_with_ctr_mode!(Aria256Ctr, Aria256);


#[test]
fn test_aes128_ctr() {
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a").unwrap();

    let mut ciphertext = plaintext.clone();

    let mut counter_block = [0u8; Aes128Ctr::BLOCK_LEN];
    counter_block.copy_from_slice(&nonce);

    let cipher = Aes128Ctr::new(&key);
    
    cipher.encrypt_slice(&mut counter_block, &mut ciphertext);


    let mut cleartext = ciphertext.clone();

    let mut counter_block = [0u8; Aes128Ctr::BLOCK_LEN];
    counter_block.copy_from_slice(&nonce);

    let cipher = Aes128Ctr::new(&key);
    
    cipher.decrypt_slice(&mut counter_block, &mut cleartext);

    assert_eq!(&cleartext[..], &plaintext[..]);
}

// F.5 CTR Example Vectors, (Page-62)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
#[test]
fn test_aes128_ctr_enc() {
    // F.5.1  CTR-AES128.Encrypt, (Page-62)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710").unwrap();

    let mut ciphertext = plaintext.clone();

    let mut counter_block = [0u8; Aes128Ctr::BLOCK_LEN];
    counter_block.copy_from_slice(&nonce);

    let cipher = Aes128Ctr::new(&key);

    cipher.encrypt_slice(&mut counter_block, &mut ciphertext);

    assert_eq!(&ciphertext[..], &hex::decode("\
874d6191b620e3261bef6864990db6ce\
9806f66b7970fdff8617187bb9fffdff\
5ae4df3edbd5d35e5b4f09020db03eab\
1e031dda2fbe03d1792170a0f3009cee").unwrap()[..]);
}

#[test]
fn test_aes128_ctr_dec() {
    // F.5.2  CTR-AES128.Decrypt, (Page-63)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
    let ciphertext = hex::decode("\
874d6191b620e3261bef6864990db6ce\
9806f66b7970fdff8617187bb9fffdff\
5ae4df3edbd5d35e5b4f09020db03eab\
1e031dda2fbe03d1792170a0f3009cee").unwrap();

    let mut plaintext = ciphertext.clone();

    let mut counter_block = [0u8; Aes128Ctr::BLOCK_LEN];
    counter_block.copy_from_slice(&nonce);

    let cipher = Aes128Ctr::new(&key);
    cipher.decrypt_slice(&mut counter_block, &mut plaintext);

    assert_eq!(&plaintext[..], &hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710").unwrap()[..]);
}