// 6.1 The Electronic Codebook Mode, (Page-16)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
// 
// NOTE:
//      ECB 和 CBC 分组模式都无法处理不定长的输入数据，
//      需要自己手动为不定长数据按照块密码算法的块大小做对齐工作。
// 
use crate::mem::Zeroize;
use crate::blockcipher::{
    Rc2FixedSize, Sm4,
    Aes128, Aes192, Aes256,
    Camellia128, Camellia192, Camellia256,
};


macro_rules! impl_block_cipher_with_ecb_mode {
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
            
            /// the plaintext must be a sequence of one or more complete data blocks.
            /// the total number of bits in the plaintext must be a positive multiple 
            /// of the block (or segment) size.
            pub fn encrypt(&mut self, blocks: &mut [u8]) {
                assert_eq!(blocks.len() % Self::BLOCK_LEN, 0);

                for plaintext in blocks.chunks_mut(Self::BLOCK_LEN) {
                    debug_assert_eq!(plaintext.len(), Self::BLOCK_LEN);

                    self.cipher.encrypt(plaintext);
                }
            }

            /// the plaintext must be a sequence of one or more complete data blocks.
            /// the total number of bits in the plaintext must be a positive multiple 
            /// of the block (or segment) size.
            pub fn decrypt(&mut self, blocks: &mut [u8]) {
                assert_eq!(blocks.len() % Self::BLOCK_LEN, 0);

                for ciphertext in blocks.chunks_mut(Self::BLOCK_LEN) {
                    debug_assert_eq!(ciphertext.len(), Self::BLOCK_LEN);

                    self.cipher.decrypt(ciphertext);
                }
            }
        }
    };
}

impl_block_cipher_with_ecb_mode!(Aes128Ecb, Aes128);
impl_block_cipher_with_ecb_mode!(Aes192Ecb, Aes192);
impl_block_cipher_with_ecb_mode!(Aes256Ecb, Aes256);

impl_block_cipher_with_ecb_mode!(Camellia128Ecb, Camellia128);
impl_block_cipher_with_ecb_mode!(Camellia192Ecb, Camellia192);
impl_block_cipher_with_ecb_mode!(Camellia256Ecb, Camellia256);

impl_block_cipher_with_ecb_mode!(Rc2FixedSizeEcb, Rc2FixedSize);

impl_block_cipher_with_ecb_mode!(Sm4Ecb, Sm4);


#[test]
fn test_aes128_ecb_enc() {
    // F.1.1  ECB-AES128.Encrypt, (Page-31)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();

    let mut cipher = Aes128Ecb::new(&key);

    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710").unwrap();

    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);

    assert_eq!(&ciphertext[..], &hex::decode("\
3ad77bb40d7a3660a89ecaf32466ef97\
f5d3d58503b9699de785895a96fdbaaf\
43b1cd7f598ece23881b00e3ed030688\
7b0c785e27e8ad3f8223207104725dd4").unwrap()[..]);
}

#[test]
fn test_aes128_ecb_dec() {
    // F.1.2  ECB-AES128.Decrypt, (Page-31)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();

    let mut cipher = Aes128Ecb::new(&key);

    let ciphertext = hex::decode("\
3ad77bb40d7a3660a89ecaf32466ef97\
f5d3d58503b9699de785895a96fdbaaf\
43b1cd7f598ece23881b00e3ed030688\
7b0c785e27e8ad3f8223207104725dd4").unwrap();

    let mut plaintext = ciphertext.clone();
    cipher.decrypt(&mut plaintext);

    assert_eq!(&plaintext[..], &hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710").unwrap()[..]);
}