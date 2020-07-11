// 6.4 The Output Feedback Mode, (Page-20)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
use crate::mem::Zeroize;
use crate::blockcipher::{
    Rc2FixedSize, Sm4,
    Aes128, Aes192, Aes256,
    Camellia128, Camellia192, Camellia256,
    Aria128, Aria192, Aria256,
};


macro_rules! impl_block_cipher_with_ofb_mode {
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

            
            pub fn new(key: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);

                let cipher = $cipher::new(key);
                
                Self { cipher }
            }
            
            pub fn encrypt_slice(&self, iv: &[u8; Self::IV_LEN], plaintext_in_ciphertext_out: &mut [u8]) {
                debug_assert_eq!(iv.len(), Self::IV_LEN);

                let mut last_input_block = iv.clone();
                for plaintext in plaintext_in_ciphertext_out.chunks_mut(Self::BLOCK_LEN) {

                    let mut output_block = last_input_block.clone();
                    self.cipher.encrypt(&mut output_block);

                    for i in 0..plaintext.len() {
                        plaintext[i] ^= output_block[i];
                    }

                    last_input_block = output_block;
                }
            }

            pub fn decrypt_slice(&self, iv: &[u8; Self::IV_LEN], ciphertext_in_plaintext_out: &mut [u8]) {
                debug_assert_eq!(iv.len(), Self::IV_LEN);

                let mut last_input_block = iv.clone();
                for ciphertext in ciphertext_in_plaintext_out.chunks_mut(Self::BLOCK_LEN) {

                    let mut output_block = last_input_block.clone();
                    self.cipher.encrypt(&mut output_block);
                    
                    for i in 0..ciphertext.len() {
                        ciphertext[i] ^= output_block[i];
                    }

                    last_input_block = output_block;
                }
            }
        }
    }
}


impl_block_cipher_with_ofb_mode!(Sm4Ofb, Sm4);
impl_block_cipher_with_ofb_mode!(Rc2FixedSizeOfb, Rc2FixedSize);
impl_block_cipher_with_ofb_mode!(Aes128Ofb, Aes128);
impl_block_cipher_with_ofb_mode!(Aes192Ofb, Aes192);
impl_block_cipher_with_ofb_mode!(Aes256Ofb, Aes256);
impl_block_cipher_with_ofb_mode!(Camellia128Ofb, Camellia128);
impl_block_cipher_with_ofb_mode!(Camellia192Ofb, Camellia192);
impl_block_cipher_with_ofb_mode!(Camellia256Ofb, Camellia256);
impl_block_cipher_with_ofb_mode!(Aria128Ofb, Aria128);
impl_block_cipher_with_ofb_mode!(Aria192Ofb, Aria192);
impl_block_cipher_with_ofb_mode!(Aria256Ofb, Aria256);


#[cfg(test)]
#[bench]
fn bench_aes128_ofb_enc(b: &mut test::Bencher) {
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let ivec = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut iv = [0u8; Aes128Ofb::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Ofb::new(&key);
    
    b.bytes = Aes128Ofb::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([0u8; Aes128Ofb::BLOCK_LEN]);
        cipher.encrypt_slice(&iv, &mut ciphertext);
        ciphertext
    })
}

#[test]
fn test_aes128_ofb() {
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let ivec  = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a").unwrap();
    let mut iv = [0u8; Aes128Ofb::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Ofb::new(&key);
    let mut ciphertext = plaintext.clone();
    cipher.encrypt_slice(&iv, &mut ciphertext);

    let cipher = Aes128Ofb::new(&key);
    let mut cleartext = ciphertext.clone();
    cipher.decrypt_slice(&iv, &mut cleartext);

    assert_eq!(&cleartext[..], &plaintext[..]);
}

#[test]
fn test_aes128_ofb_enc() {
    // F.4.1  OFB-AES128.Encrypt, (Page-59)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let ivec  = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut iv = [0u8; Aes128Ofb::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Ofb::new(&key);

    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710").unwrap();

    let mut ciphertext = plaintext.clone();
    cipher.encrypt_slice(&iv, &mut ciphertext);

    assert_eq!(&ciphertext[..], &hex::decode("\
3b3fd92eb72dad20333449f8e83cfb4a\
7789508d16918f03f53c52dac54ed825\
9740051e9c5fecf64344f7a82260edcc\
304c6528f659c77866a510d9c1d6ae5e").unwrap()[..]);
}

#[test]
fn test_aes128_ofb_dec() {
    // F.4.2  OFB-AES128.Decrypt, (Page-60)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let ivec  = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut iv = [0u8; Aes128Ofb::IV_LEN];
    iv.copy_from_slice(&ivec);

    let cipher = Aes128Ofb::new(&key);

    let ciphertext = hex::decode("\
3b3fd92eb72dad20333449f8e83cfb4a\
7789508d16918f03f53c52dac54ed825\
9740051e9c5fecf64344f7a82260edcc\
304c6528f659c77866a510d9c1d6ae5e").unwrap();

    let mut plaintext = ciphertext.clone();
    cipher.decrypt_slice(&iv, &mut plaintext);

    assert_eq!(&plaintext[..], &hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710").unwrap()[..]);
}