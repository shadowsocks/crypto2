// Authenticated Encryption with Associated Data (AEAD) Parameters
// https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
pub use crate::blockmode::{
    Aes128Gcm, Aes128Gcm8, Aes128Gcm12,
    Aes256Gcm, Aes256Gcm8, Aes256Gcm12,

    Aes128GcmSiv, Aes256GcmSiv,

    Aes128Ccm, Aes128CcmShort, Aes128CcmShort8, Aes128CcmShort12, Aes128Ccm8,
    Aes256Ccm, Aes256CcmShort, Aes256CcmShort8, Aes256CcmShort12, Aes256Ccm8,

    Aes128OcbTag64, Aes128OcbTag96, Aes128OcbTag128,
    Aes192OcbTag64, Aes192OcbTag96, Aes192OcbTag128,
    Aes256OcbTag64, Aes256OcbTag96, Aes256OcbTag128,

    AesSivCmac256, AesSivCmac384, AesSivCmac512,
    
    Aria128Ccm, Aria256Ccm, 
    Aria128Gcm, Aria256Gcm, 
    Aria128GcmSiv, Aria256GcmSiv, 

    // 3.5.1.  AEAD_SM4_GCM
    // https://tools.ietf.org/html/rfc8998#section-3.5.1
    // 
    // 3.5.2.  AEAD_SM4_CCM
    // https://tools.ietf.org/html/rfc8998#section-3.5.2
    Sm4Gcm, Sm4Ccm,
};


mod chacha20_poly1305;
pub use self::chacha20_poly1305::Chacha20Poly1305;


#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AeadCipherKind {
    AEAD_AES_128_GCM,
    AEAD_AES_256_GCM,
    AEAD_AES_128_CCM,
    AEAD_AES_256_CCM,
    AEAD_AES_128_GCM_8,
    AEAD_AES_256_GCM_8,
    AEAD_AES_128_GCM_12,
    AEAD_AES_256_GCM_12,
    AEAD_AES_128_CCM_SHORT,
    AEAD_AES_256_CCM_SHORT,
    AEAD_AES_128_CCM_SHORT_8,
    AEAD_AES_256_CCM_SHORT_8,
    AEAD_AES_128_CCM_SHORT_12,
    AEAD_AES_256_CCM_SHORT_12,
    AEAD_AES_SIV_CMAC_256,
    AEAD_AES_SIV_CMAC_384,
    AEAD_AES_SIV_CMAC_512,
    AEAD_AES_128_CCM_8,
    AEAD_AES_256_CCM_8,
    AEAD_AES_128_OCB_TAGLEN128,
    AEAD_AES_128_OCB_TAGLEN96,
    AEAD_AES_128_OCB_TAGLEN64,
    AEAD_AES_192_OCB_TAGLEN128,
    AEAD_AES_192_OCB_TAGLEN96,
    AEAD_AES_192_OCB_TAGLEN64,
    AEAD_AES_256_OCB_TAGLEN128,
    AEAD_AES_256_OCB_TAGLEN96,
    AEAD_AES_256_OCB_TAGLEN64,
    AEAD_CHACHA20_POLY1305,
    AEAD_AES_128_GCM_SIV,
    AEAD_AES_256_GCM_SIV,

    Private {
        // IANA AEAD ID
        id: u16,
        // IANA AEAD Name
        name: &'static str,
    },
}


pub trait AeadCipher: Sized {
    const KEY_LEN: usize;
    const BLOCK_LEN: usize;
    const TAG_LEN: usize;
    
    const P_MAX: usize;
    const C_MAX: usize;
    const N_MIN: usize;
    const N_MAX: usize;

    const KIND: AeadCipherKind;

    fn aead_key_len() -> usize;
    fn aead_block_len() -> usize;
    fn aead_tag_len() -> usize;
    fn aead_pmax() -> usize;
    fn aead_cmax() -> usize;
    fn aead_nmin() -> usize;
    fn aead_nmax() -> usize;
    fn aead_kind() -> AeadCipherKind;

    fn aead_new(key: &[u8], ) -> Self;
    
    fn aead_encrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]);
    #[must_use]
    fn aead_decrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) -> bool;
    fn aead_encrypt_slice_detached(&self, nonce: &[u8], aad: &[u8], plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8]);
    #[must_use]
    fn aead_decrypt_slice_detached(&self, nonce: &[u8], aad: &[u8], ciphertext_in_plaintext_out: &mut [u8], tag_in: &[u8]) -> bool;
}


macro_rules! impl_aead_cipher {
    ($name:tt, $kind:tt) => {
        impl AeadCipher for $name {
            const KEY_LEN: usize   = $name::KEY_LEN;
            const BLOCK_LEN: usize = $name::BLOCK_LEN;
            const TAG_LEN: usize   = $name::TAG_LEN;
        
            const P_MAX: usize = $name::P_MAX;
            const C_MAX: usize = $name::C_MAX;
            const N_MIN: usize = $name::N_MIN;
            const N_MAX: usize = $name::N_MAX;

            const KIND: AeadCipherKind = AeadCipherKind::$kind;

            fn aead_key_len() -> usize   { $name::KEY_LEN }
            fn aead_block_len() -> usize { $name::BLOCK_LEN }
            fn aead_tag_len() -> usize   { $name::TAG_LEN }
            fn aead_pmax() -> usize { $name::P_MAX }
            fn aead_cmax() -> usize { $name::C_MAX }
            fn aead_nmin() -> usize { $name::N_MIN }
            fn aead_nmax() -> usize { $name::N_MAX }
            fn aead_kind() -> AeadCipherKind { AeadCipherKind::$kind }

            fn aead_new(key: &[u8]) -> Self {
                Self::new(key)
            }
            fn aead_encrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) {
                self.encrypt_slice(nonce, aad, aead_pkt)
            }
            #[must_use]
            fn aead_decrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
                self.decrypt_slice(nonce, aad, aead_pkt)
            }
            fn aead_encrypt_slice_detached(&self, nonce: &[u8], aad: &[u8], plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8]) {
                self.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out)
            }
            #[must_use]
            fn aead_decrypt_slice_detached(&self, nonce: &[u8], aad: &[u8], ciphertext_in_plaintext_out: &mut [u8], tag_in: &[u8]) -> bool {
                self.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in)
            }
        }
    }
}

macro_rules! impl_aead_cipher_with_siv_cmac {
    ($name:tt, $kind:tt) => {
        impl AeadCipher for $name {
            const KEY_LEN: usize   = $name::KEY_LEN;
            const BLOCK_LEN: usize = $name::BLOCK_LEN;
            const TAG_LEN: usize   = $name::TAG_LEN;
        
            const P_MAX: usize = $name::P_MAX;
            const C_MAX: usize = $name::C_MAX;
            const N_MIN: usize = $name::N_MIN;
            const N_MAX: usize = $name::N_MAX;

            const KIND: AeadCipherKind = AeadCipherKind::$kind;

            fn aead_key_len() -> usize   { $name::KEY_LEN }
            fn aead_block_len() -> usize { $name::BLOCK_LEN }
            fn aead_tag_len() -> usize   { $name::TAG_LEN }
            fn aead_pmax() -> usize { $name::P_MAX }
            fn aead_cmax() -> usize { $name::C_MAX }
            fn aead_nmin() -> usize { $name::N_MIN }
            fn aead_nmax() -> usize { $name::N_MAX }
            fn aead_kind() -> AeadCipherKind { AeadCipherKind::$kind }
            
            fn aead_new(key: &[u8]) -> Self {
                Self::new(key)
            }

            // SIV 分组模式的加密分为2种：
            // 
            //      1. Nonce-Based Authenticated Encryption with SIV
            //      2. Deterministic Authenticated Encryption with SIV
            // 
            // 这里为了兼容  AEAD 交互 API， 实现的是 Nonce-Based Authenticated Encryption with SIV.
            fn aead_encrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) {
                match (nonce.is_empty(), aad.is_empty()) {
                    (true, true)   => self.encrypt_slice(&[aad, nonce], aead_pkt),
                    (true, false)  => self.encrypt_slice(&[nonce], aead_pkt),
                    (false, true)  => self.encrypt_slice(&[aad], aead_pkt),
                    (false, false) => self.encrypt_slice(&[], aead_pkt),
                }
            }
            #[must_use]
            fn aead_decrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
                match (nonce.is_empty(), aad.is_empty()) {
                    (true, true)   => self.decrypt_slice(&[aad, nonce], aead_pkt),
                    (true, false)  => self.decrypt_slice(&[nonce], aead_pkt),
                    (false, true)  => self.decrypt_slice(&[aad], aead_pkt),
                    (false, false) => self.decrypt_slice(&[], aead_pkt),
                }
            }
            fn aead_encrypt_slice_detached(&self, nonce: &[u8], aad: &[u8], plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8]) {
                match (nonce.is_empty(), aad.is_empty()) {
                    (true, true)   => self.encrypt_slice_detached(&[aad, nonce], plaintext_in_ciphertext_out, tag_out),
                    (true, false)  => self.encrypt_slice_detached(&[nonce], plaintext_in_ciphertext_out, tag_out),
                    (false, true)  => self.encrypt_slice_detached(&[aad], plaintext_in_ciphertext_out, tag_out),
                    (false, false) => self.encrypt_slice_detached(&[], plaintext_in_ciphertext_out, tag_out),
                }
            }
            #[must_use]
            fn aead_decrypt_slice_detached(&self, nonce: &[u8], aad: &[u8], ciphertext_in_plaintext_out: &mut [u8], tag_in: &[u8]) -> bool {
                match (nonce.is_empty(), aad.is_empty()) {
                    (true, true)   => self.decrypt_slice_detached(&[aad, nonce], ciphertext_in_plaintext_out, tag_in),
                    (true, false)  => self.decrypt_slice_detached(&[nonce], ciphertext_in_plaintext_out, tag_in),
                    (false, true)  => self.decrypt_slice_detached(&[aad], ciphertext_in_plaintext_out, tag_in),
                    (false, false) => self.decrypt_slice_detached(&[], ciphertext_in_plaintext_out, tag_in),
                }
            }
        }
    }
}


// AES-GCM
impl_aead_cipher!(Aes128Gcm,   AEAD_AES_128_GCM);
impl_aead_cipher!(Aes128Gcm8,  AEAD_AES_128_GCM_8);
impl_aead_cipher!(Aes128Gcm12, AEAD_AES_128_GCM_12);
impl_aead_cipher!(Aes256Gcm,   AEAD_AES_256_GCM);
impl_aead_cipher!(Aes256Gcm8,  AEAD_AES_256_GCM_8);
impl_aead_cipher!(Aes256Gcm12, AEAD_AES_256_GCM_12);

// AES-GCM-SIV
impl_aead_cipher!(Aes128GcmSiv, AEAD_AES_128_GCM_SIV);
impl_aead_cipher!(Aes256GcmSiv, AEAD_AES_256_GCM_SIV);

// AES-CCM
impl_aead_cipher!(Aes128Ccm,        AEAD_AES_128_CCM);
impl_aead_cipher!(Aes128CcmShort,   AEAD_AES_128_CCM_SHORT);
impl_aead_cipher!(Aes128CcmShort8,  AEAD_AES_128_CCM_SHORT_8);
impl_aead_cipher!(Aes128CcmShort12, AEAD_AES_128_CCM_SHORT_12);
impl_aead_cipher!(Aes128Ccm8,       AEAD_AES_128_CCM_8);

impl_aead_cipher!(Aes256Ccm,        AEAD_AES_256_CCM);
impl_aead_cipher!(Aes256CcmShort,   AEAD_AES_256_CCM_SHORT);
impl_aead_cipher!(Aes256CcmShort8,  AEAD_AES_256_CCM_SHORT_8);
impl_aead_cipher!(Aes256CcmShort12, AEAD_AES_256_CCM_SHORT_12);
impl_aead_cipher!(Aes256Ccm8,       AEAD_AES_256_CCM_8);

// AES-SIV-CMAC
impl_aead_cipher_with_siv_cmac!(AesSivCmac256, AEAD_AES_SIV_CMAC_256);
impl_aead_cipher_with_siv_cmac!(AesSivCmac384, AEAD_AES_SIV_CMAC_384);
impl_aead_cipher_with_siv_cmac!(AesSivCmac512, AEAD_AES_SIV_CMAC_512);

// AES-OCB
impl_aead_cipher!(Aes128OcbTag64,  AEAD_AES_128_OCB_TAGLEN64);
impl_aead_cipher!(Aes128OcbTag96,  AEAD_AES_128_OCB_TAGLEN96);
impl_aead_cipher!(Aes128OcbTag128, AEAD_AES_128_OCB_TAGLEN128);

impl_aead_cipher!(Aes192OcbTag64,  AEAD_AES_192_OCB_TAGLEN64);
impl_aead_cipher!(Aes192OcbTag96,  AEAD_AES_192_OCB_TAGLEN96);
impl_aead_cipher!(Aes192OcbTag128, AEAD_AES_192_OCB_TAGLEN128);

impl_aead_cipher!(Aes256OcbTag64,  AEAD_AES_256_OCB_TAGLEN64);
impl_aead_cipher!(Aes256OcbTag96,  AEAD_AES_256_OCB_TAGLEN96);
impl_aead_cipher!(Aes256OcbTag128, AEAD_AES_256_OCB_TAGLEN128);

// Chacha20Poly1305
impl_aead_cipher!(Chacha20Poly1305,  AEAD_CHACHA20_POLY1305);



#[cfg(test)]
#[bench]
fn bench_chacha20_poly1305_enc(b: &mut test::Bencher) {
    let key   = [1u8; Chacha20Poly1305::KEY_LEN];
    let nonce = [2u8; Chacha20Poly1305::NONCE_LEN];
    let aad   = [0u8; 0];
    
    let mut tag_out    = test::black_box([ 1u8; Chacha20Poly1305::TAG_LEN ]);
    let mut ciphertext = test::black_box([ 1u8; Chacha20Poly1305::BLOCK_LEN ]);
    
    let cipher = Chacha20Poly1305::new(&key);

    b.bytes = Chacha20Poly1305::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag_out);
    })
}

#[cfg(test)]
#[bench]
fn bench_aes128_gcm_enc(b: &mut test::Bencher) {
    let key   = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext = test::black_box([1u8; Aes128Gcm::BLOCK_LEN + Aes128Gcm::TAG_LEN]);
    let cipher = Aes128Gcm::new(&key);

    b.bytes = Aes128Gcm::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice(&nonce, &aad, &mut plaintext_and_ciphertext);
    })
}
#[cfg(test)]
#[bench]
fn bench_aes128_gcm_siv_enc(b: &mut test::Bencher) {
    let key   = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext = test::black_box([1u8; Aes128GcmSiv::BLOCK_LEN + Aes128GcmSiv::TAG_LEN]);
    let cipher = Aes128GcmSiv::new(&key);

    b.bytes = Aes128GcmSiv::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice(&nonce, &aad, &mut plaintext_and_ciphertext);
    })
}
#[cfg(test)]
#[bench]
fn bench_aes128_ccm_enc(b: &mut test::Bencher) {
    let key   = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext = test::black_box([1u8; Aes128Ccm::BLOCK_LEN + Aes128Ccm::TAG_LEN]);
    let cipher = Aes128Ccm::new(&key);

    b.bytes = Aes128Ccm::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice(&nonce, &aad, &mut plaintext_and_ciphertext);
    })
}
#[cfg(test)]
#[bench]
fn bench_aes128_ocb_tag_128_enc(b: &mut test::Bencher) {
    let key   = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext = test::black_box([1u8; Aes128OcbTag128::BLOCK_LEN + Aes128OcbTag128::TAG_LEN]);
    let cipher = Aes128OcbTag128::new(&key);

    b.bytes = Aes128OcbTag128::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice(&nonce, &aad, &mut plaintext_and_ciphertext);
    })
}
#[cfg(test)]
#[bench]
fn bench_aes_siv_cmac_256_enc(b: &mut test::Bencher) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f\
000102030405060708090a0b0c0d0e0f").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext = test::black_box([1u8; AesSivCmac256::BLOCK_LEN + AesSivCmac256::TAG_LEN]);
    let cipher = AesSivCmac256::new(&key);

    b.bytes = AesSivCmac256::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice(&[&aad], &mut plaintext_and_ciphertext);
    })
}