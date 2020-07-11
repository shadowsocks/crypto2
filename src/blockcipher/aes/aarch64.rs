use crate::mem::Zeroize;

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use super::generic;


// Emulating x86 AES Intrinsics on ARMv8-A
// https://blog.michaelbrase.com/2018/05/08/emulating-x86-aes-intrinsics-on-armv8-a/

#[inline]
fn encrypt_aarch64(expanded_key: &[u8], nr: isize, plaintext: &mut [u8]) {
    debug_assert_eq!(plaintext.len(), 16);

    unsafe {
        let mut state: uint8x16_t = vld1q_u8(plaintext.as_ptr());
        
        state = vaeseq_u8(state, vld1q_u8(expanded_key.as_ptr()));
        // 9, 11, 13
        for i in 1..nr {
            state = vaesmcq_u8(state);
            state = vaeseq_u8(state, vld1q_u8(expanded_key.as_ptr().offset( i * 16 )));
        }

        state = veorq_u8(state, vld1q_u8( expanded_key.as_ptr().offset( nr * 16 ) ));

        let block: [u8; 16] = core::mem::transmute(state);
        plaintext[0..16].copy_from_slice(&block);
    }
}

#[inline]
fn decrypt_aarch64(expanded_key: &[u8], nr: isize, ciphertext: &mut [u8]) {
    debug_assert_eq!(ciphertext.len(), 16);
    unsafe {
        let mut state: uint8x16_t = vld1q_u8(ciphertext.as_ptr());

        state = veorq_u8(state, vld1q_u8( expanded_key.as_ptr().offset( nr * 16 ) ));

        let z = vdupq_n_u8(0);
        for i in 1..nr {
            // TODO: DK 需要在 EK 的基础上做一次 `vaesimcq_u8` 运算，这个步骤可以在 `Aes::new()` 
            //       的时候提前算好，这样可以加快 解密 的速度。
            let dk = vaesimcq_u8(vld1q_u8( expanded_key.as_ptr().offset( (nr - i) * 16 ) ));
            state = veorq_u8(vaesimcq_u8(vaesdq_u8(state, z)), dk);
        }

        let dk = vld1q_u8( expanded_key.as_ptr() );
        state = veorq_u8(vaesdq_u8(state, z), dk);

        // vst1q_u8(output, block);
        let block: [u8; 16] = core::mem::transmute(state);
        ciphertext[0..16].copy_from_slice(&block);
    }
}


#[derive(Clone)]
pub struct Aes128 {
    ek: [u8; (Self::NR + 1) * Self::BLOCK_LEN],
}

impl Zeroize for Aes128 {
    fn zeroize(&mut self) {
        self.ek.zeroize();
    }
}
impl Drop for Aes128 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl core::fmt::Debug for Aes128 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Aes128").finish()
    }
}

impl Aes128 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize   = 16;
    pub const NR: usize        = 10;


    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        let ek = generic::Aes128::new(key).ek;

        Self { ek }
    }
    
    pub fn encrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);
        
        encrypt_aarch64(&self.ek, Self::NR as isize, block);
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        decrypt_aarch64(&self.ek, Self::NR as isize, block);
    }
}


#[derive(Clone)]
pub struct Aes192 {
    ek: [u8; (Self::NR + 1) * Self::BLOCK_LEN],
}
impl Zeroize for Aes192 {
    fn zeroize(&mut self) {
        self.ek.zeroize();
    }
}
impl Drop for Aes192 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl core::fmt::Debug for Aes192 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Aes192").finish()
    }
}

impl Aes192 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize   = 24;
    pub const NR: usize        = 12;


    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        let ek = generic::Aes192::new(key).ek;

        Self { ek }
    }
    
    pub fn encrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);
        
        encrypt_aarch64(&self.ek, Self::NR as isize, block);
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        decrypt_aarch64(&self.ek, Self::NR as isize, block);
    }
}

#[derive(Clone)]
pub struct Aes256 {
    ek: [u8; (Self::NR + 1) * Self::BLOCK_LEN],
}
impl Zeroize for Aes256 {
    fn zeroize(&mut self) {
        self.ek.zeroize();
    }
}
impl Drop for Aes256 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl core::fmt::Debug for Aes256 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Aes256").finish()
    }
}

impl Aes256 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize   = 32;
    pub const NR: usize        = 14;


    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        let ek = generic::Aes256::new(key).ek;

        Self { ek }
    }
    
    pub fn encrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);
        
        encrypt_aarch64(&self.ek, Self::NR as isize, block);
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        decrypt_aarch64(&self.ek, Self::NR as isize, block);
    }
}
