use crate::mem::Zeroize;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;


macro_rules! aes128_keyround {
    ($ek:tt, $i:tt, $rcon:tt) => {
        {
            let mut key = $ek[$i - 1];
            let mut gen = _mm_aeskeygenassist_si128(key, $rcon);
            gen = _mm_shuffle_epi32(gen, 255);
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            $ek[$i] = _mm_xor_si128(key, gen);
        }
    }
}

#[derive(Clone)]
pub struct Aes128 {
    ek: [__m128i; 20],
}

impl Zeroize for Aes128 {
    fn zeroize(&mut self) {
        unsafe {
            self.ek = [_mm_setzero_si128(); 20];
        }
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

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        unsafe {
            let mut ek: [__m128i; 20] = core::mem::zeroed();

            ek[0] = _mm_loadu_si128(key.as_ptr() as *const __m128i);
            aes128_keyround!(ek,  1, 0x01);
            aes128_keyround!(ek,  2, 0x02);
            aes128_keyround!(ek,  3, 0x04);
            aes128_keyround!(ek,  4, 0x08);
            aes128_keyround!(ek,  5, 0x10);
            aes128_keyround!(ek,  6, 0x20);
            aes128_keyround!(ek,  7, 0x40);
            aes128_keyround!(ek,  8, 0x80);
            aes128_keyround!(ek,  9, 0x1b);
            aes128_keyround!(ek, 10, 0x36);

            ek[11] = _mm_aesimc_si128(ek[9]);
            ek[12] = _mm_aesimc_si128(ek[8]);
            ek[13] = _mm_aesimc_si128(ek[7]);
            ek[14] = _mm_aesimc_si128(ek[6]);
            ek[15] = _mm_aesimc_si128(ek[5]);
            ek[16] = _mm_aesimc_si128(ek[4]);
            ek[17] = _mm_aesimc_si128(ek[3]);
            ek[18] = _mm_aesimc_si128(ek[2]);
            ek[19] = _mm_aesimc_si128(ek[1]);

            Self { ek }
        }
    }
    
    pub fn encrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        unsafe {
            let mut m = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            m =        _mm_xor_si128(m, self.ek[ 0]);
            m =     _mm_aesenc_si128(m, self.ek[ 1]);
            m =     _mm_aesenc_si128(m, self.ek[ 2]);
            m =     _mm_aesenc_si128(m, self.ek[ 3]);
            m =     _mm_aesenc_si128(m, self.ek[ 4]);
            m =     _mm_aesenc_si128(m, self.ek[ 5]);
            m =     _mm_aesenc_si128(m, self.ek[ 6]);
            m =     _mm_aesenc_si128(m, self.ek[ 7]);
            m =     _mm_aesenc_si128(m, self.ek[ 8]);
            m =     _mm_aesenc_si128(m, self.ek[ 9]);
            m = _mm_aesenclast_si128(m, self.ek[10]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, m);
        }
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        unsafe {
            let mut m = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            m =        _mm_xor_si128(m, self.ek[10]);
            m =     _mm_aesdec_si128(m, self.ek[11]);
            m =     _mm_aesdec_si128(m, self.ek[12]);
            m =     _mm_aesdec_si128(m, self.ek[13]);
            m =     _mm_aesdec_si128(m, self.ek[14]);
            m =     _mm_aesdec_si128(m, self.ek[15]);
            m =     _mm_aesdec_si128(m, self.ek[16]);
            m =     _mm_aesdec_si128(m, self.ek[17]);
            m =     _mm_aesdec_si128(m, self.ek[18]);
            m =     _mm_aesdec_si128(m, self.ek[19]);
            m = _mm_aesdeclast_si128(m, self.ek[ 0]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, m);
        }
    }
}



macro_rules! aes192_keyround {
    ($temp1:tt, $temp2:tt, $temp3:tt) => {
        {
            let mut temp4  = _mm_slli_si128($temp1, 0x4);
            $temp2 = _mm_shuffle_epi32($temp2, 0x55);
            $temp1 = _mm_xor_si128($temp1, temp4);
            temp4  = _mm_slli_si128(temp4, 0x4);
            $temp1 = _mm_xor_si128($temp1, temp4);
            temp4  = _mm_slli_si128(temp4, 0x4);
            $temp1 = _mm_xor_si128($temp1, temp4);
            $temp1 = _mm_xor_si128($temp1, $temp2);
            $temp2 = _mm_shuffle_epi32($temp1, 0xff);
            temp4  = _mm_slli_si128($temp3, 0x4);
            $temp3 = _mm_xor_si128($temp3, temp4);
            $temp3 = _mm_xor_si128($temp3, $temp2);
        }
    }
}

#[derive(Clone)]
pub struct Aes192 {
    ek: [__m128i; 24],
}

impl Zeroize for Aes192 {
    fn zeroize(&mut self) {
        unsafe {
            self.ek = [_mm_setzero_si128(); 24];
        }
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

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        use core::mem::transmute;

        unsafe {
            let mut ek: [__m128i; 24] = core::mem::zeroed();

            let mut k2 = [0u8; 16];
            k2[0..8].copy_from_slice(&key[16..24]);

            let mut temp1 = _mm_loadu_si128(key.as_ptr() as *const __m128i);
            let mut temp2: __m128i = core::mem::zeroed();
            let mut temp3 = _mm_loadu_si128(k2.as_ptr() as *const __m128i);
            
            ek[0] = temp1;
            ek[1] = temp3;

            temp2 = _mm_aeskeygenassist_si128(temp3, 0x1);
            aes192_keyround!(temp1, temp2, temp3);

            ek[1] = transmute(_mm_shuffle_pd(transmute(ek[1]), transmute(temp1), 0));
            ek[2] = transmute(_mm_shuffle_pd(transmute(temp1), transmute(temp3), 1));
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x2);
            aes192_keyround!(temp1, temp2, temp3);
            
            ek[3] = temp1;
            ek[4] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x4);
            aes192_keyround!(temp1, temp2, temp3);

            ek[4] = transmute(_mm_shuffle_pd(transmute(ek[4]), transmute(temp1), 0));
            ek[5] = transmute(_mm_shuffle_pd(transmute(temp1), transmute(temp3), 1));
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x8);
            aes192_keyround!(temp1, temp2, temp3);

            ek[6] = temp1;
            ek[7] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
            aes192_keyround!(temp1, temp2, temp3);

            ek[7] = transmute(_mm_shuffle_pd(transmute(ek[7]), transmute(temp1), 0));
            ek[8] = transmute(_mm_shuffle_pd(transmute(temp1), transmute(temp3), 1));
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
            aes192_keyround!(temp1, temp2, temp3);

            ek[ 9] = temp1;
            ek[10] = temp3;
            temp2  = _mm_aeskeygenassist_si128(temp3, 0x40);
            aes192_keyround!(temp1, temp2, temp3);

            ek[10] = transmute(_mm_shuffle_pd(transmute(ek[10]), transmute(temp1), 0));
            ek[11] = transmute(_mm_shuffle_pd(transmute(temp1), transmute(temp3), 1));
            temp2  = _mm_aeskeygenassist_si128(temp3, 0x80);
            aes192_keyround!(temp1, temp2, temp3);

            ek[12] = temp1;

            ek[13] = _mm_aesimc_si128(ek[11]);
            ek[14] = _mm_aesimc_si128(ek[10]);
            ek[15] = _mm_aesimc_si128(ek[ 9]);
            ek[16] = _mm_aesimc_si128(ek[ 8]);
            ek[17] = _mm_aesimc_si128(ek[ 7]);
            ek[18] = _mm_aesimc_si128(ek[ 6]);
            ek[19] = _mm_aesimc_si128(ek[ 5]);
            ek[20] = _mm_aesimc_si128(ek[ 4]);
            ek[21] = _mm_aesimc_si128(ek[ 3]);
            ek[22] = _mm_aesimc_si128(ek[ 2]);
            ek[23] = _mm_aesimc_si128(ek[ 1]);

            Self { ek }
        }
    }
    
    pub fn encrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        unsafe {
            let mut m = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            m =        _mm_xor_si128(m, self.ek[ 0]);
            m =     _mm_aesenc_si128(m, self.ek[ 1]);
            m =     _mm_aesenc_si128(m, self.ek[ 2]);
            m =     _mm_aesenc_si128(m, self.ek[ 3]);
            m =     _mm_aesenc_si128(m, self.ek[ 4]);
            m =     _mm_aesenc_si128(m, self.ek[ 5]);
            m =     _mm_aesenc_si128(m, self.ek[ 6]);
            m =     _mm_aesenc_si128(m, self.ek[ 7]);
            m =     _mm_aesenc_si128(m, self.ek[ 8]);
            m =     _mm_aesenc_si128(m, self.ek[ 9]);
            m =     _mm_aesenc_si128(m, self.ek[10]);
            m =     _mm_aesenc_si128(m, self.ek[11]);
            m =     _mm_aesenclast_si128(m, self.ek[12]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, m);
        }
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        unsafe {
            let mut m = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            m =        _mm_xor_si128(m, self.ek[12]);
            m =     _mm_aesdec_si128(m, self.ek[13]);
            m =     _mm_aesdec_si128(m, self.ek[14]);
            m =     _mm_aesdec_si128(m, self.ek[15]);
            m =     _mm_aesdec_si128(m, self.ek[16]);
            m =     _mm_aesdec_si128(m, self.ek[17]);
            m =     _mm_aesdec_si128(m, self.ek[18]);
            m =     _mm_aesdec_si128(m, self.ek[19]);
            m =     _mm_aesdec_si128(m, self.ek[20]);
            m =     _mm_aesdec_si128(m, self.ek[21]);
            m =     _mm_aesdec_si128(m, self.ek[22]);
            m =     _mm_aesdec_si128(m, self.ek[23]);
            m =     _mm_aesdeclast_si128(m, self.ek[ 0]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, m);
        }
    }
}



macro_rules! aes256_keyround_1 {
    ($temp1:tt, $temp2:tt) => {
        {
            let mut temp4 = _mm_slli_si128($temp1, 0x4);
            $temp2 = _mm_shuffle_epi32($temp2, 0xff);
            $temp1 = _mm_xor_si128($temp1, temp4);
            temp4 = _mm_slli_si128(temp4, 0x4);
            $temp1 = _mm_xor_si128($temp1, temp4);
            temp4 = _mm_slli_si128(temp4, 0x4);
            $temp1 = _mm_xor_si128($temp1, temp4);
            $temp1 = _mm_xor_si128($temp1, $temp2);
        }
    }
}
macro_rules! aes256_keyround_2 {
    ($temp1:tt, $temp3:tt) => {
        {
            let mut temp4 = _mm_aeskeygenassist_si128($temp1, 0x0);
            let temp2 = _mm_shuffle_epi32(temp4, 0xaa);
            temp4 = _mm_slli_si128($temp3, 0x4);
            $temp3 = _mm_xor_si128($temp3, temp4);
            temp4 = _mm_slli_si128(temp4, 0x4);
            $temp3 = _mm_xor_si128($temp3, temp4);
            temp4 = _mm_slli_si128(temp4, 0x4);
            $temp3 = _mm_xor_si128($temp3, temp4);
            $temp3 = _mm_xor_si128($temp3, temp2);
        }
    }
}


#[derive(Clone)]
pub struct Aes256 {
    ek: [__m128i; 28],
}

impl Zeroize for Aes256 {
    fn zeroize(&mut self) {
        unsafe {
            self.ek = [_mm_setzero_si128(); 28];
        }
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

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        unsafe {
            let mut ek: [__m128i; 28] = core::mem::zeroed();

            let mut temp1 = _mm_loadu_si128(key.as_ptr() as *const __m128i);
            let mut temp2: __m128i = core::mem::zeroed();
            let mut temp3 = _mm_loadu_si128(key.as_ptr().offset(16) as *const __m128i);

            ek[0] = temp1;
            ek[1] = temp3;

            temp2 = _mm_aeskeygenassist_si128(temp3, 0x1);
            aes256_keyround_1!(temp1, temp2);
            ek[2] = temp1;
            aes256_keyround_2!(temp1, temp3);

            ek[3] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
            aes256_keyround_1!(temp1, temp2);
            ek[4] = temp1;
            aes256_keyround_2!(temp1, temp3);
        
            ek[5] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
            aes256_keyround_1!(temp1, temp2);
            ek[6] = temp1;
            aes256_keyround_2!(temp1, temp3);

            ek[7] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
            aes256_keyround_1!(temp1, temp2);
            ek[8] = temp1;
            aes256_keyround_2!(temp1, temp3);

            ek[9] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
            aes256_keyround_1!(temp1, temp2);
            ek[10] = temp1;
            aes256_keyround_2!(temp1, temp3);

            ek[11] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
            aes256_keyround_1!(temp1, temp2);
            ek[12] = temp1;
            aes256_keyround_2!(temp1, temp3);

            ek[13] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
            aes256_keyround_1!(temp1, temp2);
            ek[14] = temp1;

            ek[15] = _mm_aesimc_si128(ek[13]);
            ek[16] = _mm_aesimc_si128(ek[12]);
            ek[17] = _mm_aesimc_si128(ek[11]);
            ek[18] = _mm_aesimc_si128(ek[10]);
            ek[19] = _mm_aesimc_si128(ek[ 9]);
            ek[20] = _mm_aesimc_si128(ek[ 8]);
            ek[21] = _mm_aesimc_si128(ek[ 7]);
            ek[22] = _mm_aesimc_si128(ek[ 6]);
            ek[23] = _mm_aesimc_si128(ek[ 5]);
            ek[24] = _mm_aesimc_si128(ek[ 4]);
            ek[25] = _mm_aesimc_si128(ek[ 3]);
            ek[26] = _mm_aesimc_si128(ek[ 2]);
            ek[27] = _mm_aesimc_si128(ek[ 1]);

            Self { ek }
        }
    }
    
    pub fn encrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        unsafe {
            let mut m = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            m =        _mm_xor_si128(m, self.ek[ 0]);
            m =     _mm_aesenc_si128(m, self.ek[ 1]);
            m =     _mm_aesenc_si128(m, self.ek[ 2]);
            m =     _mm_aesenc_si128(m, self.ek[ 3]);
            m =     _mm_aesenc_si128(m, self.ek[ 4]);
            m =     _mm_aesenc_si128(m, self.ek[ 5]);
            m =     _mm_aesenc_si128(m, self.ek[ 6]);
            m =     _mm_aesenc_si128(m, self.ek[ 7]);
            m =     _mm_aesenc_si128(m, self.ek[ 8]);
            m =     _mm_aesenc_si128(m, self.ek[ 9]);
            m =     _mm_aesenc_si128(m, self.ek[10]);
            m =     _mm_aesenc_si128(m, self.ek[11]);
            m =     _mm_aesenc_si128(m, self.ek[12]);
            m =     _mm_aesenc_si128(m, self.ek[13]);
            m =     _mm_aesenclast_si128(m, self.ek[14]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, m);
        }
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);
        
        unsafe {
            let mut m = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            m =        _mm_xor_si128(m, self.ek[14]);
            m =     _mm_aesdec_si128(m, self.ek[15]);
            m =     _mm_aesdec_si128(m, self.ek[16]);
            m =     _mm_aesdec_si128(m, self.ek[17]);
            m =     _mm_aesdec_si128(m, self.ek[18]);
            m =     _mm_aesdec_si128(m, self.ek[19]);
            m =     _mm_aesdec_si128(m, self.ek[20]);
            m =     _mm_aesdec_si128(m, self.ek[21]);
            m =     _mm_aesdec_si128(m, self.ek[22]);
            m =     _mm_aesdec_si128(m, self.ek[23]);
            m =     _mm_aesdec_si128(m, self.ek[24]);
            m =     _mm_aesdec_si128(m, self.ek[25]);
            m =     _mm_aesdec_si128(m, self.ek[26]);
            m =     _mm_aesdec_si128(m, self.ek[27]);
            m =     _mm_aesdeclast_si128(m, self.ek[0]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, m);
        }
    }
}


#[test]
fn test_example_vectors_aesni() {
    // Appendix C – Example Vectors 
    {
        // AES 128
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let plaintext = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        
        let cipher = Aes128::new(&key);

        let mut ciphertext = plaintext.clone();
        cipher.encrypt(&mut ciphertext);
        assert_eq!(&ciphertext[..],
            &hex::decode("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap()[..]);

        let mut cleartext = ciphertext.clone();
        cipher.decrypt(&mut cleartext);
        assert_eq!(&cleartext[..], &plaintext[..]);
    }

    {
        // AES 192
        let key = hex::decode("000102030405060708090a0b0c0d0e0f1011121314151617").unwrap();
        let plaintext = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        
        let cipher = Aes192::new(&key);
        
        let mut ciphertext = plaintext.clone();
        cipher.encrypt(&mut ciphertext);
        assert_eq!(&ciphertext[..],
            &hex::decode("dda97ca4864cdfe06eaf70a0ec0d7191").unwrap()[..]);

        let mut cleartext = ciphertext.clone();
        cipher.decrypt(&mut cleartext);
        assert_eq!(&cleartext[..], &plaintext[..]);
    }

    {
        // AES 256
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let plaintext = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        
        let cipher = Aes256::new(&key);

        let mut ciphertext = plaintext.clone();
        cipher.encrypt(&mut ciphertext);
        assert_eq!(&ciphertext[..],
            &hex::decode("8ea2b7ca516745bfeafc49904b496089").unwrap()[..]);

        let mut cleartext = ciphertext.clone();
        cipher.decrypt(&mut cleartext);
        assert_eq!(&cleartext[..], &plaintext[..]);
    }
}
