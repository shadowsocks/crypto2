#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;


/// ChaCha20 for IETF Protocols
/// 
/// <https://tools.ietf.org/html/rfc8439>
#[cfg(target_feature = "sse2")]
#[derive(Clone)]
pub struct XChacha20 {
    initial_state: [__m128i; 4],
}

#[cfg(target_feature = "sse2")]
impl core::fmt::Debug for XChacha20 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("XChacha20").finish()
    }
}

#[cfg(target_feature = "sse2")]
impl XChacha20 {
    pub const KEY_LEN: usize     = 32;
    pub const BLOCK_LEN: usize   = 64;
    pub const NONCE_LEN: usize   = 24;
    pub const COUNTER_LEN: usize = 4;


    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        unsafe {
            let mut initial_state = [_mm_setzero_si128(); 4];
            
            // SIGMA constant b"expand 16-byte k" [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574]
            // SIGMA constant b"expand 32-byte k" [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
            initial_state[0] = _mm_setr_epi32(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574);

            // A 256-bit key (32 Bytes)
            initial_state[1] = _mm_loadu_si128(key.as_ptr()            as *const __m128i);
            initial_state[2] = _mm_loadu_si128(key.as_ptr().offset(16) as *const __m128i);

            Self { initial_state }
        }
    }

    #[inline]
    unsafe fn hchacha20(&self, nonce: &[u8]) -> [__m128i; 2] {
        let mut initial_state = self.initial_state.clone();

        // Nonce (128-bits, little-endian)
        initial_state[3] = _mm_loadu_si128(nonce.as_ptr() as *const __m128i);

        // 20 rounds (diagonal rounds)
        diagonal_rounds(&mut initial_state);

        [ initial_state[0], initial_state[3] ]
    }

    #[inline]
    unsafe fn in_place(&self, init_block_counter: u32, nonce: &[u8], plaintext_or_ciphertext: &mut [u8]) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let subkey = self.hchacha20(&nonce[..16]);

        let mut initial_state = self.initial_state.clone();
        
        // NOTE: 使用 HChaCha20 生成的 256-bits Key.
        initial_state[1] = subkey[0];
        initial_state[2] = subkey[1];

        // Counter (32-bits, little-endian), Nonce (96-bits, little-endian)
        let n2 = u32::from_le_bytes([nonce[16], nonce[17], nonce[18], nonce[19]]) as i32;
        let n3 = u32::from_le_bytes([nonce[20], nonce[21], nonce[22], nonce[23]]) as i32;
        initial_state[3] = _mm_setr_epi32(init_block_counter as i32, 0, n2, n3);

        let one = _mm_setr_epi32(1, 0, 0, 0);

        let mut chunks = plaintext_or_ciphertext.chunks_exact_mut(Self::BLOCK_LEN);
        
        for block in &mut chunks {
            let mut state = initial_state.clone();
            
            // 20 rounds (diagonal rounds)
            diagonal_rounds(&mut state);
            state[0] = _mm_add_epi32(state[0], initial_state[0]);
            state[1] = _mm_add_epi32(state[1], initial_state[1]);
            state[2] = _mm_add_epi32(state[2], initial_state[2]);
            state[3] = _mm_add_epi32(state[3], initial_state[3]);

            // Update Block Counter
            initial_state[3] = _mm_add_epi32(initial_state[3], one);

            // XOR 512-bits
            let p1 = block.as_mut_ptr()         as *mut __m128i;
            let p2 = block.as_mut_ptr().add(16) as *mut __m128i;
            let p3 = block.as_mut_ptr().add(32) as *mut __m128i;
            let p4 = block.as_mut_ptr().add(48) as *mut __m128i;

            _mm_storeu_si128(p1, _mm_xor_si128(state[0], _mm_loadu_si128(p1 as *const _)));
            _mm_storeu_si128(p2, _mm_xor_si128(state[1], _mm_loadu_si128(p2 as *const _)));
            _mm_storeu_si128(p3, _mm_xor_si128(state[2], _mm_loadu_si128(p3 as *const _)));
            _mm_storeu_si128(p4, _mm_xor_si128(state[3], _mm_loadu_si128(p4 as *const _)));
        }

        let rem: &mut [u8] = chunks.into_remainder();
        let rlen = rem.len();

        if rlen > 0 {
            // Last Block
            let mut state = initial_state.clone();

            // 20 rounds (diagonal rounds)
            diagonal_rounds(&mut state);
            state[0] = _mm_add_epi32(state[0], initial_state[0]);
            state[1] = _mm_add_epi32(state[1], initial_state[1]);
            state[2] = _mm_add_epi32(state[2], initial_state[2]);
            state[3] = _mm_add_epi32(state[3], initial_state[3]);

            let mut last_block = [0u8; Self::BLOCK_LEN];
            last_block[..rlen].copy_from_slice(&rem);

            // XOR 512-bits
            let p1 = last_block.as_mut_ptr()         as *mut __m128i;
            let p2 = last_block.as_mut_ptr().add(16) as *mut __m128i;
            let p3 = last_block.as_mut_ptr().add(32) as *mut __m128i;
            let p4 = last_block.as_mut_ptr().add(48) as *mut __m128i;

            _mm_storeu_si128(p1, _mm_xor_si128(state[0], _mm_loadu_si128(p1 as *const _)));
            _mm_storeu_si128(p2, _mm_xor_si128(state[1], _mm_loadu_si128(p2 as *const _)));
            _mm_storeu_si128(p3, _mm_xor_si128(state[2], _mm_loadu_si128(p3 as *const _)));
            _mm_storeu_si128(p4, _mm_xor_si128(state[3], _mm_loadu_si128(p4 as *const _)));

            rem.copy_from_slice(&last_block[..rlen]);
        }
    }

    /// Nonce (96-bits, little-endian)
    #[inline]
    pub fn encrypt_slice(&self, init_block_counter: u32, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        unsafe { self.in_place(init_block_counter, nonce, plaintext_in_ciphertext_out) }
    }

    /// Nonce (96-bits, little-endian)
    #[inline]
    pub fn decrypt_slice(&self, init_block_counter: u32, nonce: &[u8], ciphertext_in_plaintext_and: &mut [u8]) {
        unsafe { self.in_place(init_block_counter, nonce, ciphertext_in_plaintext_and) }
    }
}

#[cfg(target_feature = "sse2")]
unsafe fn diagonal_rounds(state: &mut [__m128i; 4]) {
    macro_rules! VG {
        ($va:expr, $vb:expr, $vc:expr, $vd:expr) => {
            // NOTE: _mm_rol_epi32 和 _mm_ror_epi32 需要 avx512f, avx512vl X86 target feature.
            //       因此我们使用模拟。
            $va = _mm_add_epi32($va, $vb);
            $vd = _mm_xor_si128($vd, $va);
            $vd = _mm_xor_si128(_mm_slli_epi32::<16>($vd), _mm_srli_epi32::<16>($vd)); // rotate_left(16)
            $vc = _mm_add_epi32($vc, $vd);
            $vb = _mm_xor_si128($vb, $vc);
            $vb = _mm_xor_si128(_mm_slli_epi32::<12>($vb), _mm_srli_epi32::<20>($vb)); // rotate_left(12)
            
            $va = _mm_add_epi32($va, $vb);
            $vd = _mm_xor_si128($vd, $va);
            $vd = _mm_xor_si128(_mm_slli_epi32::<8>($vd), _mm_srli_epi32::<24>($vd)); // rotate_left(8)
            $vc = _mm_add_epi32($vc, $vd);
            $vb = _mm_xor_si128($vb, $vc);
            $vb = _mm_xor_si128(_mm_slli_epi32::<7>($vb), _mm_srli_epi32::<25>($vb)); // rotate_left(7)
        }
    }
    
    for _ in 0..10 {
        VG!(state[0], state[1], state[2], state[3]);
        state[1] = _mm_shuffle_epi32::<0b_00_11_10_01>(state[1]); // _MM_SHUFFLE(0, 3, 2, 1)
        state[2] = _mm_shuffle_epi32::<0b_01_00_11_10>(state[2]); // _MM_SHUFFLE(1, 0, 3, 2)
        state[3] = _mm_shuffle_epi32::<0b_10_01_00_11>(state[3]); // _MM_SHUFFLE(2, 1, 0, 3)

        VG!(state[0], state[1], state[2], state[3]);
        state[1] = _mm_shuffle_epi32::<0b_10_01_00_11>(state[1]); // _MM_SHUFFLE(2, 1, 0, 3)
        state[2] = _mm_shuffle_epi32::<0b_01_00_11_10>(state[2]); // _MM_SHUFFLE(1, 0, 3, 2)
        state[3] = _mm_shuffle_epi32::<0b_00_11_10_01>(state[3]); // _MM_SHUFFLE(0, 3, 2, 1)
    }
}


#[test]
fn test_xchacha20() {
    // Example and Test Vectors for XChaCha20
    // https://github.com/bikeshedders/xchacha-rfc/blob/master/xchacha.md#example-and-test-vectors-for-xchacha20
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x58,
    ];

    let plaintext = b"The dhole (pronounced \"dole\") is also known as the Asiatic wild dog\
, red dog, and whistling dog. It is about the size of a German shepherd but looks more like a \
long-legged fox. This highly elusive and skilled jumper is classified with wolves, coyotes, \
jackals, and foxes in the taxonomic family Canidae.";
    
    let cipher = XChacha20::new(&key);
    let block_counter = 0u32;

    let mut ciphertext = plaintext.to_vec();
    cipher.encrypt_slice(block_counter, &nonce, &mut ciphertext);
    assert_eq!(&ciphertext, &[
        0x45, 0x59, 0xab, 0xba, 0x4e, 0x48, 0xc1, 0x61, 0x02, 0xe8, 0xbb, 0x2c, 0x05, 0xe6, 0x94, 0x7f,
        0x50, 0xa7, 0x86, 0xde, 0x16, 0x2f, 0x9b, 0x0b, 0x7e, 0x59, 0x2a, 0x9b, 0x53, 0xd0, 0xd4, 0xe9,
        0x8d, 0x8d, 0x64, 0x10, 0xd5, 0x40, 0xa1, 0xa6, 0x37, 0x5b, 0x26, 0xd8, 0x0d, 0xac, 0xe4, 0xfa,
        0xb5, 0x23, 0x84, 0xc7, 0x31, 0xac, 0xbf, 0x16, 0xa5, 0x92, 0x3c, 0x0c, 0x48, 0xd3, 0x57, 0x5d,
        0x4d, 0x0d, 0x2c, 0x67, 0x3b, 0x66, 0x6f, 0xaa, 0x73, 0x10, 0x61, 0x27, 0x77, 0x01, 0x09, 0x3a,
        0x6b, 0xf7, 0xa1, 0x58, 0xa8, 0x86, 0x42, 0x92, 0xa4, 0x1c, 0x48, 0xe3, 0xa9, 0xb4, 0xc0, 0xda,
        0xec, 0xe0, 0xf8, 0xd9, 0x8d, 0x0d, 0x7e, 0x05, 0xb3, 0x7a, 0x30, 0x7b, 0xbb, 0x66, 0x33, 0x31,
        0x64, 0xec, 0x9e, 0x1b, 0x24, 0xea, 0x0d, 0x6c, 0x3f, 0xfd, 0xdc, 0xec, 0x4f, 0x68, 0xe7, 0x44,
        0x30, 0x56, 0x19, 0x3a, 0x03, 0xc8, 0x10, 0xe1, 0x13, 0x44, 0xca, 0x06, 0xd8, 0xed, 0x8a, 0x2b,
        0xfb, 0x1e, 0x8d, 0x48, 0xcf, 0xa6, 0xbc, 0x0e, 0xb4, 0xe2, 0x46, 0x4b, 0x74, 0x81, 0x42, 0x40,
        0x7c, 0x9f, 0x43, 0x1a, 0xee, 0x76, 0x99, 0x60, 0xe1, 0x5b, 0xa8, 0xb9, 0x68, 0x90, 0x46, 0x6e,
        0xf2, 0x45, 0x75, 0x99, 0x85, 0x23, 0x85, 0xc6, 0x61, 0xf7, 0x52, 0xce, 0x20, 0xf9, 0xda, 0x0c,
        0x09, 0xab, 0x6b, 0x19, 0xdf, 0x74, 0xe7, 0x6a, 0x95, 0x96, 0x74, 0x46, 0xf8, 0xd0, 0xfd, 0x41,
        0x5e, 0x7b, 0xee, 0x2a, 0x12, 0xa1, 0x14, 0xc2, 0x0e, 0xb5, 0x29, 0x2a, 0xe7, 0xa3, 0x49, 0xae,
        0x57, 0x78, 0x20, 0xd5, 0x52, 0x0a, 0x1f, 0x3f, 0xb6, 0x2a, 0x17, 0xce, 0x6a, 0x7e, 0x68, 0xfa,
        0x7c, 0x79, 0x11, 0x1d, 0x88, 0x60, 0x92, 0x0b, 0xc0, 0x48, 0xef, 0x43, 0xfe, 0x84, 0x48, 0x6c,
        0xcb, 0x87, 0xc2, 0x5f, 0x0a, 0xe0, 0x45, 0xf0, 0xcc, 0xe1, 0xe7, 0x98, 0x9a, 0x9a, 0xa2, 0x20,
        0xa2, 0x8b, 0xdd, 0x48, 0x27, 0xe7, 0x51, 0xa2, 0x4a, 0x6d, 0x5c, 0x62, 0xd7, 0x90, 0xa6, 0x63,
        0x93, 0xb9, 0x31, 0x11, 0xc1, 0xa5, 0x5d, 0xd7, 0x42, 0x1a, 0x10, 0x18, 0x49, 0x74, 0xc7, 0xc5,
    ]);

    let mut cleartext = ciphertext.clone();
    cipher.decrypt_slice(block_counter, &nonce, &mut cleartext);
    assert_eq!(&cleartext, &plaintext);
}