#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;


/// ChaCha20 for IETF Protocols
/// 
/// <https://tools.ietf.org/html/rfc8439>
#[cfg(target_feature = "sse2")]
#[derive(Clone)]
pub struct Chacha20 {
    initial_state: [__m128i; 4],
}

#[cfg(target_feature = "sse2")]
impl core::fmt::Debug for Chacha20 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Chacha20").finish()
    }
}

#[cfg(target_feature = "sse2")]
impl Chacha20 {
    pub const KEY_LEN: usize     = 32;
    pub const BLOCK_LEN: usize   = 64;
    pub const NONCE_LEN: usize   = 12;
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
    unsafe fn in_place(&self, init_block_counter: u32, nonce: &[u8], plaintext_or_ciphertext: &mut [u8]) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let mut initial_state = self.initial_state.clone();
        
        // Counter (32-bits, little-endian), Nonce (96-bits, little-endian)
        let n1 = u32::from_le_bytes([nonce[ 0], nonce[ 1], nonce[ 2], nonce[ 3]]) as i32;
        let n2 = u32::from_le_bytes([nonce[ 4], nonce[ 5], nonce[ 6], nonce[ 7]]) as i32;
        let n3 = u32::from_le_bytes([nonce[ 8], nonce[ 9], nonce[10], nonce[11]]) as i32;
        initial_state[3] = _mm_setr_epi32(init_block_counter as i32, n1, n2, n3);

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
fn test_chacha20_cipher() {
    // 2.4.2.  Example and Test Vector for the ChaCha20 Cipher
    // https://tools.ietf.org/html/rfc8439#section-2.4.2
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 
        0x00, 0x00, 0x00, 0x00
    ];
    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
    let mut ciphertext = plaintext.to_vec();

    let chacha20 = Chacha20::new(&key);
    chacha20.encrypt_slice(1, &nonce, &mut ciphertext);
    assert_eq!(&ciphertext[..], &[
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    ]);
}