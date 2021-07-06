/// ChaCha20 for IETF Protocols
/// 
/// <https://tools.ietf.org/html/rfc8439>
#[derive(Clone)]
pub struct XChacha20 {
    initial_state: [u32; 16],
}

impl core::fmt::Debug for XChacha20 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("XChacha20").finish()
    }
}

impl XChacha20 {
    pub const KEY_LEN: usize     = 32;
    pub const BLOCK_LEN: usize   = 64;
    pub const NONCE_LEN: usize   = 24;
    
    const STATE_LEN: usize = 16; // len in doubleword (32-bits)

    // cccccccc  cccccccc  cccccccc  cccccccc
    // kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
    // kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
    // nnnnnnnn  nnnnnnnn  nnnnnnnn  nnnnnnnn
    //
    // HChaCha20 State: c=constant k=key n=nonce
    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        let mut initial_state = [0u32; Self::STATE_LEN];

        // The ChaCha20 state is initialized as follows:
        // 
        // SIGMA constant b"expand 16-byte k" [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574]
        // SIGMA constant b"expand 32-byte k" [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        initial_state[0] = 0x61707865;
        initial_state[1] = 0x3320646e;
        initial_state[2] = 0x79622d32;
        initial_state[3] = 0x6b206574;

        // A 256-bit key (32 Bytes)
        initial_state[ 4] = u32::from_le_bytes([key[ 0], key[ 1], key[ 2], key[ 3]]);
        initial_state[ 5] = u32::from_le_bytes([key[ 4], key[ 5], key[ 6], key[ 7]]);
        initial_state[ 6] = u32::from_le_bytes([key[ 8], key[ 9], key[10], key[11]]);
        initial_state[ 7] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
        initial_state[ 8] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        initial_state[ 9] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        initial_state[10] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        initial_state[11] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);

        Self { initial_state }
    }

    #[inline]
    fn hchacha20(&self, nonce: &[u8]) -> [u32; 8] {
        let mut initial_state = self.initial_state.clone();

        // Nonce (128-bits, little-endian)
        initial_state[12] = u32::from_le_bytes([nonce[ 0], nonce[ 1], nonce[ 2], nonce[ 3]]);
        initial_state[13] = u32::from_le_bytes([nonce[ 4], nonce[ 5], nonce[ 6], nonce[ 7]]);
        initial_state[14] = u32::from_le_bytes([nonce[ 8], nonce[ 9], nonce[10], nonce[11]]);
        initial_state[15] = u32::from_le_bytes([nonce[12], nonce[13], nonce[14], nonce[15]]);
        
        // 20 rounds (diagonal rounds)
        diagonal_rounds(&mut initial_state);

        let mut subkey = [0u32; 8];
        subkey[0] = initial_state[0];
        subkey[1] = initial_state[1];
        subkey[2] = initial_state[2];
        subkey[3] = initial_state[3];

        subkey[4] = initial_state[12];
        subkey[5] = initial_state[13];
        subkey[6] = initial_state[14];
        subkey[7] = initial_state[15];

        subkey
    }

    #[inline]
    fn in_place(&self, init_block_counter: u32, nonce: &[u8], plaintext_or_ciphertext: &mut [u8]) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let subkey = self.hchacha20(&nonce[..16]);

        let mut initial_state = self.initial_state.clone();
        
        // NOTE: 使用 HChaCha20 生成的 256-bits Key.
        initial_state[ 4] = subkey[0];
        initial_state[ 5] = subkey[1];
        initial_state[ 6] = subkey[2];
        initial_state[ 7] = subkey[3];
        initial_state[ 8] = subkey[4];
        initial_state[ 9] = subkey[5];
        initial_state[10] = subkey[6];
        initial_state[11] = subkey[7];

        // ChaCha20 Counter (32-bits, little-endian)
        initial_state[12] = init_block_counter;

        // ChaCha20 Nonce (96-bits, little-endian)
        // 
        // NOTE: 重新组装 12 Bytes 的 Chacha20 Nonce
        //       [0, 0, 0, 0] + nonce[16..24]
        //       ------------   -------------
        //          4 Bytes   +    8 Bytes    = 12 Bytes
        initial_state[13] = 0;
        initial_state[14] = u32::from_le_bytes([nonce[16], nonce[17], nonce[18], nonce[19]]);
        initial_state[15] = u32::from_le_bytes([nonce[20], nonce[21], nonce[22], nonce[23]]);
        
        let mut chunks = plaintext_or_ciphertext.chunks_exact_mut(Self::BLOCK_LEN);

        for block in &mut chunks {
            let mut state = initial_state.clone();

            // 20 rounds (diagonal rounds)
            diagonal_rounds(&mut state);
            for i in 0..16 {
                state[i] = state[i].wrapping_add(initial_state[i]);
            }

            // Update Block Counter
            initial_state[12] = initial_state[12].wrapping_add(1);

            // XOR 512-bits
            #[cfg(target_endian = "little")]
            unsafe {
                let p = core::slice::from_raw_parts_mut(block.as_mut_ptr() as *mut u32, 16);
                for i in 0..16 {
                    p[i] ^= state[i];
                }
            }
            #[cfg(target_endian = "big")]
            {
                let mut keystream = [0u8; Self::BLOCK_LEN];
                state_to_keystream(&state, &mut keystream);
                for i in 0..64 {
                    p[i] ^= keystream[i];
                }
            }
        }

        let rem = chunks.into_remainder();
        let rlen = rem.len();

        if rlen > 0 {
            // Last Block
            let mut state = initial_state.clone();

            // 20 rounds (diagonal rounds)
            diagonal_rounds(&mut state);
            for i in 0..16 {
                state[i] = state[i].wrapping_add(initial_state[i]);
            }
            
            #[cfg(target_endian = "little")]
            unsafe {
                let keystream = core::slice::from_raw_parts(state.as_ptr() as *const u8, Self::BLOCK_LEN);
                for i in 0..rlen {
                    rem[i] ^= keystream[i];
                }
            }

            #[cfg(target_endian = "big")]
            {
                let mut keystream = [0u8; Self::BLOCK_LEN];
                state_to_keystream(&state, &mut keystream);

                for i in 0..rlen {
                    rem[i] ^= keystream[i];
                }
            }
        }
    }

    /// Nonce (96-bits, little-endian)
    #[inline]
    pub fn encrypt_slice(&self, init_block_counter: u32, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        self.in_place(init_block_counter, nonce, plaintext_in_ciphertext_out)
    }

    /// Nonce (96-bits, little-endian)
    #[inline]
    pub fn decrypt_slice(&self, init_block_counter: u32, nonce: &[u8], ciphertext_in_plaintext_and: &mut [u8]) {
        self.in_place(init_block_counter, nonce, ciphertext_in_plaintext_and)
    }
}

/// 2.1.  The ChaCha Quarter Round
// https://tools.ietf.org/html/rfc8439#section-2.1
#[inline]
fn quarter_round(state: &mut [u32], ai: usize, bi: usize, ci: usize, di: usize) {
    // n <<<= m
    // 等价于: (n << m) ^ (n >> (32 - 8))

    // a += b; d ^= a; d <<<= 16;
    // c += d; b ^= c; b <<<= 12;
    // a += b; d ^= a; d <<<= 8;
    // c += d; b ^= c; b <<<= 7;
    let mut a = state[ai];
    let mut b = state[bi];
    let mut c = state[ci];
    let mut d = state[di];

    a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
    c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
    a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);
    c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);

    state[ai] = a;
    state[bi] = b;
    state[ci] = c;
    state[di] = d;
}

#[inline]
fn diagonal_rounds(state: &mut [u32; XChacha20::STATE_LEN]) {
    for _ in 0..10 {
        // column rounds
        quarter_round(state, 0, 4,  8, 12);
        quarter_round(state, 1, 5,  9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);

        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7,  8, 13);
        quarter_round(state, 3, 4,  9, 14);
    }
}

#[cfg(target_endian = "big")]
#[inline]
fn state_to_keystream(state: &[u32; XChacha20::STATE_LEN], keystream: &mut [u8; XChacha20::BLOCK_LEN]) {
    keystream[ 0.. 4].copy_from_slice(&state[ 0].to_le_bytes());
    keystream[ 4.. 8].copy_from_slice(&state[ 1].to_le_bytes());
    keystream[ 8..12].copy_from_slice(&state[ 2].to_le_bytes());
    keystream[12..16].copy_from_slice(&state[ 3].to_le_bytes());
    keystream[16..20].copy_from_slice(&state[ 4].to_le_bytes());
    keystream[20..24].copy_from_slice(&state[ 5].to_le_bytes());
    keystream[24..28].copy_from_slice(&state[ 6].to_le_bytes());
    keystream[28..32].copy_from_slice(&state[ 7].to_le_bytes());
    keystream[32..36].copy_from_slice(&state[ 8].to_le_bytes());
    keystream[36..40].copy_from_slice(&state[ 9].to_le_bytes());
    keystream[40..44].copy_from_slice(&state[10].to_le_bytes());
    keystream[44..48].copy_from_slice(&state[11].to_le_bytes());
    keystream[48..52].copy_from_slice(&state[12].to_le_bytes());
    keystream[52..56].copy_from_slice(&state[13].to_le_bytes());
    keystream[56..60].copy_from_slice(&state[14].to_le_bytes());
    keystream[60..64].copy_from_slice(&state[15].to_le_bytes());
}


#[test]
fn test_xchacha20_hchacha20() {
    // Test Vector for the HChaCha20 Block Function
    // https://github.com/bikeshedders/xchacha-rfc/blob/master/xchacha.md#test-vector-for-the-hchacha20-block-function
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59,
        0x27,
    ];

    let xchacha20 = XChacha20::new(&key);
    let mut subkey = xchacha20.hchacha20(&nonce);
    for n in subkey.iter_mut() {
        *n = n.to_be();
    }

    assert_eq!(&subkey, &[
            0x82413b42, 0x27b27bfe, 0xd30e4250, 0x8a877d73, 0xa0f9e4d5, 0x8a74a853, 0xc12ec413,
            0x26d3ecdc,
    ]);
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