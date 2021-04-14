use crate::mem::Zeroize;
// use crate::util::xor_si128_inplace;


#[inline]
fn add_si512_inplace(a: &mut [u32; Chacha20::STATE_LEN], b: &[u32; Chacha20::STATE_LEN]) {
    for i in 0..Chacha20::STATE_LEN {
        a[i] = a[i].wrapping_add(b[i]);
    }
}

#[inline]
fn xor_si512_inplace(a: &mut [u8], b: &[u32; Chacha20::STATE_LEN]) {
    // NOTE: 看起来编译器会对这种单独的函数做优化，我们不再需要手动写 AVX2/AVX512 的代码咯。
    use core::slice;
    
    unsafe {
        let d1 = slice::from_raw_parts_mut(a.as_mut_ptr() as *mut u32, Chacha20::STATE_LEN);
        for i in 0..Chacha20::STATE_LEN {
            d1[i] ^= b[i];
        }
    }
}

#[inline]
fn v512_i8_xor_inplace(a: &mut [u8], b: &[u8]) {
    for i in 0..64 {
        a[i] ^= b[i];
    }
}


/// ChaCha20 for IETF Protocols
/// 
/// <https://tools.ietf.org/html/rfc8439>
#[derive(Clone)]
pub struct Chacha20 {
    initial_state: [u32; 16],
}

impl Zeroize for Chacha20 {
    fn zeroize(&mut self) {
        self.initial_state.zeroize();
    }
}

impl Drop for Chacha20 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for Chacha20 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Chacha20").finish()
    }
}

impl Chacha20 {
    pub const KEY_LEN: usize     = 32;
    pub const BLOCK_LEN: usize   = 64;
    pub const NONCE_LEN: usize   = 12;
    pub const COUNTER_LEN: usize = 4;

    const STATE_LEN: usize = 16; // len in doubleword (32-bits)

    // NOTE: 16 bytes 长度的 Key 并没有被标准采纳。
    // 
    // sigma constant b"expand 16-byte k" in little-endian encoding
    // const K16: [u32; 4] = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574];

    // sigma constant b"expand 32-byte k" in little-endian encoding
    const K32: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    
    
    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        let mut initial_state = [0u32; Self::STATE_LEN];

        // The ChaCha20 state is initialized as follows:
        initial_state[0] = Self::K32[0];
        initial_state[1] = Self::K32[1];
        initial_state[2] = Self::K32[2];
        initial_state[3] = Self::K32[3];

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
    fn in_place(&self, init_block_counter: u32, nonce: &[u8], plaintext_or_ciphertext: &mut [u8]) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let mut initial_state = self.initial_state.clone();

        // Counter (32-bits, little-endian)
        initial_state[12] = init_block_counter;

        // Nonce (96-bits, little-endian)
        if cfg!(target_endian = "little") {
            unsafe {
                let data: &[u32] = std::slice::from_raw_parts(nonce.as_ptr() as *const u32, nonce.len() / core::mem::size_of::<u32>());
                initial_state[13..16].copy_from_slice(data);
            }
        } else {
            initial_state[13] = u32::from_le_bytes([nonce[ 0], nonce[ 1], nonce[ 2], nonce[ 3]]);
            initial_state[14] = u32::from_le_bytes([nonce[ 4], nonce[ 5], nonce[ 6], nonce[ 7]]);
            initial_state[15] = u32::from_le_bytes([nonce[ 8], nonce[ 9], nonce[10], nonce[11]]);
        }
        
        let mut chunks = plaintext_or_ciphertext.chunks_exact_mut(Self::BLOCK_LEN);
        for plaintext in &mut chunks {
            let mut state = initial_state.clone();

            // 20 rounds (diagonal rounds)
            diagonal_rounds(&mut state);
            add_si512_inplace(&mut state, &mut initial_state);

            // Update Block Counter
            initial_state[12] = initial_state[12].wrapping_add(1);

            if cfg!(target_endian = "little") {
                xor_si512_inplace(plaintext, &state);
            } else {
                let mut keystream = [0u8; Self::BLOCK_LEN];
                state_to_keystream(&state, &mut keystream);

                v512_i8_xor_inplace(plaintext, &keystream)
            }
        }

        let rem = chunks.into_remainder();
        let rlen = rem.len();

        if rlen > 0 {
            // Last Block
            let mut state = initial_state.clone();

            // 20 rounds (diagonal rounds)
            diagonal_rounds(&mut state);
            add_si512_inplace(&mut state, &mut initial_state);

            // Update Block Counter
            // initial_state[12] = initial_state[12].wrapping_add(1);
            
            if cfg!(target_endian = "little") {
                unsafe {
                    use core::slice;
                    
                    let keystream = slice::from_raw_parts(state.as_ptr() as *const u8, Self::BLOCK_LEN);
                    for i in 0..rlen {
                        rem[i] ^= keystream[i];
                    }
                }
            } else {
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
fn diagonal_rounds(state: &mut [u32; Chacha20::STATE_LEN]) {
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

#[inline]
fn state_to_keystream(state: &[u32; Chacha20::STATE_LEN], keystream: &mut [u8; Chacha20::BLOCK_LEN]) {
    keystream[ 0.. 4].copy_from_slice(&state[0].to_le_bytes());
    keystream[ 4.. 8].copy_from_slice(&state[1].to_le_bytes());
    keystream[ 8..12].copy_from_slice(&state[2].to_le_bytes());
    keystream[12..16].copy_from_slice(&state[3].to_le_bytes());
    keystream[16..20].copy_from_slice(&state[4].to_le_bytes());
    keystream[20..24].copy_from_slice(&state[5].to_le_bytes());
    keystream[24..28].copy_from_slice(&state[6].to_le_bytes());
    keystream[28..32].copy_from_slice(&state[7].to_le_bytes());
    keystream[32..36].copy_from_slice(&state[8].to_le_bytes());
    keystream[36..40].copy_from_slice(&state[9].to_le_bytes());
    keystream[40..44].copy_from_slice(&state[10].to_le_bytes());
    keystream[44..48].copy_from_slice(&state[11].to_le_bytes());
    keystream[48..52].copy_from_slice(&state[12].to_le_bytes());
    keystream[52..56].copy_from_slice(&state[13].to_le_bytes());
    keystream[56..60].copy_from_slice(&state[14].to_le_bytes());
    keystream[60..64].copy_from_slice(&state[15].to_le_bytes());
}


#[test]
fn test_chacha20_qround() {
    // 2.1.1.  Test Vector for the ChaCha Quarter Round
    // https://tools.ietf.org/html/rfc8439#section-2.1.1
    let mut state = [0x11111111u32, 0x01020304, 0x9b8d6f43, 0x01234567];
    quarter_round(&mut state, 0, 1, 2, 3);
    assert_eq!(state, [0xea2a92f4u32, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]);
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
