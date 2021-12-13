/// ChaCha20 for OpenSSH Protocols
#[derive(Clone)]
pub struct Chacha20 {
    state: [u32; 16],
}

impl core::fmt::Debug for Chacha20 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Chacha20").finish()
    }
}

impl Chacha20 {
    // NOTE: OpenSSH 版本的 Chacha20 密码算法支持 128-bit 和 256-bit 的 Key，
    //       但是，在 Chacha20Poly1305 里面，只使用 256-bit 的 Key.
    //       所以，我们不再需要处理 128-bit key 的问题。
    //
    //       https://github.com/openbsd/src/blob/master/usr.bin/ssh/cipher-chachapoly.h#L25
    pub const KEY_LEN: usize = 32;
    pub const BLOCK_LEN: usize = 64;
    pub const NONCE_LEN: usize = 8;

    // INITIAL_STATE
    const K16: [u32; 4] = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574]; // b"expand 16-byte k";
    const K32: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]; // b"expand 32-byte k";

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        let mut state = [0u32; 16];

        // The ChaCha20 state is initialized as follows:
        if key.len() == 16 {
            state[0] = Self::K16[0];
            state[1] = Self::K16[1];
            state[2] = Self::K16[2];
            state[3] = Self::K16[3];
        } else if key.len() == 32 {
            state[0] = Self::K32[0];
            state[1] = Self::K32[1];
            state[2] = Self::K32[2];
            state[3] = Self::K32[3];
        } else {
            unreachable!()
        }

        // A 128-bit or 256-bit key (32 Bytes)
        state[4] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        state[5] = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
        state[6] = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
        state[7] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
        if key.len() == 16 {
            // 128-bits
            state[8] = state[4];
            state[9] = state[5];
            state[10] = state[6];
            state[11] = state[7];
        } else if key.len() == 32 {
            // 256-bits
            state[8] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
            state[9] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
            state[10] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
            state[11] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);
        } else {
            unreachable!()
        }

        Self { state }
    }

    #[inline]
    fn ctr64(&mut self) {
        // Block counter ( 64-bits )
        let lo = self.state[12].to_le_bytes();
        let hi = self.state[13].to_le_bytes();

        let counter = u64::from_le_bytes([lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]])
            .wrapping_add(1)
            .to_le_bytes();
        self.state[12] = u32::from_le_bytes([counter[0], counter[1], counter[2], counter[3]]);
        self.state[13] = u32::from_le_bytes([counter[4], counter[5], counter[6], counter[7]]);
    }

    #[inline]
    fn in_place(&mut self, pkt_seq_num: u32, block_counter: u64, data: &mut [u8]) {
        // assert_eq!(nonce.len(), Self::NONCE_LEN);
        let nonce = (pkt_seq_num as u64).to_be_bytes();
        self.state[14] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        self.state[15] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);

        let counter = block_counter.to_le_bytes();
        self.state[12] = u32::from_le_bytes([counter[0], counter[1], counter[2], counter[3]]);
        self.state[13] = u32::from_le_bytes([counter[4], counter[5], counter[6], counter[7]]);

        let mut chunks = data.chunks_exact_mut(Self::BLOCK_LEN);
        for chunk in &mut chunks {
            let mut state = self.state.clone();

            // 20 rounds (diagonal rounds)
            diagonal_rounds(&mut state);

            for i in 0..16 {
                state[i] = state[i].wrapping_add(self.state[i]);
            }

            let mut keystream = [0u8; Self::BLOCK_LEN];
            state_to_keystream(&state, &mut keystream);

            for i in 0..Self::BLOCK_LEN {
                chunk[i] ^= keystream[i];
            }

            // Block counter
            self.ctr64();
        }

        let rem = chunks.into_remainder();
        let rlen = rem.len();
        if rlen > 0 {
            // Last block
            let mut state = self.state.clone();

            // 20 rounds (diagonal rounds)
            diagonal_rounds(&mut state);

            for i in 0..16 {
                state[i] = state[i].wrapping_add(self.state[i]);
            }

            let mut keystream = [0u8; Self::BLOCK_LEN];
            state_to_keystream(&state, &mut keystream);

            for i in 0..rlen {
                rem[i] ^= keystream[i];
            }

            // Block counter
            self.ctr64();
        }
    }

    pub fn encrypt_slice(
        &mut self,
        pkt_seq_num: u32,
        block_counter: u64,
        plaintext_in_ciphertext_out: &mut [u8],
    ) {
        self.in_place(pkt_seq_num, block_counter, plaintext_in_ciphertext_out)
    }

    pub fn decrypt_slice(
        &mut self,
        pkt_seq_num: u32,
        block_counter: u64,
        ciphertext_out_plaintext_in: &mut [u8],
    ) {
        self.in_place(pkt_seq_num, block_counter, ciphertext_out_plaintext_in)
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

    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);

    state[ai] = a;
    state[bi] = b;
    state[ci] = c;
    state[di] = d;
}

#[inline]
fn diagonal_rounds(state: &mut [u32]) {
    for _ in 0..10 {
        // column rounds
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
}

#[inline]
fn state_to_keystream(state: &[u32; 16], keystream: &mut [u8; Chacha20::BLOCK_LEN]) {
    keystream[0..4].copy_from_slice(&state[0].to_le_bytes());
    keystream[4..8].copy_from_slice(&state[1].to_le_bytes());
    keystream[8..12].copy_from_slice(&state[2].to_le_bytes());
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
