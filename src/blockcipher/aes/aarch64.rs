#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
use core::mem::transmute;

// The round constant word array.
const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// Forward S-Box
const FORWARD_S_BOX: [u8; 256] = [
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[inline]
fn sub_word(x: u32) -> u32 {
    // SubWord([b0, b1, b2, b3]) = [ SubByte(b0), SubByte(b1), SubByte(b2), SubByte(b3) ]
    let mut bytes = x.to_le_bytes();
    bytes[0] = FORWARD_S_BOX[bytes[0] as usize];
    bytes[1] = FORWARD_S_BOX[bytes[1] as usize];
    bytes[2] = FORWARD_S_BOX[bytes[2] as usize];
    bytes[3] = FORWARD_S_BOX[bytes[3] as usize];
    u32::from_le_bytes(bytes)
}

#[derive(Clone)]
pub struct Aes128 {
    ek: [uint8x16_t; 20],
}

impl core::fmt::Debug for Aes128 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Aes128").finish()
    }
}

impl Aes128 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 16;
    pub const NR: usize = 10;
    const WLEN: usize = (Self::NR + 1) * 4; // 44

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        unsafe {
            let mut ek: [u32; Self::WLEN] = [0u32; Self::WLEN];

            let k1: [u32; 4] = transmute(vld1q_u32(key.as_ptr() as *const u32));
            ek[0] = k1[0];
            ek[1] = k1[1];
            ek[2] = k1[2];
            ek[3] = k1[3];

            ek[4] = ek[0] ^ (sub_word(ek[3]).rotate_left(24) ^ RCON[0]);
            ek[5] = ek[1] ^ ek[4];
            ek[6] = ek[2] ^ ek[5];
            ek[7] = ek[3] ^ ek[6];

            ek[8] = ek[4] ^ (sub_word(ek[7]).rotate_left(24) ^ RCON[1]);
            ek[9] = ek[5] ^ ek[8];
            ek[10] = ek[6] ^ ek[9];
            ek[11] = ek[7] ^ ek[10];

            ek[12] = ek[8] ^ (sub_word(ek[11]).rotate_left(24) ^ RCON[2]);
            ek[13] = ek[9] ^ ek[12];
            ek[14] = ek[10] ^ ek[13];
            ek[15] = ek[11] ^ ek[14];

            ek[16] = ek[12] ^ (sub_word(ek[15]).rotate_left(24) ^ RCON[3]);
            ek[17] = ek[13] ^ ek[16];
            ek[18] = ek[14] ^ ek[17];
            ek[19] = ek[15] ^ ek[18];

            ek[20] = ek[16] ^ (sub_word(ek[19]).rotate_left(24) ^ RCON[4]);
            ek[21] = ek[17] ^ ek[20];
            ek[22] = ek[18] ^ ek[21];
            ek[23] = ek[19] ^ ek[22];

            ek[24] = ek[20] ^ (sub_word(ek[23]).rotate_left(24) ^ RCON[5]);
            ek[25] = ek[21] ^ ek[24];
            ek[26] = ek[22] ^ ek[25];
            ek[27] = ek[23] ^ ek[26];

            ek[28] = ek[24] ^ (sub_word(ek[27]).rotate_left(24) ^ RCON[6]);
            ek[29] = ek[25] ^ ek[28];
            ek[30] = ek[26] ^ ek[29];
            ek[31] = ek[27] ^ ek[30];

            ek[32] = ek[28] ^ (sub_word(ek[31]).rotate_left(24) ^ RCON[7]);
            ek[33] = ek[29] ^ ek[32];
            ek[34] = ek[30] ^ ek[33];
            ek[35] = ek[31] ^ ek[34];

            ek[36] = ek[32] ^ (sub_word(ek[35]).rotate_left(24) ^ RCON[8]);
            ek[37] = ek[33] ^ ek[36];
            ek[38] = ek[34] ^ ek[37];
            ek[39] = ek[35] ^ ek[38];

            ek[40] = ek[36] ^ (sub_word(ek[39]).rotate_left(24) ^ RCON[9]);
            ek[41] = ek[37] ^ ek[40];
            ek[42] = ek[38] ^ ek[41];
            ek[43] = ek[39] ^ ek[42];

            let ptr = ek.as_ptr();
            let mut k = [vdupq_n_u8(0); 20];

            k[0] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(0)));
            k[1] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(4)));
            k[2] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(8)));
            k[3] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(12)));
            k[4] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(16)));
            k[5] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(20)));
            k[6] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(24)));
            k[7] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(28)));
            k[8] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(32)));
            k[9] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(36)));
            k[10] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(40)));

            k[11] = vaesimcq_u8(k[9]);
            k[12] = vaesimcq_u8(k[8]);
            k[13] = vaesimcq_u8(k[7]);
            k[14] = vaesimcq_u8(k[6]);
            k[15] = vaesimcq_u8(k[5]);
            k[16] = vaesimcq_u8(k[4]);
            k[17] = vaesimcq_u8(k[3]);
            k[18] = vaesimcq_u8(k[2]);
            k[19] = vaesimcq_u8(k[1]);

            Self { ek: k }
        }
    }

    pub fn encrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        unsafe {
            let mut state: uint8x16_t = vld1q_u8(block.as_ptr());

            state = vaeseq_u8(state, self.ek[0]);

            state = vaeseq_u8(vaesmcq_u8(state), self.ek[1]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[2]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[3]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[4]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[5]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[6]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[7]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[8]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[9]);

            state = veorq_u8(state, self.ek[10]);
            // vst1q_u8
            let dst = block.as_mut_ptr() as *mut uint8x16_t;
            *dst = state;
        }
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        unsafe {
            let mut state: uint8x16_t = vld1q_u8(block.as_ptr());

            state = vaesimcq_u8(vaesdq_u8(state, self.ek[10]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[11]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[12]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[13]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[14]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[15]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[16]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[17]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[18]));

            // Last
            state = vaesdq_u8(state, self.ek[19]);
            state = veorq_u8(state, self.ek[0]);

            // vst1q_u8
            let dst = block.as_mut_ptr() as *mut uint8x16_t;
            *dst = state;
        }
    }
}

#[derive(Clone)]
pub struct Aes192 {
    ek: [uint8x16_t; 24],
}

impl core::fmt::Debug for Aes192 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Aes192").finish()
    }
}

impl Aes192 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 24;
    pub const NR: usize = 12;
    const WLEN: usize = (Self::NR + 1) * 4; // 52

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        unsafe {
            let k1: [u32; 4] = transmute(vld1q_u32(key.as_ptr() as *const u32));
            let mut ek: [u32; Self::WLEN] = [0u32; Self::WLEN];

            ek[0] = k1[0];
            ek[1] = k1[1];
            ek[2] = k1[2];
            ek[3] = k1[3];
            ek[4] = *((key.as_ptr() as *const u32).add(4));
            ek[5] = *((key.as_ptr() as *const u32).add(5));

            ek[6] = ek[0] ^ (sub_word(ek[5]).rotate_left(24) ^ RCON[0]);
            ek[7] = ek[1] ^ ek[6];
            ek[8] = ek[2] ^ ek[7];
            ek[9] = ek[3] ^ ek[8];
            ek[10] = ek[4] ^ ek[9];
            ek[11] = ek[5] ^ ek[10];

            ek[12] = ek[6] ^ (sub_word(ek[11]).rotate_left(24) ^ RCON[1]);
            ek[13] = ek[7] ^ ek[12];
            ek[14] = ek[8] ^ ek[13];
            ek[15] = ek[9] ^ ek[14];
            ek[16] = ek[10] ^ ek[15];
            ek[17] = ek[11] ^ ek[16];

            ek[18] = ek[12] ^ (sub_word(ek[17]).rotate_left(24) ^ RCON[2]);
            ek[19] = ek[13] ^ ek[18];
            ek[20] = ek[14] ^ ek[19];
            ek[21] = ek[15] ^ ek[20];
            ek[22] = ek[16] ^ ek[21];
            ek[23] = ek[17] ^ ek[22];

            ek[24] = ek[18] ^ (sub_word(ek[23]).rotate_left(24) ^ RCON[3]);
            ek[25] = ek[19] ^ ek[24];
            ek[26] = ek[20] ^ ek[25];
            ek[27] = ek[21] ^ ek[26];
            ek[28] = ek[22] ^ ek[27];
            ek[29] = ek[23] ^ ek[28];

            ek[30] = ek[24] ^ (sub_word(ek[29]).rotate_left(24) ^ RCON[4]);
            ek[31] = ek[25] ^ ek[30];
            ek[32] = ek[26] ^ ek[31];
            ek[33] = ek[27] ^ ek[32];
            ek[34] = ek[28] ^ ek[33];
            ek[35] = ek[29] ^ ek[34];

            ek[36] = ek[30] ^ (sub_word(ek[35]).rotate_left(24) ^ RCON[5]);
            ek[37] = ek[31] ^ ek[36];
            ek[38] = ek[32] ^ ek[37];
            ek[39] = ek[33] ^ ek[38];
            ek[40] = ek[34] ^ ek[39];
            ek[41] = ek[35] ^ ek[40];

            ek[42] = ek[36] ^ (sub_word(ek[41]).rotate_left(24) ^ RCON[6]);
            ek[43] = ek[37] ^ ek[42];
            ek[44] = ek[38] ^ ek[43];
            ek[45] = ek[39] ^ ek[44];
            ek[46] = ek[40] ^ ek[45];
            ek[47] = ek[41] ^ ek[46];

            ek[48] = ek[42] ^ (sub_word(ek[47]).rotate_left(24) ^ RCON[7]);
            ek[49] = ek[43] ^ ek[48];
            ek[50] = ek[44] ^ ek[49];
            ek[51] = ek[45] ^ ek[50];

            let mut k = [vdupq_n_u8(0); 24];
            let ptr = ek.as_ptr();

            k[0] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(0)));
            k[1] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(4)));
            k[2] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(8)));
            k[3] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(12)));
            k[4] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(16)));
            k[5] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(20)));
            k[6] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(24)));
            k[7] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(28)));
            k[8] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(32)));
            k[9] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(36)));
            k[10] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(40)));
            k[11] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(44)));
            k[12] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(48)));

            k[13] = vaesimcq_u8(k[11]);
            k[14] = vaesimcq_u8(k[10]);
            k[15] = vaesimcq_u8(k[9]);
            k[16] = vaesimcq_u8(k[8]);
            k[17] = vaesimcq_u8(k[7]);
            k[18] = vaesimcq_u8(k[6]);
            k[19] = vaesimcq_u8(k[5]);
            k[20] = vaesimcq_u8(k[4]);
            k[21] = vaesimcq_u8(k[3]);
            k[22] = vaesimcq_u8(k[2]);
            k[23] = vaesimcq_u8(k[1]);

            Self { ek: k }
        }
    }

    pub fn encrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        unsafe {
            let mut state: uint8x16_t = vld1q_u8(block.as_ptr());

            state = vaeseq_u8(state, self.ek[0]);

            state = vaeseq_u8(vaesmcq_u8(state), self.ek[1]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[2]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[3]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[4]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[5]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[6]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[7]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[8]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[9]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[10]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[11]);

            state = veorq_u8(state, self.ek[12]);
            // vst1q_u8
            let dst = block.as_mut_ptr() as *mut uint8x16_t;
            *dst = state;
        }
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        unsafe {
            let mut state: uint8x16_t = vld1q_u8(block.as_ptr());

            state = vaesimcq_u8(vaesdq_u8(state, self.ek[12]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[13]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[14]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[15]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[16]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[17]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[18]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[19]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[20]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[21]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[22]));

            // Last
            state = vaesdq_u8(state, self.ek[23]);
            state = veorq_u8(state, self.ek[0]);

            // vst1q_u8
            let dst = block.as_mut_ptr() as *mut uint8x16_t;
            *dst = state;
        }
    }
}

#[derive(Clone)]
pub struct Aes256 {
    ek: [uint8x16_t; 28],
}

impl core::fmt::Debug for Aes256 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Aes256").finish()
    }
}

impl Aes256 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 32;
    pub const NR: usize = 14;
    const WLEN: usize = (Self::NR + 1) * 4; // 60

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        unsafe {
            let k1: [u32; 4] = transmute(vld1q_u32(key.as_ptr().add(0) as *const u32));
            let k2: [u32; 4] = transmute(vld1q_u32(key.as_ptr().add(16) as *const u32));

            let mut ek: [u32; Self::WLEN] = [0u32; Self::WLEN];
            ek[0] = k1[0];
            ek[1] = k1[1];
            ek[2] = k1[2];
            ek[3] = k1[3];
            ek[4] = k2[0];
            ek[5] = k2[1];
            ek[6] = k2[2];
            ek[7] = k2[3];

            ek[8] = ek[0] ^ (sub_word(ek[7]).rotate_left(24) ^ RCON[0]);
            ek[9] = ek[1] ^ ek[8];
            ek[10] = ek[2] ^ ek[9];
            ek[11] = ek[3] ^ ek[10];
            ek[12] = ek[4] ^ sub_word(ek[11]);
            ek[13] = ek[5] ^ ek[12];
            ek[14] = ek[6] ^ ek[13];
            ek[15] = ek[7] ^ ek[14];

            ek[16] = ek[8] ^ (sub_word(ek[15]).rotate_left(24) ^ RCON[1]);
            ek[17] = ek[9] ^ ek[16];
            ek[18] = ek[10] ^ ek[17];
            ek[19] = ek[11] ^ ek[18];
            ek[20] = ek[12] ^ sub_word(ek[19]);
            ek[21] = ek[13] ^ ek[20];
            ek[22] = ek[14] ^ ek[21];
            ek[23] = ek[15] ^ ek[22];

            ek[24] = ek[16] ^ (sub_word(ek[23]).rotate_left(24) ^ RCON[2]);
            ek[25] = ek[17] ^ ek[24];
            ek[26] = ek[18] ^ ek[25];
            ek[27] = ek[19] ^ ek[26];
            ek[28] = ek[20] ^ sub_word(ek[27]);
            ek[29] = ek[21] ^ ek[28];
            ek[30] = ek[22] ^ ek[29];
            ek[31] = ek[23] ^ ek[30];

            ek[32] = ek[24] ^ (sub_word(ek[31]).rotate_left(24) ^ RCON[3]);
            ek[33] = ek[25] ^ ek[32];
            ek[34] = ek[26] ^ ek[33];
            ek[35] = ek[27] ^ ek[34];
            ek[36] = ek[28] ^ sub_word(ek[35]);
            ek[37] = ek[29] ^ ek[36];
            ek[38] = ek[30] ^ ek[37];
            ek[39] = ek[31] ^ ek[38];

            ek[40] = ek[32] ^ (sub_word(ek[39]).rotate_left(24) ^ RCON[4]);
            ek[41] = ek[33] ^ ek[40];
            ek[42] = ek[34] ^ ek[41];
            ek[43] = ek[35] ^ ek[42];
            ek[44] = ek[36] ^ sub_word(ek[43]);
            ek[45] = ek[37] ^ ek[44];
            ek[46] = ek[38] ^ ek[45];
            ek[47] = ek[39] ^ ek[46];

            ek[48] = ek[40] ^ (sub_word(ek[47]).rotate_left(24) ^ RCON[5]);
            ek[49] = ek[41] ^ ek[48];
            ek[50] = ek[42] ^ ek[49];
            ek[51] = ek[43] ^ ek[50];
            ek[52] = ek[44] ^ sub_word(ek[51]);
            ek[53] = ek[45] ^ ek[52];
            ek[54] = ek[46] ^ ek[53];
            ek[55] = ek[47] ^ ek[54];

            ek[56] = ek[48] ^ (sub_word(ek[55]).rotate_left(24) ^ RCON[6]);
            ek[57] = ek[49] ^ ek[56];
            ek[58] = ek[50] ^ ek[57];
            ek[59] = ek[51] ^ ek[58];

            let mut k = [vdupq_n_u8(0); 28];
            let ptr = ek.as_ptr();

            k[0] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(0)));
            k[1] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(4)));
            k[2] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(8)));
            k[3] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(12)));
            k[4] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(16)));
            k[5] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(20)));
            k[6] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(24)));
            k[7] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(28)));
            k[8] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(32)));
            k[9] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(36)));
            k[10] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(40)));
            k[11] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(44)));
            k[12] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(48)));
            k[13] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(52)));
            k[14] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(56)));

            k[15] = vaesimcq_u8(k[13]);
            k[16] = vaesimcq_u8(k[12]);
            k[17] = vaesimcq_u8(k[11]);
            k[18] = vaesimcq_u8(k[10]);
            k[19] = vaesimcq_u8(k[9]);
            k[20] = vaesimcq_u8(k[8]);
            k[21] = vaesimcq_u8(k[7]);
            k[22] = vaesimcq_u8(k[6]);
            k[23] = vaesimcq_u8(k[5]);
            k[24] = vaesimcq_u8(k[4]);
            k[25] = vaesimcq_u8(k[3]);
            k[26] = vaesimcq_u8(k[2]);
            k[27] = vaesimcq_u8(k[1]);

            Self { ek: k }
        }
    }

    pub fn encrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        unsafe {
            let mut state: uint8x16_t = vld1q_u8(block.as_ptr());

            state = vaeseq_u8(state, self.ek[0]);

            state = vaeseq_u8(vaesmcq_u8(state), self.ek[1]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[2]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[3]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[4]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[5]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[6]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[7]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[8]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[9]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[10]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[11]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[12]);
            state = vaeseq_u8(vaesmcq_u8(state), self.ek[13]);

            state = veorq_u8(state, self.ek[14]);
            // vst1q_u8
            let dst = block.as_mut_ptr() as *mut uint8x16_t;
            *dst = state;
        }
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        unsafe {
            let mut state: uint8x16_t = vld1q_u8(block.as_ptr());

            state = vaesimcq_u8(vaesdq_u8(state, self.ek[14]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[15]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[16]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[17]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[18]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[19]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[20]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[21]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[22]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[23]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[24]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[25]));
            state = vaesimcq_u8(vaesdq_u8(state, self.ek[26]));

            // Last
            state = vaesdq_u8(state, self.ek[27]);
            state = veorq_u8(state, self.ek[0]);

            // vst1q_u8
            let dst = block.as_mut_ptr() as *mut uint8x16_t;
            *dst = state;
        }
    }
}
