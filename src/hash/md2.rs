// The MD2 Message-Digest Algorithm
// https://tools.ietf.org/html/rfc1319


// The S-table's values are derived from Pi
const S: [u8; 256] = [
    0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13, 
    0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA, 
    0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12, 
    0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A, 
    0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21, 
    0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03, 
    0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6, 
    0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1, 
    0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02, 
    0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F, 
    0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26, 
    0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52, 
    0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A, 
    0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39, 
    0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A, 
    0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14, 
];

#[inline]
fn transform(state_and_checksum: &mut [u8; 64], block: &[u8]) {
    debug_assert_eq!(state_and_checksum.len(), 64);
    debug_assert_eq!(block.len(), Md2::BLOCK_LEN);
    
    for j in 0..16 {
        state_and_checksum[16 + j] = block[j];
        state_and_checksum[32 + j] = state_and_checksum[16 + j] ^ state_and_checksum[j];
    }

    let mut t = 0u8;
    for j in 0u8..18 {
        for k in 0..48 {
            state_and_checksum[k] ^= S[t as usize];
            t = state_and_checksum[k];
        }
        t = t.wrapping_add(j);
    }

    t = state_and_checksum[48 + 15];
    for j in 0..16 {
        state_and_checksum[48 + j] ^= S[(block[j] ^ t) as usize];
        t = state_and_checksum[48 + j];
    }
}


fn last_block(data: &[u8]) -> [u8; Md2::BLOCK_LEN] {
    debug_assert!(data.len() < Md2::BLOCK_LEN);

    let mut block = [0u8; Md2::BLOCK_LEN];
    block[..data.len()].copy_from_slice(data);

    let pad_byte = (Md2::BLOCK_LEN - data.len()) as u8;
    for byte in &mut block[data.len()..].iter_mut() {
        *byte = pad_byte;
    }

    block
}

pub fn md2<T: AsRef<[u8]>>(data: T) -> [u8; Md2::DIGEST_LEN] {
    Md2::oneshot(data)
}


#[derive(Clone)]
pub struct Md2 {
    buffer: [u8; Self::BLOCK_LEN],
    state: [u8; 64],
    offset: usize,
}

impl Md2 {
    pub const BLOCK_LEN: usize  = 16;
    pub const DIGEST_LEN: usize = 16;

    pub fn new() -> Self {
        Self {
            buffer: [0u8; Self::BLOCK_LEN],
            state: [0u8; 64],
            // len: 0usize,
            offset: 0usize,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        for i in 0..data.len() {
            if self.offset == Self::BLOCK_LEN {
                transform(&mut self.state, &self.buffer);
                self.offset = 0;
            }

            self.buffer[self.offset] = data[i];
            self.offset += 1;
        }

        if self.offset == Self::BLOCK_LEN {
            transform(&mut self.state, &self.buffer);
            self.offset = 0;
        }
    }

    pub fn finalize(mut self) -> [u8; Self::DIGEST_LEN] {
        let data = &self.buffer[..self.offset];

        let block = last_block(data);
        transform(&mut self.state, &block);

        let mut block = [0u8; 16];
        block.copy_from_slice(&self.state[48..]);
        transform(&mut self.state, &block);

        let mut output = [0u8; Self::DIGEST_LEN];
        output.copy_from_slice(&self.state[..Self::DIGEST_LEN]);
        output
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}


#[test]
fn test_md2() {
    // A.5 Test suite
    // https://tools.ietf.org/html/rfc1319#appendix-A.5
    assert_eq!(&md2(""),
        &hex::decode("8350e5a3e24c153df2275c9f80692773").unwrap()[..]);
    assert_eq!(&md2("a"),
        &hex::decode("32ec01ec4a6dac72c0ab96fb34c0b5d1").unwrap()[..]);
    assert_eq!(&md2("abc"),
        &hex::decode("da853b0d3f88d99b30283a69e6ded6bb").unwrap()[..]);
    assert_eq!(&md2("message digest"),
        &hex::decode("ab4f496bfb2a530b219ff33031fe06b0").unwrap()[..]);
    assert_eq!(&md2("abcdefghijklmnopqrstuvwxyz"),
        &hex::decode("4e8ddff3650292ab5a4108c3aa47940b").unwrap()[..]);
    assert_eq!(&md2("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
        &hex::decode("da33def2a42df13975352846c30338cd").unwrap()[..]);
    assert_eq!(&md2("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
        &hex::decode("d5976f79d83d3a0dc9806c3c66f3efd8").unwrap()[..]);
}
