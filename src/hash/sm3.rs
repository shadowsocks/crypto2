// GM/T 0004-2012 SM3密码杂凑算法标准 （中文版本）
// https://sca.gov.cn/sca/xwdt/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
// 
// GM/T 0004-2012 SM3 Cryptographic Hash Algorithm （English Version）
// http://www.gmbz.org.cn/upload/2018-07-24/1532401392982079739.pdf


const INITIAL_STATE: [u32; 8] = [
    0x7380_166f, 0x4914_b2b9, 0x1724_42d7, 0xda8a_0600, 
    0xa96f_30bc, 0x1631_38aa, 0xe38d_ee4d, 0xb0fb_0e4e, 
];


/// GM/T 0004-2012 SM3密码杂凑算法标准
pub fn sm3<T: AsRef<[u8]>>(data: T) -> [u8; Sm3::DIGEST_LEN] {
    Sm3::oneshot(data)
}

/// GM/T 0004-2012 SM3密码杂凑算法标准
#[derive(Clone)]
pub struct Sm3 {
    buffer: [u8; Self::BLOCK_LEN],
    state: [u32; 8],
    len: u64,      // in bytes
    offset: usize,
}

impl Sm3 {
    pub const BLOCK_LEN: usize  = 64;
    pub const DIGEST_LEN: usize = 32;
    

    pub fn new() -> Self {
        Self {
            buffer: [0u8; Self::BLOCK_LEN],
            state: INITIAL_STATE,
            len: 0,
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
            self.len += 1;
        }

        if self.offset == Self::BLOCK_LEN {
            transform(&mut self.state, &self.buffer);
            self.offset = 0;
        }
    }

    pub fn finalize(mut self) -> [u8; Self::DIGEST_LEN] {
        self.buffer[self.offset] = 0x80;
        self.offset += 1;

        for i in self.offset..Self::BLOCK_LEN {
            self.buffer[i] = 0;
        }

        let len_bits = self.len * 8;
        if self.offset <= 56 {
            self.buffer[56..64].copy_from_slice(&len_bits.to_be_bytes());
            transform(&mut self.state, &self.buffer);
        } else {
            transform(&mut self.state, &self.buffer);

            let mut last_block = [0u8; Self::BLOCK_LEN];
            last_block[56..64].copy_from_slice(&len_bits.to_be_bytes());
            transform(&mut self.state, &self.buffer);
        }

        let mut output = [0u8; Self::DIGEST_LEN];

        output[ 0.. 4].copy_from_slice(&self.state[0].to_be_bytes());
        output[ 4.. 8].copy_from_slice(&self.state[1].to_be_bytes());
        output[ 8..12].copy_from_slice(&self.state[2].to_be_bytes());
        output[12..16].copy_from_slice(&self.state[3].to_be_bytes());
        output[16..20].copy_from_slice(&self.state[4].to_be_bytes());
        output[20..24].copy_from_slice(&self.state[5].to_be_bytes());
        output[24..28].copy_from_slice(&self.state[6].to_be_bytes());
        output[28..32].copy_from_slice(&self.state[7].to_be_bytes());

        output
    }
    
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}


#[inline(always)]
fn ff0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn ff1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

#[inline(always)]
fn gg0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn gg1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[inline(always)]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

#[inline(always)]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}


#[inline]
fn transform(state: &mut [u32; 8], block: &[u8; Sm3::BLOCK_LEN]) {
    // get expend
    let mut w: [u32; 68]  = [0; 68];
    let mut w1: [u32; 64] = [0; 64];

    for i in 0..16 {
        let a = block[i * 4 + 0];
        let b = block[i * 4 + 1];
        let c = block[i * 4 + 2];
        let d = block[i * 4 + 3];
        w[i] = u32::from_be_bytes([a, b, c, d]);
    }

    for i in 16..68 {
        w[i] = p1(w[i - 16] 
                ^ w[i - 9] 
                ^ w[i - 3].rotate_left(15))
                ^ w[i - 13].rotate_left(7)
                ^ w[i - 6];
    }

    for i in 0..Sm3::BLOCK_LEN {
        w1[i] = w[i] ^ w[i + 4];
    }

    let mut ra = state[0];
    let mut rb = state[1];
    let mut rc = state[2];
    let mut rd = state[3];
    let mut re = state[4];
    let mut rf = state[5];
    let mut rg = state[6];
    let mut rh = state[7];
    let mut ss1: u32;
    let mut ss2: u32;
    let mut tt1: u32;
    let mut tt2: u32;

    for i in 0..16 {
        ss1 = ra
            .rotate_left(12)
            .wrapping_add(re)
            .wrapping_add(0x79cc_4519u32.rotate_left(i as u32))
            .rotate_left(7);
        ss2 = ss1 ^ ra.rotate_left(12);
        tt1 = ff0(ra, rb, rc)
            .wrapping_add(rd)
            .wrapping_add(ss2)
            .wrapping_add(w1[i]);
        tt2 = gg0(re, rf, rg)
            .wrapping_add(rh)
            .wrapping_add(ss1)
            .wrapping_add(w[i]);
        rd = rc;
        rc = rb.rotate_left(9);
        rb = ra;
        ra = tt1;
        rh = rg;
        rg = rf.rotate_left(19);
        rf = re;
        re = p0(tt2);
    }

    for i in 16..64 {
        ss1 = ra
            .rotate_left(12)
            .wrapping_add(re)
            .wrapping_add(0x7a87_9d8au32.rotate_left(i as u32))
            .rotate_left(7);
        ss2 = ss1 ^ ra.rotate_left(12);
        tt1 = ff1(ra, rb, rc)
            .wrapping_add(rd)
            .wrapping_add(ss2)
            .wrapping_add(w1[i]);
        tt2 = gg1(re, rf, rg)
            .wrapping_add(rh)
            .wrapping_add(ss1)
            .wrapping_add(w[i]);
        rd = rc;
        rc = rb.rotate_left(9);
        rb = ra;
        ra = tt1;
        rh = rg;
        rg = rf.rotate_left(19);
        rf = re;
        re = p0(tt2);
    }

    state[0] ^= ra;
    state[1] ^= rb;
    state[2] ^= rc;
    state[3] ^= rd;
    state[4] ^= re;
    state[5] ^= rf;
    state[6] ^= rg;
    state[7] ^= rh;
}


#[test]
fn test_sm3() {
    // A.1 示例1
    // https://sca.gov.cn/sca/xwdt/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
    let digest = sm3(b"abc");
    
    assert_eq!(&digest[..], &[
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 
        0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2, 
        0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 
        0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0, 
    ]);

    // A.1 示例2
    let digest = sm3(b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
    assert_eq!(&digest[..], &[
        0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 
        0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d, 
        0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 
        0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32, 
    ]);
}
