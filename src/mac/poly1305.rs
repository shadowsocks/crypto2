// 2.5.  The Poly1305 Algorithm
// https://tools.ietf.org/html/rfc8439#section-2.5
// 
//    Poly1305 is a one-time authenticator designed by D. J. Bernstein.
//    Poly1305 takes a 32-byte one-time key and a message and produces a
//    16-byte tag.  This tag is used to authenticate the message.
// 
// The Poly1305-AES message-authenticationcode
// http://cr.yp.to/mac/poly1305-20050329.pdf
// 
// TODO: 
//      `r` 和 `s` 里面用到的 fixed-size bignum 有时间重新写。
// 
// 参考 bigint: 
//      https://github.com/sorpaas/etcommon-rs/blob/master/bigint/src/uint/mod.rs
// 


// 2.5.1.  The Poly1305 Algorithms in Pseudocode
// https://tools.ietf.org/html/rfc8439#section-2.5.1
#[derive(Clone)]
pub struct Poly1305 {
    r        : [u32; 5], // r: le_bytes_to_num(key[0..15])
    h        : [u32; 5],
    pad      : [u32; 4], // s: le_bytes_to_num(key[16..31])
}

impl core::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Poly1305").finish()
    }
}

impl Poly1305 {
    pub const KEY_LEN: usize   = 32;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize   = 16;

    
    pub fn new(key: &[u8]) -> Self {
        // A 256-bit one-time key
        debug_assert!(key.len() >= Self::KEY_LEN);

        let h       = [0u32; 5];
        let mut r   = [0u32; 5];
        let mut pad = [0u32; 4];

        // r &= 0xffffffc0ffffffc0ffffffc0fffffff
        r[0] =  u32::from_le_bytes([key[ 0], key[ 1], key[ 2], key[ 3]])       & 0x3ffffff;
        r[1] = (u32::from_le_bytes([key[ 3], key[ 4], key[ 5], key[ 6]]) >> 2) & 0x3ffff03;
        r[2] = (u32::from_le_bytes([key[ 6], key[ 7], key[ 8], key[ 9]]) >> 4) & 0x3ffc0ff;
        r[3] = (u32::from_le_bytes([key[ 9], key[10], key[11], key[12]]) >> 6) & 0x3f03fff;
        r[4] = (u32::from_le_bytes([key[12], key[13], key[14], key[15]]) >> 8) & 0x00fffff;

        // save pad for later
        pad[0] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        pad[1] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        pad[2] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        pad[3] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);

        Self { r, h, pad, }
    }

    #[inline]
    fn block(&mut self, m: &[u8], hibit: u32) {
        debug_assert_eq!(m.len(), Self::BLOCK_LEN);
        
        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        // h += m
        h0 += (u32::from_le_bytes([m[ 0], m[ 1], m[ 2], m[ 3]])     ) & 0x3ffffff;
        h1 += (u32::from_le_bytes([m[ 3], m[ 4], m[ 5], m[ 6]]) >> 2) & 0x3ffffff;
        h2 += (u32::from_le_bytes([m[ 6], m[ 7], m[ 8], m[ 9]]) >> 4) & 0x3ffffff;
        h3 += (u32::from_le_bytes([m[ 9], m[10], m[11], m[12]]) >> 6) & 0x3ffffff;
        h4 += (u32::from_le_bytes([m[12], m[13], m[14], m[15]]) >> 8) | hibit;

        // h *= r
        let     d0 = (h0 as u64 * r0 as u64) 
                   + (h1 as u64 * s4 as u64) 
                   + (h2 as u64 * s3 as u64) 
                   + (h3 as u64 * s2 as u64) 
                   + (h4 as u64 * s1 as u64);
        let mut d1 = (h0 as u64 * r1 as u64) 
                   + (h1 as u64 * r0 as u64) 
                   + (h2 as u64 * s4 as u64) 
                   + (h3 as u64 * s3 as u64) 
                   + (h4 as u64 * s2 as u64);
        let mut d2 = (h0 as u64 * r2 as u64) 
                   + (h1 as u64 * r1 as u64) 
                   + (h2 as u64 * r0 as u64) 
                   + (h3 as u64 * s4 as u64) 
                   + (h4 as u64 * s3 as u64);
        let mut d3 = (h0 as u64 * r3 as u64) 
                   + (h1 as u64 * r2 as u64) 
                   + (h2 as u64 * r1 as u64) 
                   + (h3 as u64 * r0 as u64) 
                   + (h4 as u64 * s4 as u64);
        let mut d4 = (h0 as u64 * r4 as u64) 
                   + (h1 as u64 * r3 as u64) 
                   + (h2 as u64 * r2 as u64) 
                   + (h3 as u64 * r1 as u64) 
                   + (h4 as u64 * r0 as u64);

        // (partial) h %= p
        let mut c : u32;
                        c = (d0 >> 26) as u32; h0 = d0 as u32 & 0x3ffffff;
        d1 += c as u64; c = (d1 >> 26) as u32; h1 = d1 as u32 & 0x3ffffff;
        d2 += c as u64; c = (d2 >> 26) as u32; h2 = d2 as u32 & 0x3ffffff;
        d3 += c as u64; c = (d3 >> 26) as u32; h3 = d3 as u32 & 0x3ffffff;
        d4 += c as u64; c = (d4 >> 26) as u32; h4 = d4 as u32 & 0x3ffffff;
        h0 += c * 5;    c = h0 >> 26; h0 = h0 & 0x3ffffff;
        h1 += c;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
        self.h[4] = h4;
    }

    #[cfg(test)]
    pub fn update2(&mut self, m: &[u8]) {
        let chunks = m.chunks_exact(Self::BLOCK_LEN);

        let rem  = chunks.remainder();
        let rlen = rem.len();

        for chunk in chunks {
            self.block(chunk, 1 << 24);
        }

        if rlen > 0 {
            let mut padding_block = [0u8; Self::BLOCK_LEN];
            padding_block[..rlen].copy_from_slice(rem);
            padding_block[rlen] = 1;

            self.block(&padding_block, 0);
        }
    }

    pub fn update(&mut self, m: &[u8]) {
        let chunks = m.chunks_exact(Self::BLOCK_LEN);

        let rem  = chunks.remainder();
        let rlen = rem.len();

        for chunk in chunks {
            self.block(chunk, 1 << 24);
        }

        if rlen > 0 {
            let mut padding_block = [0u8; Self::BLOCK_LEN];
            padding_block[..rlen].copy_from_slice(rem);
            self.block(&padding_block, 1 << 24);
        }
    }

    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        // fully carry h
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c : u32;
                     c = h1 >> 26; h1 = h1 & 0x3ffffff;
        h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
        h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
        h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
        h1 +=     c;

        // compute h + -p
        let mut g0 = h0.wrapping_add(5); c = g0 >> 26; g0 &= 0x3ffffff;
        let mut g1 = h1.wrapping_add(c); c = g1 >> 26; g1 &= 0x3ffffff;
        let mut g2 = h2.wrapping_add(c); c = g2 >> 26; g2 &= 0x3ffffff;
        let mut g3 = h3.wrapping_add(c); c = g3 >> 26; g3 &= 0x3ffffff;
        let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // select h if h < p, or h + -p if h >= p
        let mut mask = (g4 >> (32 - 1)).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // h = h % (2^128)
        h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
        h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
        h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
        h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

        // h = mac = (h + pad) % (2^128)
        let mut f : u64;
        f = h0 as u64 + self.pad[0] as u64            ; h0 = f as u32;
        f = h1 as u64 + self.pad[1] as u64 + (f >> 32); h1 = f as u32;
        f = h2 as u64 + self.pad[2] as u64 + (f >> 32); h2 = f as u32;
        f = h3 as u64 + self.pad[3] as u64 + (f >> 32); h3 = f as u32;

        // The output is a 128-bit tag.
        let mut tag = [0u8; Self::TAG_LEN];
        tag[ 0.. 4].copy_from_slice(&h0.to_le_bytes());
        tag[ 4.. 8].copy_from_slice(&h1.to_le_bytes());
        tag[ 8..12].copy_from_slice(&h2.to_le_bytes());
        tag[12..16].copy_from_slice(&h3.to_le_bytes());

        tag
    }
}


#[test]
fn test_poly1305_donna() {
    // https://github.com/floodyberry/poly1305-donna/blob/master/example-poly1305.c
    let expected: [u8; Poly1305::TAG_LEN] = [
        0xdd, 0xb9, 0xda, 0x7d, 0xdd, 0x5e, 0x52, 0x79, 
        0x27, 0x30, 0xed, 0x5c, 0xda, 0x5f, 0x90, 0xa4, 
    ];
    let mut key = [0u8; Poly1305::KEY_LEN];
    let mut msg = [0u8; 73];
    
    for i in 0..key.len() {
        key[i] = i as u8 + 221;
    }
    for i in 0..msg.len() {
        msg[i] = i as u8 + 121;
    }

    let mut poly1305 = Poly1305::new(&key);
    poly1305.update2(&msg);

    assert_eq!(poly1305.finalize(), expected);
}

#[test]
fn test_poly1305() {
    // 2.5.2.  Poly1305 Example and Test Vector
    // https://tools.ietf.org/html/rfc8439#section-2.5.2
    let key = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8, 
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    ];
    let message = [
        0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f, 
        0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f, 
        0x75, 0x70, 
    ];
    let expected_tag = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9, 
    ];

    let mut poly1305 = Poly1305::new(&key);
    poly1305.update2(&message);
    assert_eq!(&poly1305.finalize(), &expected_tag);
}


