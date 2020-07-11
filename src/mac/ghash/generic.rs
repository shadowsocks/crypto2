use crate::mem::Zeroize;


#[derive(Clone)]
pub struct GHash {
    hh: [u64; Self::BLOCK_LEN],
    hl: [u64; Self::BLOCK_LEN],
    buf: [u8; Self::BLOCK_LEN],
}

impl Zeroize for GHash {
    fn zeroize(&mut self) {
        self.hh.zeroize();
        self.hl.zeroize();
        self.buf.zeroize();
    }
}

impl Drop for GHash {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl GHash {
    pub const KEY_LEN: usize   = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize   = 16;

    
    pub fn new(h: &[u8; Self::BLOCK_LEN]) -> Self {
        // pack h as two 64-bits ints, big-endian
        let mut vh = u64::from_be_bytes([
            h[0], h[1], h[2], h[3],
            h[4], h[5], h[6], h[7],
        ]);
        let mut vl = u64::from_be_bytes([
            h[ 8], h[ 9], h[10], h[11],
            h[12], h[13], h[14], h[15],
        ]);

        let mut hl = [0u64; Self::BLOCK_LEN];
        let mut hh = [0u64; Self::BLOCK_LEN];
        
        // 8 = 1000 corresponds to 1 in GF(2^128)
        hl[8] = vl;
        hh[8] = vh;
        
        let mut i = 4usize;
        while i > 0 {
            // 4, 2, 1
            let t = ( vl & 1 ) * 0xe1000000;
            vl = ( vh << 63 ) | ( vl >> 1 );
            vh = ( vh >> 1 ) ^ (t << 32);

            hl[i] = vl;
            hh[i] = vh;

            i >>= 1;
        }

        i = 2usize;
        while i <= 8 {
            // 2, 4, 8
            vh = hh[i];
            vl = hl[i];
            for j in 1usize..i {
                hh[i + j] = vh ^ hh[j];
                hl[i + j] = vl ^ hl[j];
            }
            i *= 2;
        }

        let buf = [0u8; 16];

        Self { hh, hl, buf }
    }
    
    // Multiplication operation in GF(2^128)
    #[inline]
    fn gf_mul(&mut self, x: &[u8]) {
        // Reduction table
        // 
        // Shoup's method for multiplication use this table with
        //     last4[x] = x times P^128
        // where x and last4[x] are seen as elements of GF(2^128) as in [MGV]
        const LAST4: [u64; 16] = [
            0x0000, 0x1c20, 0x3840, 0x2460,
            0x7080, 0x6ca0, 0x48c0, 0x54e0,
            0xe100, 0xfd20, 0xd940, 0xc560,
            0x9180, 0x8da0, 0xa9c0, 0xb5e0,
        ];

        let hh = &self.hh;
        let hl = &self.hl;

        for i in 0..16 {
            self.buf[i] ^= x[i];
        }
        let x = &mut self.buf;

        let mut lo: u8  = x[15] & 0xf;
        let mut hi: u8  = 0;
        let mut zh: u64 = hh[lo as usize];
        let mut zl: u64 = hl[lo as usize];
        let mut rem: u8 = 0;

        for i in 0..16 {
            lo = x[16 - 1 - i] & 0xf;
            hi = (x[16 - 1 - i] >> 4) & 0xf;

            if i != 0 {
                rem = (zl & 0xf) as u8;
                zl = ( zh << 60 ) | ( zl >> 4 );
                zh = zh >> 4;
                zh ^= LAST4[rem as usize] << 48;
                zh ^= hh[lo as usize];
                zl ^= hl[lo as usize];
            }

            rem = (zl & 0xf) as u8;
            zl = ( zh << 60 ) | ( zl >> 4 );
            zh = zh >> 4;

            zh ^= LAST4[rem as usize] << 48;
            zh ^= hh[hi as usize];
            zl ^= hl[hi as usize];
        }

        let a = zh.to_be_bytes();
        let b = zl.to_be_bytes();

        x[0.. 8].copy_from_slice(&a);
        x[8..16].copy_from_slice(&b);
    }

    pub fn update(&mut self, m: &[u8]) {
        let mlen = m.len();

        if mlen == 0 {
            return ();
        }

        let n = mlen / Self::BLOCK_LEN;
        for i in 0..n {
            let chunk = &m[i * Self::BLOCK_LEN..i * Self::BLOCK_LEN + Self::BLOCK_LEN];
            self.gf_mul(chunk);
        }

        if mlen % Self::BLOCK_LEN != 0 {
            let rem = &m[n * Self::BLOCK_LEN..];
            let rlen = rem.len();

            let mut last_block = [0u8; Self::BLOCK_LEN];
            last_block[..rlen].copy_from_slice(rem);
            self.gf_mul(&last_block);
        }
    }

    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        self.buf
    }
}
