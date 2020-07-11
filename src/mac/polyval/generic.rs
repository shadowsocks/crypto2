use crate::mem::Zeroize;


// Carry-less Multiplication
#[inline]
fn cl_mul(a: u64, b: u64, dst: &mut [u64; 2]) {
    dst[0] = 0;
    dst[1] = 0;

    for i in 0u64..64 {
        if (b & (1u64 << i)) != 0 {
            dst[1] ^= a;
        }

        // Shift the result
        dst[0] >>= 1;

        if (dst[1] & (1u64 << 0)) != 0 {
            dst[0] ^= 1u64 << 63;
        }

        dst[1] >>= 1;
    }
}


#[derive(Clone)]
pub struct Polyval {
    key: [u8; Self::KEY_LEN],
    h: [u8; Self::BLOCK_LEN],
}

impl Zeroize for Polyval {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.h.zeroize();
    }
}

impl Drop for Polyval {
    fn drop(&mut self) {
        self.zeroize();
    }
}


impl Polyval {
    pub const KEY_LEN: usize   = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize   = 16;

    
    pub fn new(k: &[u8]) -> Self {
        assert_eq!(k.len(), Self::KEY_LEN);

        let h = [0u8; Self::TAG_LEN];

        let mut key = [0u8; Self::KEY_LEN];
        key.copy_from_slice(&k[..Self::KEY_LEN]);

        Self { key, h  }
    }

    #[inline]
    fn gf_mul(&mut self) {
        // a: h
        // b: key
        let a = [
            u64::from_le_bytes([
                self.h[0], self.h[1], self.h[2], self.h[3],
                self.h[4], self.h[5], self.h[6], self.h[7],
            ]),
            u64::from_le_bytes([
                self.h[ 8], self.h[ 9], self.h[10], self.h[11],
                self.h[12], self.h[13], self.h[14], self.h[15],
            ]),
        ];

        let b = [
            u64::from_le_bytes([
                self.key[0], self.key[1], self.key[2], self.key[3],
                self.key[4], self.key[5], self.key[6], self.key[7],
            ]),
            u64::from_le_bytes([
                self.key[ 8], self.key[ 9], self.key[10], self.key[11],
                self.key[12], self.key[13], self.key[14], self.key[15],
            ]),
        ];

        let mut tmp1 = [0u64; 2];
        let mut tmp2 = [0u64; 2];
        let mut tmp3 = [0u64; 2];
        let mut tmp4 = [0u64; 2];

        cl_mul(a[0], b[0], &mut tmp1); // 0x00
        cl_mul(a[1], b[0], &mut tmp2); // 0x01
        cl_mul(a[0], b[1], &mut tmp3); // 0x10
        cl_mul(a[1], b[1], &mut tmp4); // 0x11

        tmp2[0] ^= tmp3[0];
        tmp2[1] ^= tmp3[1];

        tmp3[0] = 0;
        tmp3[1] = tmp2[0];
        
        tmp2[0] = tmp2[1];
        tmp2[1] = 0;
        
        tmp1[0] ^= tmp3[0];
        tmp1[1] ^= tmp3[1];
        
        tmp4[0] ^= tmp2[0];
        tmp4[1] ^= tmp2[1];
        
        const XMMMASK: [u64; 2] = [0x1u64, 0xc200000000000000];

        cl_mul(XMMMASK[1], tmp1[0], &mut tmp2); // 0x01

        unsafe {
            let tmp33: &mut [u32; 4] = core::mem::transmute::<&mut [u64; 2], &mut [u32; 4]>(&mut tmp3);
            let tmp11: &mut [u32; 4] = core::mem::transmute::<&mut [u64; 2], &mut [u32; 4]>(&mut tmp1);

            tmp33[0] = tmp11[2];
            tmp33[1] = tmp11[3];
            tmp33[2] = tmp11[0];
            tmp33[3] = tmp11[1];
        }
        
        tmp1[0] = tmp2[0] ^ tmp3[0];
        tmp1[1] = tmp2[1] ^ tmp3[1];

        cl_mul(XMMMASK[1], tmp1[0], &mut tmp2); // 0x01

        unsafe {
            let tmp33: &mut [u32; 4] = core::mem::transmute::<&mut [u64; 2], &mut [u32; 4]>(&mut tmp3);
            let tmp11: &mut [u32; 4] = core::mem::transmute::<&mut [u64; 2], &mut [u32; 4]>(&mut tmp1);

            tmp33[0] = tmp11[2];
            tmp33[1] = tmp11[3];
            tmp33[2] = tmp11[0];
            tmp33[3] = tmp11[1];
        }

        tmp1[0] = tmp2[0] ^ tmp3[0];
        tmp1[1] = tmp2[1] ^ tmp3[1];
        
        tmp4[0] ^= tmp1[0];
        tmp4[1] ^= tmp1[1];

        self.h[0.. 8].copy_from_slice(&tmp4[0].to_le_bytes());
        self.h[8..16].copy_from_slice(&tmp4[1].to_le_bytes());
    }
    
    pub fn update(&mut self, m: &[u8]) {
        for chunk in m.chunks(Self::BLOCK_LEN) {
            for i in 0..chunk.len() {
                self.h[i] ^= chunk[i];
            }
            self.gf_mul();
        }
    }

    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        self.h
    }
}
