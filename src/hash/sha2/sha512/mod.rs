// FIPS-180-2 compliant SHA-384/512 implementation
// 
// The SHA-512 Secure Hash Standard was published by NIST in 2002.
// http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
use core::convert::TryFrom;


// NOTE:
//      1. AArch64 架构在 ARMv8.4-A 版本里面增加了对 SHA2-512 的支持。
//      2. X86/X86_64 架构的 SHA-NI 目前并不包含 SHA2-512。 
mod generic;
#[cfg(target_arch = "aarch64")]
mod aarch64;


// Round constants
const K64: [u64; 80] = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
];


// SHA-512
const SHA512_INITIAL_STATE: [u64; 8] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
];

// SHA-384
const SHA384_INITIAL_STATE: [u64; 8] = [
    0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
    0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4,
];


#[cfg(target_arch = "aarch64")]
#[inline]
fn transform(state: &mut [u64; 8], block: &[u8]) {
    // NOTE: 等待 Rust 的 `std_detect` 库支持 AArch64 v8.4-A。
    // https://github.com/rust-lang/stdarch/blob/master/crates/std_detect/src/detect/arch/aarch64.rs#L13
    
    generic::transform(state, block)

    // if is_aarch64_feature_detected!("sha512") {
    //     aarch64::transform(state, block)
    // } else {
    //     generic::transform(state, block)
    // }
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
fn transform(state: &mut [u64; 8], block: &[u8]) {
    generic::transform(state, block)
}


/// SHA2-384
pub fn sha384<T: AsRef<[u8]>>(data: T) -> [u8; Sha384::DIGEST_LEN] {
    Sha384::oneshot(data)
}

/// SHA2-512
pub fn sha512<T: AsRef<[u8]>>(data: T) -> [u8; Sha512::DIGEST_LEN] {
    Sha512::oneshot(data)
}


/// SHA2-384
#[derive(Clone)]
pub struct Sha384 {
    inner: Sha512,
}

impl Sha384 {
    pub const BLOCK_LEN: usize  = 128;
    pub const DIGEST_LEN: usize =  48;

    pub fn new() -> Self {
        let inner = Sha512 {
            buffer: [0u8; 128],
            state: SHA384_INITIAL_STATE,
            len: 0,
        };
        Self { inner }
    }
    
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let h = self.inner.finalize();

        let mut output = [0u8; Self::DIGEST_LEN];
        output.copy_from_slice(&h[..Self::DIGEST_LEN]);

        output
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}


/// SHA2-512
#[derive(Clone)]
pub struct Sha512 {
    buffer: [u8; 128],
    state: [u64; 8],
    len: u128,      // in bytes.
}

impl Sha512 {
    pub const BLOCK_LEN: usize  = 128;
    pub const DIGEST_LEN: usize =  64;

    pub fn new() -> Self {
        Self {
            buffer: [0u8; 128],
            state: SHA512_INITIAL_STATE,
            len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut n = self.len % Self::BLOCK_LEN as u128;
        if n != 0 {
            let mut i = 0usize;
            loop {
                if n == 128 || i >= data.len() {
                    break;
                }
                self.buffer[n as usize] = data[i];
                n += 1;
                i += 1;
                self.len += 1;
            }

            if self.len % Self::BLOCK_LEN as u128 != 0 {
                return ();
            } else {
                transform(&mut self.state, &self.buffer);

                let data = &data[i..];
                if data.len() > 0 {
                    return self.update(data);
                }
            }
        }

        if data.len() < 128 {
            self.buffer[..data.len()].copy_from_slice(data);
            self.len += data.len() as u128;
        } else if data.len() == 128 {
            transform(&mut self.state, data);
            self.len += 128;
        } else if data.len() > 128 {
            let blocks = data.len() / 128;
            for i in 0..blocks {
                transform(&mut self.state, &data[i*128..i*128+128]);
                self.len += 128;
            }
            let data = &data[blocks*128..];
            if data.len() > 0 {
                self.buffer[..data.len()].copy_from_slice(data);
                self.len += data.len() as u128;
            }
        } else {
            unreachable!()
        }
    }

    pub fn finalize(mut self) -> [u8; Self::DIGEST_LEN] {
        let len_bits: u128 = self.len * 8;
        let n = usize::try_from(self.len % Self::BLOCK_LEN as u128).unwrap();
        if n == 0 {
            let mut block = [0u8; 128];
            block[0] = 0x80;
            block[112..].copy_from_slice(&len_bits.to_be_bytes());
            transform(&mut self.state, &block);
        } else {
            self.buffer[n] = 0x80;
            for i in n+1..128 {
                self.buffer[i] = 0;
            }
            if 128 - n - 1 >= 16 {
                self.buffer[112..].copy_from_slice(&len_bits.to_be_bytes());
                transform(&mut self.state, &self.buffer);
            } else {
                transform(&mut self.state, &self.buffer);
                let mut block = [0u8; 128];
                block[112..].copy_from_slice(&len_bits.to_be_bytes());
                transform(&mut self.state, &block);
            }
        }

        let mut output = [0u8; Self::DIGEST_LEN];

        output[ 0.. 8].copy_from_slice(&self.state[0].to_be_bytes());
        output[ 8..16].copy_from_slice(&self.state[1].to_be_bytes());
        output[16..24].copy_from_slice(&self.state[2].to_be_bytes());
        output[24..32].copy_from_slice(&self.state[3].to_be_bytes());
        output[32..40].copy_from_slice(&self.state[4].to_be_bytes());
        output[40..48].copy_from_slice(&self.state[5].to_be_bytes());
        output[48..56].copy_from_slice(&self.state[6].to_be_bytes());
        output[56..64].copy_from_slice(&self.state[7].to_be_bytes());

        output
    }
    
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }
}


#[test]
fn test_sha512_one_block_message() {
    let msg = b"abc";
    let digest = [
        221u8, 175, 53, 161, 147, 97, 122, 186, 204, 65, 115, 73, 174, 32, 
        65, 49, 18, 230, 250, 78, 137, 169, 126, 162, 10, 158, 238, 230, 
        75, 85, 211, 154, 33, 146, 153, 42, 39, 79, 193, 168, 54, 186, 60, 
        35, 163, 254, 235, 189, 69, 77, 68, 35, 100, 60, 232, 14, 42, 154, 
        201, 79, 165, 76, 164, 159
    ];
    assert_eq!(&(sha512(&msg[..]))[..], &digest[..]);
}
#[test]
fn test_sha512_multi_block_message() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let digest = [
        32u8, 74, 143, 198, 221, 168, 47, 10, 12, 237, 123, 235, 142, 8, 164, 
        22, 87, 193, 110, 244, 104, 178, 40, 168, 39, 155, 227, 49, 167, 3, 
        195, 53, 150, 253, 21, 193, 59, 27, 7, 249, 170, 29, 59, 234, 87, 
        120, 156, 160, 49, 173, 133, 199, 167, 29, 215, 3, 84, 236, 99, 18, 
        56, 202, 52, 69
    ];
    assert_eq!(&(sha512(&msg[..]))[..], &digest[..]);
}
#[test]
fn test_sha512_long_message() {
    let msg = vec![b'a'; 1000_000];
    let digest = [
        231u8, 24, 72, 61, 12, 231, 105, 100, 78, 46, 66, 199, 188, 21, 180, 
        99, 142, 31, 152, 177, 59, 32, 68, 40, 86, 50, 168, 3, 175, 169, 
        115, 235, 222, 15, 242, 68, 135, 126, 166, 10, 76, 176, 67, 44, 
        229, 119, 195, 27, 235, 0, 156, 92, 44, 73, 170, 46, 78, 173, 178, 
        23, 173, 140, 192, 155
    ];
    assert_eq!(&(sha512(&msg[..]))[..], &digest[..]);
}

#[test]
fn test_sha384_one_block_message() {
    let msg = b"abc";
    let digest = [
        203, 0, 117, 63, 69, 163, 94, 139, 181, 160, 61, 105, 154, 198, 80, 7, 
        39, 44, 50, 171, 14, 222, 209, 99, 26, 139, 96, 90, 67, 255, 91, 237, 
        128, 134, 7, 43, 161, 231, 204, 35, 88, 186, 236, 161, 52, 200, 37, 167
    ];
    assert_eq!(&(sha384(&msg[..]))[..], &digest[..]);
}
#[test]
fn test_sha384_multi_block_message() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let digest = [
        51, 145, 253, 221, 252, 141, 199, 57, 55, 7, 166, 91, 27, 71, 9, 57, 
        124, 248, 177, 209, 98, 175, 5, 171, 254, 143, 69, 13, 229, 243, 107, 
        198, 176, 69, 90, 133, 32, 188, 78, 111, 95, 233, 91, 31, 227, 200, 69, 43
    ];
    assert_eq!(&(sha384(&msg[..]))[..], &digest[..]);
}
#[test]
fn test_sha384_long_message() {
    let msg = vec![b'a'; 1000_000];
    let digest = [
        157, 14, 24, 9, 113, 100, 116, 203, 8, 110, 131, 78, 49, 10, 74, 28, 237, 
        20, 158, 156, 0, 242, 72, 82, 121, 114, 206, 197, 112, 76, 42, 91, 7, 184, 
        179, 220, 56, 236, 196, 235, 174, 151, 221, 216, 127, 61, 137, 133
    ];
    assert_eq!(&(sha384(&msg[..]))[..], &digest[..]);
}