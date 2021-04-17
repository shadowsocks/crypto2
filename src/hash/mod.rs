mod md2;
mod md4;
mod md5;
mod sm3;
mod sha1;
mod sha2;
// TODO: 暂未实现
mod sha3;

pub use self::md2::*;
pub use self::md4::*;
pub use self::md5::*;
pub use self::sm3::*;
pub use self::sha1::*;
pub use self::sha2::*;
pub use self::sha3::*;


// const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";
// #[allow(dead_code)]
// const HEX_CHARS_UPPER: &[u8; 16] = b"0123456789ABCDEF";

// #[inline]
// #[must_use]
// fn byte2hex(byte: u8, table: &[u8; 16]) -> (u8, u8) {
//     let high = table[((byte & 0xf0) >> 4) as usize];
//     let low = table[(byte & 0x0f) as usize];

//     (high, low)
// }


// pub trait Digest: Clone + Copy + AsRef<[u8]> + AsMut<[u8]> + Sized {

// }

// impl Digest for [u8; 16] { }
// impl Digest for [u8; 20] { }
// impl Digest for [u8; 28] { }
// impl Digest for [u8; 32] { }
// impl Digest for [u8; 48] { }
// impl Digest for [u8; 64] { }

// pub trait HexDigest: Copy + Clone + AsRef<str> + core::fmt::Display + core::fmt::Debug {

// }

// impl HexDigest for HexStr<[u8; 16 * 2 + 2]> { }
// impl HexDigest for HexStr<[u8; 20 * 2 + 2]> { }
// impl HexDigest for HexStr<[u8; 28 * 2 + 2]> { }
// impl HexDigest for HexStr<[u8; 32 * 2 + 2]> { }
// impl HexDigest for HexStr<[u8; 48 * 2 + 2]> { }
// impl HexDigest for HexStr<[u8; 64 * 2 + 2]> { }


// // TODO: multihash
// // https://github.com/multiformats/multicodec/blob/master/table.csv


// #[derive(Clone, Copy)]
// pub struct HexStr<T: Copy + Clone + AsRef<[u8]> + AsMut<[u8]>> {
//     inner: T,
// }

// impl<T: Copy + Clone + AsRef<[u8]> + AsMut<[u8]>> HexStr<T> {
//     pub fn to_lowercase(&self) -> Self {
//         let mut inner = self.inner.clone();
//         let bytes: &mut [u8] = inner.as_mut();

//         for byte in bytes.iter_mut() {
//             byte.make_ascii_lowercase();
//         }

//         Self { inner }
//     }

//     pub fn to_uppercase(&self) -> Self {
//         let mut inner = self.inner.clone();
//         let bytes: &mut [u8] = inner.as_mut();

//         for byte in bytes.iter_mut() {
//             byte.make_ascii_uppercase();
//         }

//         Self { inner }
//     }

//     pub fn as_str(&self) -> &str {
//         unsafe {
//             let bytes: &[u8] = self.inner.as_ref();
//             core::str::from_utf8_unchecked(bytes)
//         }
//     }

//     pub fn as_str_mut(&mut self) -> &mut str {
//         unsafe {
//             let bytes: &mut [u8] = self.inner.as_mut();
//             core::str::from_utf8_unchecked_mut(bytes)
//         }
//     }

//     pub fn as_str_without_prefix(&self) -> &str {
//         unsafe {
//             let bytes: &[u8] = self.inner.as_ref();
//             core::str::from_utf8_unchecked(&bytes[2..])
//         }
//     }

//     pub fn as_str_mut_without_prefix(&mut self) -> &mut str {
//         unsafe {
//             let bytes: &mut [u8] = self.inner.as_mut();
//             core::str::from_utf8_unchecked_mut(&mut bytes[2..])
//         }
//     }
// }

// impl<T: Copy + Clone + AsRef<[u8]> + AsMut<[u8]>> core::fmt::Display for HexStr<T> {
//     fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
//         let s = if f.alternate() {
//             self.as_str()
//         } else {
//             self.as_str_without_prefix()
//         };
//         core::fmt::Display::fmt(s, f)
//     }
// }
// impl<T: Copy + Clone + AsRef<[u8]> + AsMut<[u8]>> core::fmt::Debug for HexStr<T> {
//     fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
//         let s = if f.alternate() {
//             self.as_str()
//         } else {
//             self.as_str_without_prefix()
//         };
//         core::fmt::Debug::fmt(s, f)
//     }
// }

// impl<T: Copy + Clone + AsRef<[u8]> + AsMut<[u8]>> core::convert::AsRef<str> for HexStr<T> {
//     fn as_ref(&self) -> &str {
//         self.as_str_without_prefix()
//     }
// }

// #[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
// pub enum CryptoHashKind {
//     MD2,
//     MD4,
//     MD5,
//     SM3,
//     SHA1,
//     SHA2_224,
//     SHA2_256,
//     SHA2_384,
//     SHA2_512,
// }

// pub trait CryptoHasher {
//     // const BLOCK_LEN : usize;
//     // const OUTPUT_LEN: usize; // Output digest
//     // const KIND: CryptoHashKind;

//     type Output: Digest;
//     type HexOutput: HexDigest;

//     fn kind(&self) -> CryptoHashKind;
    
//     fn block_len(&self) -> usize;

//     fn output_len(&self) -> usize;

//     fn write<T: AsRef<[u8]>>(&mut self, bytes: T);

//     fn digest(self) -> Self::Output;

//     fn hexdigest(self) -> Self::HexOutput;

//     fn oneshot<T: AsRef<[u8]>>(data: T) -> Self::Output;
// }


// pub trait BuildCryptoHasher {
//     type Hasher: CryptoHasher;

//     fn build_hasher() -> Self::Hasher;
// }

// macro_rules! impl_crypto_hasher {
//     ($name:tt, $kind:tt) => {
//         impl CryptoHasher for $name {
//             // const BLOCK_LEN : usize    = $name::BLOCK_LEN;
//             // const OUTPUT_LEN: usize    = $name::DIGEST_LEN;
//             // const KIND: CryptoHashKind = CryptoHashKind::$kind;

//             type Output    = [u8; Self::DIGEST_LEN];
//             type HexOutput = HexStr<[u8; Self::DIGEST_LEN * 2 + 2]>;
            
//             fn kind(&self) -> CryptoHashKind {
//                 CryptoHashKind::$kind
//             }

//             fn block_len(&self) -> usize {
//                 $name::BLOCK_LEN
//             }
            
//             fn output_len(&self) -> usize {
//                 $name::DIGEST_LEN
//             }
            
//             fn write<T: AsRef<[u8]>>(&mut self, bytes: T) {
//                 self.update(bytes.as_ref());
//             }
            
//             fn digest(self) -> Self::Output {
//                 self.finalize()
//             }
            
//             fn hexdigest(self) -> Self::HexOutput {
//                 let digest = self.digest();
                
//                 let mut hex_bytes = [0u8; Self::DIGEST_LEN * 2 + 2];
//                 hex_bytes[0] = b'0';
//                 hex_bytes[1] = b'x';
                
//                 for i in 0..Self::DIGEST_LEN {
//                     let (hi, lo) = byte2hex(digest[i], &HEX_CHARS_LOWER);
//                     let offset = i * 2 + 2;
//                     hex_bytes[offset] = hi;
//                     hex_bytes[offset + 1] = lo;
//                 }
                
//                 HexStr { inner: hex_bytes }
//             }
            
//             fn oneshot<T: AsRef<[u8]>>(data: T) -> Self::Output {
//                 Self::oneshot(data)
//             }
//         }
//     }
// }

// macro_rules! impl_build_crypto_hasher {
//     ($name:tt) => {
//         impl BuildCryptoHasher for $name {
//             type Hasher = Self;

//             fn build_hasher() -> Self::Hasher {
//                 Self::new()
//             }
//         }
//     }
// }

// impl_crypto_hasher!(Md2, MD2);
// impl_crypto_hasher!(Md4, MD4);
// impl_crypto_hasher!(Md5, MD5);
// impl_crypto_hasher!(Sm3, SM3);

// impl_build_crypto_hasher!(Md2);
// impl_build_crypto_hasher!(Md4);
// impl_build_crypto_hasher!(Md5);
// impl_build_crypto_hasher!(Sm3);

// // SHA-1
// impl_crypto_hasher!(Sha1, SHA1);
// impl_build_crypto_hasher!(Sha1);

// // SHA-2
// impl_crypto_hasher!(Sha224, SHA2_224);
// impl_crypto_hasher!(Sha256, SHA2_256);
// impl_crypto_hasher!(Sha384, SHA2_384);
// impl_crypto_hasher!(Sha512, SHA2_512);
// impl_build_crypto_hasher!(Sha224);
// impl_build_crypto_hasher!(Sha256);
// impl_build_crypto_hasher!(Sha384);
// impl_build_crypto_hasher!(Sha512);

// // SHA-3



#[test]
fn test_hasher_oneshot() {
    macro_rules! test_oneshot {
        ($name:tt) => {
            {
                let mut m1 = $name::new();
                m1.update(&hex::decode("4b01a2d762fada9ede4d1034a13dc69c").unwrap());
                m1.update(&hex::decode("496d616b65746869735f4c6f6e6750617373506872617365466f725f7361666574795f323031395f30393238405f4021").unwrap());
                let h1 = m1.finalize();

                let h2 = $name::oneshot(&hex::decode("4b01a2d762fada9ede4d1034a13dc69c\
            496d616b65746869735f4c6f6e6750617373506872617365466f725f7361666574795f323031395f30393238405f4021").unwrap());

                assert_eq!(h1, h2);
            }
        }
    }
    
    test_oneshot!(Md2);
    test_oneshot!(Md4);
    test_oneshot!(Md5);
    test_oneshot!(Sm3);

    // SHA-1
    test_oneshot!(Sha1);
    
    // SHA-2
    test_oneshot!(Sha224);
    test_oneshot!(Sha256);
    test_oneshot!(Sha384);
    test_oneshot!(Sha512);

    // SHA-3
}


#[cfg(test)]
#[bench]
fn bench_md2(b: &mut test::Bencher) {
    let data = [1u8; 64];
    b.bytes = data.len() as u64;
    b.iter(|| {
        md2(&data)
    });
}

#[cfg(test)]
#[bench]
fn bench_md4(b: &mut test::Bencher) {
    let data = [1u8; 64];
    b.bytes = data.len() as u64;
    b.iter(|| {
        md4(&data)
    });
}

#[cfg(test)]
#[bench]
fn bench_md5(b: &mut test::Bencher) {
    let data = [1u8; 64];
    b.bytes = data.len() as u64;
    b.iter(|| {
        md5(&data)
    });
}

#[cfg(test)]
#[bench]
fn bench_sm3(b: &mut test::Bencher) {
    let data = [1u8; 64];
    b.bytes = data.len() as u64;
    b.iter(|| {
        sm3(&data)
    });
}

#[cfg(test)]
#[bench]
fn bench_sha1(b: &mut test::Bencher) {
    let data = [1u8; 64];
    b.bytes = data.len() as u64;
    b.iter(|| {
        sha1(&data)
    });
}

#[cfg(test)]
#[bench]
fn bench_sha256(b: &mut test::Bencher) {
    use self::sha2::sha256;

    let data = [1u8; 64];
    b.bytes = data.len() as u64;
    b.iter(|| {
        sha256(&data)
    });
}
#[cfg(test)]
#[bench]
fn bench_sha384(b: &mut test::Bencher) {
    use self::sha2::sha384;

    let data = [1u8; 64];
    b.bytes = data.len() as u64;
    b.iter(|| {
        sha384(&data)
    });
}
#[cfg(test)]
#[bench]
fn bench_sha512(b: &mut test::Bencher) {
    let data = [1u8; 64];
    b.bytes = data.len() as u64;
    b.iter(|| {
        sha512(&data)
    });
}
