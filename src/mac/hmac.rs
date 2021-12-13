// HMAC: Keyed-Hashing for Message Authentication
// https://tools.ietf.org/html/rfc2104
use crate::hash::{Md2, Md4, Md5, Sha1, Sha224, Sha256, Sha384, Sha512, Sm3};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

macro_rules! impl_hmac_with_hasher {
    ($name:tt, $hasher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            okey: [u8; Self::BLOCK_LEN],
            hasher: $hasher,
        }

        impl $name {
            pub const BLOCK_LEN: usize = $hasher::BLOCK_LEN;
            pub const TAG_LEN: usize = $hasher::DIGEST_LEN;

            pub fn new(key: &[u8]) -> Self {
                // H(K XOR opad, H(K XOR ipad, text))
                let mut ikey = [0u8; Self::BLOCK_LEN];
                let mut okey = [0u8; Self::BLOCK_LEN];

                if key.len() > Self::BLOCK_LEN {
                    let hkey = $hasher::oneshot(key);

                    ikey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
                    okey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
                } else {
                    ikey[..key.len()].copy_from_slice(&key);
                    okey[..key.len()].copy_from_slice(&key);
                }

                for idx in 0..Self::BLOCK_LEN {
                    ikey[idx] ^= IPAD;
                    okey[idx] ^= OPAD;
                }

                let mut hasher = $hasher::new();
                hasher.update(&ikey);

                Self { okey, hasher }
            }

            pub fn update(&mut self, m: &[u8]) {
                self.hasher.update(m);
            }

            pub fn finalize(self) -> [u8; Self::TAG_LEN] {
                let h1 = self.hasher.finalize();

                let mut hasher = $hasher::new();
                hasher.update(&self.okey);
                hasher.update(&h1);

                let h2 = hasher.finalize();

                return h2;
            }

            pub fn oneshot(key: &[u8], m: &[u8]) -> [u8; Self::TAG_LEN] {
                let mut mac = Self::new(key);
                mac.update(m);
                mac.finalize()
            }
        }
    };
}

impl_hmac_with_hasher!(HmacMd2, Md2);
impl_hmac_with_hasher!(HmacMd4, Md4);
impl_hmac_with_hasher!(HmacMd5, Md5);
impl_hmac_with_hasher!(HmacSm3, Sm3);

impl_hmac_with_hasher!(HmacSha1, Sha1);

// SHA-2
impl_hmac_with_hasher!(HmacSha224, Sha224);
impl_hmac_with_hasher!(HmacSha256, Sha256);
impl_hmac_with_hasher!(HmacSha384, Sha384);
impl_hmac_with_hasher!(HmacSha512, Sha512);

// SHA-3

pub fn hmac_md2(key: &[u8], m: &[u8]) -> [u8; HmacMd2::TAG_LEN] {
    HmacMd2::oneshot(key, m)
}

pub fn hmac_md4(key: &[u8], m: &[u8]) -> [u8; HmacMd4::TAG_LEN] {
    HmacMd4::oneshot(key, m)
}

pub fn hmac_md5(key: &[u8], m: &[u8]) -> [u8; HmacMd5::TAG_LEN] {
    HmacMd5::oneshot(key, m)
}

pub fn hmac_sm3(key: &[u8], m: &[u8]) -> [u8; HmacSm3::TAG_LEN] {
    HmacSm3::oneshot(key, m)
}

pub fn hmac_sha1(key: &[u8], m: &[u8]) -> [u8; HmacSha1::TAG_LEN] {
    HmacSha1::oneshot(key, m)
}

pub fn hmac_sha256(key: &[u8], m: &[u8]) -> [u8; HmacSha256::TAG_LEN] {
    HmacSha256::oneshot(key, m)
}
pub fn hmac_sha384(key: &[u8], m: &[u8]) -> [u8; HmacSha384::TAG_LEN] {
    HmacSha384::oneshot(key, m)
}
pub fn hmac_sha512(key: &[u8], m: &[u8]) -> [u8; HmacSha512::TAG_LEN] {
    HmacSha512::oneshot(key, m)
}

// TODO: hmac-drbg
// https://github.com/sorpaas/rust-hmac-drbg/blob/master/src/lib.rs

#[cfg(test)]
use crate::encoding::hex;

// HMAC_MD5("key", "The quick brown fox jumps over the lazy dog")    = 80070713463e7749b90c2dc24911e275
// HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog")   = de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
// HMAC_SHA256("key", "The quick brown fox jumps over the lazy dog") = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
#[test]
fn test_hmac_md5() {
    // [Page 8] Test Vectors
    // https://tools.ietf.org/html/rfc2104#section-6
    let b16 = [0x0b; 16]; // 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
    let aa16 = [0xaa; 16]; // 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    let dd50 = [0xdd; 50];

    let suites: &[(&[u8], &[u8], &str)] = &[
        (
            b"key",
            b"The quick brown fox jumps over the lazy dog",
            "80070713463e7749b90c2dc24911e275",
        ),
        (&b16, b"Hi There", "9294727a3638bb1c13f48ef8158bfc9d"),
        (
            b"Jefe",
            b"what do ya want for nothing?",
            "750c783e6ab0b503eaa86e310a5db738",
        ),
        (&aa16, &dd50, "56be34521d144c88dbb8c733f0e8b3f6"),
    ];
    for (key, data, result) in suites.iter() {
        assert_eq!(&hex::encode_lowercase(&HmacMd5::oneshot(key, data)), result);
    }
}
#[test]
fn test_hmac_sha1() {
    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    let result = "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9";

    assert_eq!(
        &hex::encode_lowercase(&HmacSha1::oneshot(key, data)),
        result
    );
}

#[test]
fn test_hmac_sha2_256() {
    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    let result = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";

    assert_eq!(
        &hex::encode_lowercase(&HmacSha256::oneshot(key, data)),
        result
    );
}
#[test]
fn test_hmac_sha2_384() {
    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    let result = "d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc592c5d3e1ae50700582a96cf35e1e554995fe4e03381c237";

    assert_eq!(
        &hex::encode_lowercase(&HmacSha384::oneshot(key, data)),
        result
    );
}
#[test]
fn test_hmac_sha2_512() {
    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    let result = "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a";

    assert_eq!(
        &hex::encode_lowercase(&HmacSha512::oneshot(key, data)),
        result
    );
}
