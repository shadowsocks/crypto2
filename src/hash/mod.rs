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


// NOTE: 等待 core::array::FixedSizeArray 稳定后，即可替换。
pub trait Array<T> {
    fn array_as_slice(&self) -> &[T];
    fn array_as_mut_slice(&mut self) -> &mut [T];
}

macro_rules! array_impls {
    ($($N:literal)+) => {
        $(
            impl<T> Array<T> for [T; $N] {
                fn array_as_slice(&self) -> &[T] {
                    self
                }

                fn array_as_mut_slice(&mut self) -> &mut [T] {
                    self
                }

            }
        )+
    }
}
array_impls! {
     0  1  2  3  4  5  6  7  8  9
    10 11 12 13 14 15 16 17 18 19
    20 21 22 23 24 25 26 27 28 29
    30 31 32 33 34 35 36 37 38 39 
    40 41 42 43 44 45 46 47 48 49 
    50 51 52 53 54 55 56 57 58 59 
    60 61 62 63 64
}


// TODO: multihash
// https://github.com/multiformats/multicodec/blob/master/table.csv

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CryptoHashKind {
    MD2,
    MD4,
    MD5,
    SM3,
    SHA1,
    SHA2_256,
    SHA2_384,
    SHA2_512,
}

pub trait CryptoHasher {
    const BLOCK_LEN : usize;
    const OUTPUT_LEN: usize; // Output digest
    
    type Output: Array<u8> + Sized;
    
    fn digest(self) -> Self::Output;
    fn hexdigest(self) -> String 
    where 
        Self: Sized 
    {
        let digest = self.digest();
        let digest: &[u8] = digest.array_as_slice();

        let mut s = String::with_capacity(digest.len()*2);
        for n in digest.iter() {
            s.push_str(format!("{:02x}", n).as_str());
        }
        s
    }
    
    fn write<T: AsRef<[u8]>>(&mut self, bytes: T);

    fn oneshot<T: AsRef<[u8]>>(data: T) -> Self::Output;
}


pub trait BuildCryptoHasher {
    type Hasher: CryptoHasher;

    fn build_hasher() -> Self::Hasher;
}

// pub trait CryptoHash {
//     /// Feeds this value into the given `Hasher`.
//     fn crypto_hash<H: CryptoHasher>(&self, state: &mut H);

//     /// Feeds a slice of this type into the given `Hasher`.
//     fn crypto_hash_slice<H: CryptoHasher>(data: &[Self], state: &mut H)
//     where
//         Self: Sized,
//     {
//         for piece in data {
//             piece.crypto_hash(state);
//         }
//     }
// }

// impl<T: CryptoHash> CryptoHash for [T] {
//     fn crypto_hash<H: CryptoHasher>(&self, state: &mut H) {
//         CryptoHash::crypto_hash_slice(self, state);
//     }
// }
// impl<'a, T: CryptoHash> CryptoHash for &'a [T] {
//     fn crypto_hash<H: CryptoHasher>(&self, state: &mut H) {
//         CryptoHash::crypto_hash_slice(self, state);
//     }
// }

macro_rules! impl_crypto_hasher {
    ($name:tt) => {
        impl CryptoHasher for $name {
            const BLOCK_LEN : usize = $name::BLOCK_LEN;
            const OUTPUT_LEN: usize = $name::DIGEST_LEN;
            
            type Output = [u8; Self::DIGEST_LEN];

            // fn finish(self);

            fn write<T: AsRef<[u8]>>(&mut self, bytes: T) {
                self.update(bytes.as_ref());
            }

            fn digest(self) -> Self::Output {
                self.finalize()
            }

            fn oneshot<T: AsRef<[u8]>>(data: T) -> Self::Output {
                Self::oneshot(data)
            }
        }
    }
}

macro_rules! impl_build_crypto_hasher {
    ($name:tt) => {
        impl BuildCryptoHasher for $name {
            type Hasher = Self;

            fn build_hasher() -> Self::Hasher {
                Self::new()
            }
        }
    }
}

impl_crypto_hasher!(Md2);
impl_crypto_hasher!(Md4);
impl_crypto_hasher!(Md5);
impl_crypto_hasher!(Sm3);
impl_crypto_hasher!(Sha1);
impl_build_crypto_hasher!(Md2);
impl_build_crypto_hasher!(Md4);
impl_build_crypto_hasher!(Md5);
impl_build_crypto_hasher!(Sm3);
impl_build_crypto_hasher!(Sha1);

// SHA-2
impl_crypto_hasher!(Sha256);
impl_crypto_hasher!(Sha384);
impl_crypto_hasher!(Sha512);
impl_build_crypto_hasher!(Sha256);
impl_build_crypto_hasher!(Sha384);
impl_build_crypto_hasher!(Sha512);

// SHA-3



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
