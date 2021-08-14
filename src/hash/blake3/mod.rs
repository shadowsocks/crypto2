// BLAKE3 specifications
// https://github.com/BLAKE3-team


#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2", 
))]
#[path = "./x86/mod.rs"]
mod platform;

#[cfg(not(all(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2", 
    ),
)))]
#[path = "./generic.rs"]
mod platform;


pub use self::platform::*;


/// The blake3 default hash function with any digest length
pub fn blake3<T: AsRef<[u8]>>(data: T, digest: &mut [u8]) {
    Blake3::oneshot_hash(data, digest);
}

/// The blake3 default hash function with 256 digest length
pub fn blake3_256<T: AsRef<[u8]>>(data: T) -> [u8; 32] {
    let mut digest = [0u8; 32];
    Blake3::oneshot_hash(data, &mut digest[..]);
    digest
}

/// The blake3 default hash function with 512 digest length
pub fn blake3_512<T: AsRef<[u8]>>(data: T) -> [u8; 64] {
    let mut digest = [0u8; 64];
    Blake3::oneshot_hash(data, &mut digest[..]);
    digest
}


/// The blake3 keyed hash function with any digest length
pub fn blake3_keyed_hash<T: AsRef<[u8]>>(key: &[u8; Blake3::KEY_LEN], data: T, digest: &mut [u8]) {
    Blake3::oneshot_keyed_hash(key, data, digest);
}

/// The blake3 keyed hash function with 256 digest length
pub fn blake3_keyed_hash_256<T: AsRef<[u8]>>(key: &[u8; Blake3::KEY_LEN], data: T) -> [u8; 32] {
    let mut digest = [0u8; 32];
    Blake3::oneshot_keyed_hash(key, data, &mut digest);
    
    return digest;
}

/// The blake3 keyed hash function with 512 digest length
pub fn blake3_keyed_hash_512<T: AsRef<[u8]>>(key: &[u8; Blake3::KEY_LEN], data: T) -> [u8; 64] {
    let mut digest = [0u8; 64];
    Blake3::oneshot_keyed_hash(key, data, &mut digest);

    return digest;
}


/// The blake3 key derivation function with any digest length
pub fn blake3_derive_key<S: AsRef<[u8]>, T: AsRef<[u8]>>(context: S, data: T, digest: &mut [u8]) {
    Blake3::oneshot_derive_key(context, data, digest)
}

/// The blake3 key derivation function with 256 digest length
pub fn blake3_derive_key_256<S: AsRef<[u8]>, T: AsRef<[u8]>>(context: S, data: T) -> [u8; 32] {
    let mut digest = [0u8; 32];
    Blake3::oneshot_derive_key(context, data, &mut digest);

    return digest;
}

/// The blake3 key derivation function with 512 digest length
pub fn blake3_derive_key_512<S: AsRef<[u8]>, T: AsRef<[u8]>>(context: S, data: T) -> [u8; 64] {
    let mut digest = [0u8; 64];
    Blake3::oneshot_derive_key(context, data, &mut digest);
    
    return digest;
}



#[cfg(test)]
#[bench]
fn bench_blake3_256(b: &mut test::Bencher) {
    let data = [3u8; 64];

    b.bytes = 64;
    b.iter(|| {
        blake3_256(&data)
    })
}

#[cfg(test)]
#[bench]
fn bench_blake3_512(b: &mut test::Bencher) {
    let data = [3u8; 64];

    b.bytes = 64;
    b.iter(|| {
        blake3_512(&data)
    })
}

#[cfg(test)]
#[bench]
fn bench_blake3_1024(b: &mut test::Bencher) {
    let data = [3u8; 64];

    b.bytes = 64;
    b.iter(|| {
        let mut digest = [0u8; 128];
        blake3(&data, &mut digest);
        digest
    })
}


#[cfg(test)]
#[bench]
fn bench_blake3_256_gt1024(b: &mut test::Bencher) {
    let data = [3u8; 1024+128];

    b.bytes = data.len() as _;
    b.iter(|| {
        blake3_256(&data)
    })
}