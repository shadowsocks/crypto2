use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"),
                 all(target_feature = "aes", target_feature = "sse2")))] {
        mod x86;
        pub use self::x86::*;
    } else if #[cfg(all(target_arch = "aarch64", target_feature = "aes"))] {
        mod aarch64;
        pub use self::aarch64::*;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))] {
        // Check for platform specific optimizations dynamically
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        #[path = "./x86.rs"]
        mod platform;

        #[cfg(target_arch = "aarch64")]
        #[path = "./aarch64.rs"]
        mod platform;

        mod generic;

        mod dynamic;
        pub use self::dynamic::*;
    } else {
        mod generic;
        pub use self::generic::*;
    }
}

#[test]
fn test_aes128() {
    // AES 128
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode("00112233445566778899aabbccddeeff").unwrap();

    let cipher = Aes128::new(&key);

    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);
    assert_eq!(
        &ciphertext[..],
        &hex::decode("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap()[..]
    );

    let mut cleartext = ciphertext.clone();
    cipher.decrypt(&mut cleartext);
    assert_eq!(&cleartext[..], &plaintext[..]);
}

#[test]
fn test_aes192() {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f1011121314151617").unwrap();
    let plaintext = hex::decode("00112233445566778899aabbccddeeff").unwrap();

    let cipher = Aes192::new(&key);

    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);
    assert_eq!(
        &ciphertext[..],
        &hex::decode("dda97ca4864cdfe06eaf70a0ec0d7191").unwrap()[..]
    );

    let mut cleartext = ciphertext.clone();
    cipher.decrypt(&mut cleartext);
    assert_eq!(&cleartext[..], &plaintext[..]);
}

#[test]
fn test_aes256() {
    // AES 256
    let key =
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let plaintext = hex::decode("00112233445566778899aabbccddeeff").unwrap();

    let cipher = Aes256::new(&key);

    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);
    assert_eq!(
        &ciphertext[..],
        &hex::decode("8ea2b7ca516745bfeafc49904b496089").unwrap()[..]
    );

    let mut cleartext = ciphertext.clone();
    cipher.decrypt(&mut cleartext);
    assert_eq!(&cleartext[..], &plaintext[..]);
}
