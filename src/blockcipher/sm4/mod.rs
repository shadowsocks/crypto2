// #[cfg(all(
//     any(target_arch = "x86", target_arch = "x86_64"),
//     all(target_feature = "aes", target_feature = "sse2")
// ))]
// #[path = "./x86.rs"]
// mod platform;


// // NOTE:
// //      Crypto: AES + PMULL + SHA1 + SHA2
// //      https://github.com/rust-lang/stdarch/blob/master/crates/std_detect/src/detect/arch/aarch64.rs#L26
// #[cfg(all(target_arch = "aarch64", target_feature = "crypto"))]
// #[path = "./aarch64.rs"]
// mod platform;
// // #[cfg(all(target_arch = "aarch64", target_feature = "crypto"))]
// // mod generic;


// #[cfg(not(any(
//     all(
//         any(target_arch = "x86", target_arch = "x86_64"),
//         all(target_feature = "aes", target_feature = "sse2")
//     ),
//     all(target_arch = "aarch64", target_feature = "crypto")
// )))]
// #[path = "./generic.rs"]
// mod platform;


mod generic;
// pub use self::platform::*;
pub use self::generic::*;


// Tests below
#[test]
fn test_sm4_setup_cipher() {
    let key: [u8; Sm4::KEY_LEN] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 
    ];

    let cipher = Sm4::new(&key);
    
    assert_eq!(cipher.rk[0][0], 0xf12186f9);
    assert_eq!(cipher.rk[Sm4::NR - 1][3], 0x9124a012);
}

#[test]
fn test_sm4_enc_and_dec() {
    let key: [u8; Sm4::KEY_LEN] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 
    ];
    let plaintext: [u8; Sm4::BLOCK_LEN] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];

    let cipher = Sm4::new(&key);

    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);
    assert_eq!(&ciphertext[..], &[
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
    ]);

    cipher.decrypt(&mut ciphertext);
    assert_eq!(&ciphertext[..], &plaintext[..]);
}