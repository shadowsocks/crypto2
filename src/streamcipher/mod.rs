pub use crate::blockmode::{
    Aes128Cfb1, Aes128Cfb128, Aes128Cfb8, Aes128Ctr, Aes128Ofb, Aes192Cfb1, Aes192Cfb128,
    Aes192Cfb8, Aes192Ctr, Aes192Ofb, Aes256Cfb1, Aes256Cfb128, Aes256Cfb8, Aes256Ctr, Aes256Ofb,
    Aria128Cfb1, Aria128Cfb128, Aria128Cfb8, Aria128Ctr, Aria128Ofb, Aria192Cfb1, Aria192Cfb128,
    Aria192Cfb8, Aria192Ctr, Aria192Ofb, Aria256Cfb1, Aria256Cfb128, Aria256Cfb8, Aria256Ctr,
    Aria256Ofb, Camellia128Cfb1, Camellia128Cfb128, Camellia128Cfb8, Camellia128Ctr,
    Camellia128Ofb, Camellia192Cfb1, Camellia192Cfb128, Camellia192Cfb8, Camellia192Ctr,
    Camellia192Ofb, Camellia256Cfb1, Camellia256Cfb128, Camellia256Cfb8, Camellia256Ctr,
    Camellia256Ofb, Sm4Cfb1, Sm4Cfb128, Sm4Cfb8, Sm4Ctr, Sm4Ofb,
};

mod chacha20;
mod rc4;

pub use self::chacha20::*;
pub use self::rc4::*;

#[cfg(test)]
#[bench]
fn bench_rc4(b: &mut test::Bencher) {
    let key =
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let mut ciphertext = test::black_box([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]);

    let mut cipher = Rc4::new(&key);

    b.bytes = 16;
    b.iter(|| {
        cipher.encrypt_slice(&mut ciphertext);
    })
}

#[cfg(test)]
#[bench]
fn bench_chacha20(b: &mut test::Bencher) {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut plaintext_and_ciphertext = test::black_box([1u8; Chacha20::BLOCK_LEN]);

    let chacha20 = Chacha20::new(&key);

    b.bytes = Chacha20::BLOCK_LEN as u64;
    b.iter(|| {
        chacha20.encrypt_slice(1, &nonce, &mut plaintext_and_ciphertext);
    })
}
