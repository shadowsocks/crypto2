
mod rc2;
mod sm4;
mod aes;
mod aria;
#[allow(unused_macros, unused_variables, dead_code, unused_assignments, unused_imports)]
mod camellia;

pub use self::rc2::*;
pub use self::sm4::*;
pub use self::aes::*;
pub use self::aria::*;
pub use self::camellia::*;


#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum BlockCipherKind {
    SM4,
    RC2_FIXED_SIZE,

    AES128,
    AES192,
    AES256,
    
    CAMELLIA128,
    CAMELLIA192,
    CAMELLIA256,

    ARIA128,
    ARIA192,
    ARIA256,
    
    Private(&'static str),
}


// ==============================  对称分组密码  ===============================
pub trait BlockCipher: Sized {
    const KIND: BlockCipherKind;
    const KEY_LEN: usize;
    const BLOCK_LEN: usize;
    
    fn new(key: &[u8]) -> Self;

    fn encrypt_block_oneshot(key: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]) {
        let mut cipher = Self::new(key);
        cipher.encrypt_block(plaintext_in_and_ciphertext_out);
    }

    fn decrypt_block_oneshot(key: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) {
        let mut cipher = Self::new(key);
        cipher.decrypt_block(ciphertext_in_and_plaintext_out);
    }

    fn encrypt_block(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
    fn decrypt_block(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]);
}


macro_rules! impl_block_cipher {
    ($name:tt, $kind:tt) => {
        impl BlockCipher for $name {
            const KIND: BlockCipherKind = BlockCipherKind::$kind;
            const KEY_LEN: usize   = $name::KEY_LEN;
            const BLOCK_LEN: usize = $name::BLOCK_LEN;

            fn new(key: &[u8]) -> Self {
                Self::new(key)
            }

            fn encrypt_block(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]) {
                self.encrypt(plaintext_in_and_ciphertext_out);
            }

            fn decrypt_block(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]) {
                self.decrypt(ciphertext_in_and_plaintext_out);
            }
        }
    }
}

impl_block_cipher!(Rc2FixedSize, RC2_FIXED_SIZE);
impl_block_cipher!(Sm4, SM4);

impl_block_cipher!(Aes128, AES128);
impl_block_cipher!(Aes192, AES192);
impl_block_cipher!(Aes256, AES256);
impl_block_cipher!(Camellia128, CAMELLIA128);
impl_block_cipher!(Camellia192, CAMELLIA192);
impl_block_cipher!(Camellia256, CAMELLIA256);
impl_block_cipher!(Aria128, ARIA128);
impl_block_cipher!(Aria192, ARIA192);
impl_block_cipher!(Aria256, ARIA256);



#[cfg(test)]
#[bench]
fn bench_rc2_enc(b: &mut test::Bencher) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let cipher = Rc2::new(&key);

    // NOTE: RC2 的 Block Size 为 8 bytes，改成双倍大小后数据量就会和 AES 这些一样。
    b.bytes = Rc2::BLOCK_LEN as u64 * 2;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        cipher.decrypt_two_blocks(&mut ciphertext);
        ciphertext
    })
}

#[cfg(test)]
#[bench]
fn bench_sm4_enc(b: &mut test::Bencher) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let cipher = Sm4::new(&key);

    b.bytes = Sm4::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        cipher.encrypt(&mut ciphertext);
        ciphertext
    })
}

#[cfg(test)]
#[bench]
fn bench_aria128_enc(b: &mut test::Bencher) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let cipher = Aria128::new(&key);

    b.bytes = Aria128::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        cipher.encrypt(&mut ciphertext);
        ciphertext
    })
}
#[cfg(test)]
#[bench]
fn bench_aria256_enc(b: &mut test::Bencher) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f\
000102030405060708090a0b0c0d0e0f").unwrap();

    let cipher = Aria256::new(&key);

    b.bytes = Aria256::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        cipher.encrypt(&mut ciphertext);
        ciphertext
    })
}

#[cfg(test)]
#[bench]
fn bench_camellia128_enc(b: &mut test::Bencher) {
    let key = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];

    let cipher = Camellia128::new(&key);

    b.bytes = Camellia128::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        cipher.encrypt(&mut ciphertext);
        ciphertext
    });
}

#[cfg(test)]
#[bench]
fn bench_camellia256_enc(b: &mut test::Bencher) {
    let key = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];

    let cipher = Camellia256::new(&key);

    b.bytes = Camellia256::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        cipher.encrypt(&mut ciphertext);
        ciphertext
    });
}

#[cfg(test)]
#[bench]
fn bench_aes128_enc(b: &mut test::Bencher) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let cipher = Aes128::new(&key);

    b.bytes = Aes128::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        cipher.encrypt(&mut ciphertext);
        ciphertext
    })
}

#[cfg(test)]
#[bench]
fn bench_aes256_enc(b: &mut test::Bencher) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f\
000102030405060708090a0b0c0d0e0f").unwrap();

    let cipher = Aes256::new(&key);

    b.bytes = Aes256::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        cipher.encrypt(&mut ciphertext);
        ciphertext
    })
}
