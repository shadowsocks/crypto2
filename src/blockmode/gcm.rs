// Recommendation for Block Cipher Modes of Operation:  Galois/Counter Mode (GCM) and GMAC
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
//
// Galois/Counter Mode:
// https://en.wikipedia.org/wiki/Galois/Counter_Mode
use crate::blockcipher::{Aes128, Aes256, Aria128, Aria256, Camellia128, Camellia256, Sm4};
use crate::mac::GHash;
use crate::mem::constant_time_eq;
use crate::util::xor_si128_inplace;

// NOTE:
//      1. GCM 认证算法本身支持变长的 IV，但是目前普遍的实现都是限制 IV 长度至 12 Bytes。
//      2. GCM 只可以和 块大小为 16 Bytes 的块密码算法协同工作。
//      3. GCM 不接受用户输入的 BlockCounter。
//

const GCM_BLOCK_LEN: usize = 16;

macro_rules! impl_block_cipher_with_gcm_mode {
    ($name:tt, $cipher:tt, $tlen:tt) => {
        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
            ghash: GHash,
        }

        // 6.  AES GCM Algorithms for Secure Shell
        // https://tools.ietf.org/html/rfc5647#section-6
        impl $name {
            pub const KEY_LEN: usize = $cipher::KEY_LEN;
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            // NOTE: GCM 认证算法本身支持变长的 IV，但是目前普遍的实现都是限制 IV 长度至 12 Bytes。
            //       这样和 BlockCounter (u32) 合在一起 组成一个 Nonce，为 12 + 4 = 16 Bytes。
            pub const NONCE_LEN: usize = 12;
            pub const TAG_LEN: usize = $tlen;

            #[cfg(target_pointer_width = "64")]
            pub const A_MAX: usize = 2305843009213693951; // 2^61 - 1
            #[cfg(target_pointer_width = "32")]
            pub const A_MAX: usize = usize::MAX; // 2^32 - 1

            #[cfg(target_pointer_width = "64")]
            pub const P_MAX: usize = 68719476735; // 2^36 - 31
            #[cfg(target_pointer_width = "32")]
            pub const P_MAX: usize = usize::MAX - Self::TAG_LEN; // 2^36 - 31

            #[cfg(target_pointer_width = "64")]
            pub const C_MAX: usize = 68719476721; // 2^36 - 15
            #[cfg(target_pointer_width = "32")]
            pub const C_MAX: usize = usize::MAX; // 2^36 - 15

            pub const N_MIN: usize = Self::NONCE_LEN;
            pub const N_MAX: usize = Self::NONCE_LEN;

            pub fn new(key: &[u8]) -> Self {
                // NOTE: GCM 只可以和 块大小为 16 Bytes 的块密码算法协同工作。
                assert_eq!(Self::BLOCK_LEN, GCM_BLOCK_LEN);
                assert_eq!(Self::BLOCK_LEN, GHash::BLOCK_LEN);
                assert_eq!(key.len(), Self::KEY_LEN);

                let cipher = $cipher::new(key);

                // NOTE: 计算 Ghash 初始状态。
                let mut h = [0u8; Self::BLOCK_LEN];
                cipher.encrypt(&mut h);

                let ghash = GHash::new(&h);

                Self { cipher, ghash }
            }

            #[inline]
            fn ctr32(counter_block: &mut [u8; Self::BLOCK_LEN]) {
                let counter = u32::from_be_bytes([
                    counter_block[12],
                    counter_block[13],
                    counter_block[14],
                    counter_block[15],
                ]);

                counter_block[Self::NONCE_LEN..Self::BLOCK_LEN]
                    .copy_from_slice(&counter.wrapping_add(1).to_be_bytes());
            }

            pub fn encrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) {
                debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

                let plen = aead_pkt.len() - Self::TAG_LEN;
                let (plaintext_in_ciphertext_out, tag_out) = aead_pkt.split_at_mut(plen);

                self.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out)
            }

            #[must_use]
            pub fn decrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
                debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

                let clen = aead_pkt.len() - Self::TAG_LEN;
                let (ciphertext_in_plaintext_out, tag_in) = aead_pkt.split_at_mut(clen);

                self.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, &tag_in)
            }

            pub fn encrypt_slice_detached(
                &self,
                nonce: &[u8],
                aad: &[u8],
                plaintext_in_ciphertext_out: &mut [u8],
                tag_out: &mut [u8],
            ) {
                // NOTE: 前面 12 Bytes 为 IV，后面 4 Bytes 为 BlockCounter。
                assert_eq!(nonce.len(), Self::NONCE_LEN);

                let alen = aad.len();
                let plen = plaintext_in_ciphertext_out.len();
                let tlen = tag_out.len();

                debug_assert!(alen <= Self::A_MAX);
                debug_assert!(plen <= Self::P_MAX);
                debug_assert!(tlen == Self::TAG_LEN);

                let mut mac = self.ghash.clone();

                let mut counter_block = [0u8; Self::BLOCK_LEN];
                counter_block[..Self::NONCE_LEN].copy_from_slice(&nonce[..Self::NONCE_LEN]);
                counter_block[15] = 1; // 初始化计数器 （大端序）

                let mut base_ectr = counter_block.clone();
                self.cipher.encrypt(&mut base_ectr);

                mac.update(aad);

                //////// Update ////////
                let n = plen / Self::BLOCK_LEN;
                for i in 0..n {
                    Self::ctr32(&mut counter_block);

                    let mut ectr = counter_block.clone();
                    self.cipher.encrypt(&mut ectr);

                    let block = &mut plaintext_in_ciphertext_out
                        [i * Self::BLOCK_LEN..i * Self::BLOCK_LEN + Self::BLOCK_LEN];

                    xor_si128_inplace(block, &ectr);

                    mac.update(&block);
                }

                if plen % Self::BLOCK_LEN != 0 {
                    Self::ctr32(&mut counter_block);

                    let mut ectr = counter_block.clone();
                    self.cipher.encrypt(&mut ectr);

                    let rem = &mut plaintext_in_ciphertext_out[n * Self::BLOCK_LEN..];
                    for i in 0..rem.len() {
                        rem[i] ^= ectr[i];
                    }

                    mac.update(&rem);
                }

                // Finalize
                let mut octets = [0u8; Self::BLOCK_LEN];
                octets[0..8].copy_from_slice(&((alen as u64) * 8).to_be_bytes());
                octets[8..16].copy_from_slice(&((plen as u64) * 8).to_be_bytes());

                mac.update(&octets);

                let mut tag = [0u8; Self::TAG_LEN];
                tag[..Self::TAG_LEN].copy_from_slice(&base_ectr[..Self::TAG_LEN]);

                let code = mac.finalize();
                if Self::TAG_LEN == 16 {
                    xor_si128_inplace(&mut tag, &code);
                } else {
                    for i in 0..Self::TAG_LEN {
                        tag[i] ^= code[i];
                    }
                }

                tag_out.copy_from_slice(&tag[..Self::TAG_LEN]);
            }

            #[must_use]
            pub fn decrypt_slice_detached(
                &self,
                nonce: &[u8],
                aad: &[u8],
                ciphertext_in_plaintext_out: &mut [u8],
                tag_in: &[u8],
            ) -> bool {
                // NOTE: 前面 12 Bytes 为 IV，后面 4 Bytes 为 BlockCounter。
                assert_eq!(nonce.len(), Self::NONCE_LEN);

                let alen = aad.len();
                let clen = ciphertext_in_plaintext_out.len();
                let tlen = tag_in.len();

                debug_assert!(alen <= Self::A_MAX);
                debug_assert!(clen <= Self::P_MAX);
                debug_assert!(tlen == Self::TAG_LEN);

                let mut mac = self.ghash.clone();

                let mut counter_block = [0u8; Self::BLOCK_LEN];
                counter_block[..Self::NONCE_LEN].copy_from_slice(&nonce[..Self::NONCE_LEN]);
                counter_block[15] = 1; // 初始化计数器 （大端序）

                let mut base_ectr = counter_block.clone();
                self.cipher.encrypt(&mut base_ectr);

                mac.update(&aad);

                //////////// Update ///////////////
                let n = clen / Self::BLOCK_LEN;
                for i in 0..n {
                    Self::ctr32(&mut counter_block);

                    let mut ectr = counter_block.clone();
                    self.cipher.encrypt(&mut ectr);

                    let block = &mut ciphertext_in_plaintext_out
                        [i * Self::BLOCK_LEN..i * Self::BLOCK_LEN + Self::BLOCK_LEN];

                    mac.update(&block);

                    xor_si128_inplace(block, &ectr);
                }

                if clen % Self::BLOCK_LEN != 0 {
                    Self::ctr32(&mut counter_block);

                    let mut ectr = counter_block.clone();
                    self.cipher.encrypt(&mut ectr);

                    let rem = &mut ciphertext_in_plaintext_out[n * Self::BLOCK_LEN..];

                    mac.update(&rem);

                    for i in 0..rem.len() {
                        rem[i] ^= ectr[i];
                    }
                }

                // Finalize
                let mut octets = [0u8; 16];
                octets[0..8].copy_from_slice(&((alen as u64) * 8).to_be_bytes());
                octets[8..16].copy_from_slice(&((clen as u64) * 8).to_be_bytes());

                mac.update(&octets);

                let mut tag = [0u8; Self::TAG_LEN];
                tag[..Self::TAG_LEN].copy_from_slice(&base_ectr[..Self::TAG_LEN]);

                let code = mac.finalize();
                if Self::TAG_LEN == 16 {
                    xor_si128_inplace(&mut tag, &code);
                } else {
                    for i in 0..Self::TAG_LEN {
                        tag[i] ^= code[i];
                    }
                }

                // Verify
                constant_time_eq(tag_in, &tag[..Self::TAG_LEN])
            }
        }
    };
}

impl_block_cipher_with_gcm_mode!(Aes128Gcm, Aes128, 16); // TAG-LEN=16
impl_block_cipher_with_gcm_mode!(Aes128Gcm8, Aes128, 8); // TAG-LEN= 8
impl_block_cipher_with_gcm_mode!(Aes128Gcm12, Aes128, 12); // TAG-LEN=12

impl_block_cipher_with_gcm_mode!(Aes256Gcm, Aes256, 16); // TAG-LEN=16
impl_block_cipher_with_gcm_mode!(Aes256Gcm8, Aes256, 8); // TAG-LEN= 8
impl_block_cipher_with_gcm_mode!(Aes256Gcm12, Aes256, 12); // TAG-LEN=12

impl_block_cipher_with_gcm_mode!(Sm4Gcm, Sm4, 16); // TAG-LEN=16
impl_block_cipher_with_gcm_mode!(Camellia128Gcm, Camellia128, 16); // TAG-LEN=16
impl_block_cipher_with_gcm_mode!(Aria128Gcm, Aria128, 16); // TAG-LEN=16

impl_block_cipher_with_gcm_mode!(Camellia256Gcm, Camellia256, 16); // TAG-LEN=16
impl_block_cipher_with_gcm_mode!(Aria256Gcm, Aria256, 16); // TAG-LEN=16

#[test]
fn test_aes128_gcm() {
    // B   AES Test Vectors, (Page-29)
    // https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

    // Test  Case  1
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let iv = hex::decode("000000000000000000000000").unwrap();
    let aad = [0u8; 0];
    // let plaintext = [0u8; 0];
    let mut ciphertext_and_tag = [0u8; 0 + Aes128Gcm::TAG_LEN];

    let cipher = Aes128Gcm::new(&key);
    cipher.encrypt_slice(&iv, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex::decode("58e2fccefa7e3061367f1d57a4e7455a").unwrap()[..]
    );

    // Test  Case  2
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let iv = hex::decode("000000000000000000000000").unwrap();
    let aad = [0u8; 0];
    let plaintext = hex::decode("00000000000000000000000000000000").unwrap();
    let plen = plaintext.len();
    let mut plaintext_and_ciphertext = plaintext.clone();
    plaintext_and_ciphertext.resize(plen + Aes128Gcm::TAG_LEN, 0);

    let cipher = Aes128Gcm::new(&key);
    cipher.encrypt_slice(&iv, &aad, &mut plaintext_and_ciphertext);

    assert_eq!(
        &plaintext_and_ciphertext[..plen],
        &hex::decode("0388dace60b6a392f328c2b971b2fe78").unwrap()[..]
    );
    assert_eq!(
        &plaintext_and_ciphertext[plen..],
        &hex::decode("ab6e47d42cec13bdf53a67b21257bddf").unwrap()[..]
    );

    // Test  Case  3
    let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
    let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];
    let plaintext = hex::decode(
        "d9313225f88406e5a55909c5aff5269a\
86a7a9531534f7da2e4c303d8a318a72\
1c3c0c95956809532fcf0e2449a6b525\
b16aedf5aa0de657ba637b391aafd255",
    )
    .unwrap();
    let plen = plaintext.len();
    let mut plaintext_and_ciphertext = plaintext.clone();
    plaintext_and_ciphertext.resize(plen + Aes128Gcm::TAG_LEN, 0);

    let cipher = Aes128Gcm::new(&key);
    cipher.encrypt_slice(&iv, &aad, &mut plaintext_and_ciphertext);
    assert_eq!(
        &plaintext_and_ciphertext[..plen],
        &hex::decode(
            "42831ec2217774244b7221b784d0d49c\
e3aa212f2c02a4e035c17e2329aca12e\
21d514b25466931c7d8f6a5aac84aa05\
1ba30b396a0aac973d58e091473f5985"
        )
        .unwrap()[..]
    );
    assert_eq!(
        &plaintext_and_ciphertext[plen..],
        &hex::decode("4d5c2af327cd64a62cf35abd2ba6fab4").unwrap()[..]
    );

    // Test  Case  4
    let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
    let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = hex::decode(
        "feedfacedeadbeeffeedfacedeadbeef\
abaddad2",
    )
    .unwrap();
    let plaintext = hex::decode(
        "d9313225f88406e5a55909c5aff5269a\
86a7a9531534f7da2e4c303d8a318a72\
1c3c0c95956809532fcf0e2449a6b525\
b16aedf5aa0de657ba637b39",
    )
    .unwrap();
    let plen = plaintext.len();
    let mut plaintext_and_ciphertext = plaintext.clone();
    plaintext_and_ciphertext.resize(plen + Aes128Gcm::TAG_LEN, 0);

    let cipher = Aes128Gcm::new(&key);
    cipher.encrypt_slice(&iv, &aad, &mut plaintext_and_ciphertext);
    assert_eq!(
        &plaintext_and_ciphertext[..plen],
        &hex::decode(
            "42831ec2217774244b7221b784d0d49c\
e3aa212f2c02a4e035c17e2329aca12e\
21d514b25466931c7d8f6a5aac84aa05\
1ba30b396a0aac973d58e091"
        )
        .unwrap()[..]
    );
    assert_eq!(
        &plaintext_and_ciphertext[plen..],
        &hex::decode("5bc94fbc3221a5db94fae95ae7121a47").unwrap()[..]
    );
}
