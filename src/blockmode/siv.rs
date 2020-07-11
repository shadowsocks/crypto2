// NIST Special Publication 800-38B
// Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication
// https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-38b.pdf
// 
// The AES-CMAC Algorithm
// https://tools.ietf.org/html/rfc4493
// 
// Synthetic Initialization Vector (SIV) Authenticated Encryption Using the Advanced Encryption Standard (AES)
// https://tools.ietf.org/html/rfc5297
// 
// Block Cipher Techniques
// https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-development
use super::dbl;
use crate::mem::Zeroize;
use crate::mem::constant_time_eq;
use crate::util::xor_si128_inplace;
use crate::util::and_si128_inplace;
use crate::blockcipher::{Aes128, Aes192, Aes256};



macro_rules! impl_block_cipher_with_siv_cmac_mode {
    ($name:tt, $cipher:tt) => {

        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
            cmac_cipher: $cipher,
            cmac_k1: [u8; Self::BLOCK_LEN],
            cmac_k2: [u8; Self::BLOCK_LEN],
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.cipher.zeroize();
                self.cmac_cipher.zeroize();
                self.cmac_k1.zeroize();
                self.cmac_k2.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl $name {
            pub const KEY_LEN: usize   = $cipher::KEY_LEN * 2; // 16 Byte Cipher Key, 16 Byte CMac Key
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const TAG_LEN: usize   = 16;
            
            pub const A_MAX: usize = usize::MAX; // NOTE: 实际上是 unlimited
            // NOTE: 实际上是 2 ^ 132，但是这超出了 u64 的最大值。
            pub const P_MAX: usize = usize::MAX - 16;
            pub const C_MAX: usize = usize::MAX;
            pub const N_MIN: usize = 1;
            pub const N_MAX: usize = usize::MAX;

            pub const COMPONENTS_MAX: usize = 126;


            const BLOCK_ZERO: [u8; Self::BLOCK_LEN] = [0u8; Self::BLOCK_LEN];
            // 1^64 || 0^1 || 1^31 || 0^1 || 1^31
            const V1: [u8; Self::BLOCK_LEN] = [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 
            ];


            pub fn new(key: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);

                // CMac Cipher Key
                let k1 = &key[..$cipher::KEY_LEN];
                // Cipher Key
                let k2 = &key[$cipher::KEY_LEN..];

                let cipher = $cipher::new(k2);
                let cmac_cipher = $cipher::new(k1);
                
                // 2.3.  Subkey Generation Algorithm
                // https://tools.ietf.org/html/rfc4493#section-2.3
                let mut cmac_k1 = [0u8; Self::BLOCK_LEN];
                cmac_cipher.encrypt(&mut cmac_k1);

                let cmac_k1 = dbl(u128::from_be_bytes(cmac_k1)).to_be_bytes();
                let cmac_k2 = dbl(u128::from_be_bytes(cmac_k1)).to_be_bytes();

                Self { cipher, cmac_cipher, cmac_k1, cmac_k2 }
            }

            // The AES-CMAC Algorithm
            // https://tools.ietf.org/html/rfc4493
            #[inline]
            fn cmac(&self, m: &[u8], last_block: Option<&[u8; Self::BLOCK_LEN]>) -> [u8; Self::BLOCK_LEN] {
                // 2.4.  MAC Generation Algorithm
                // https://tools.ietf.org/html/rfc4493#section-2.4
                if cfg!(debug_assertions) {
                    if last_block.is_some() {
                        assert!(m.len() >= Self::BLOCK_LEN);
                    }
                }
                let mlen = if last_block.is_some() { m.len() + Self::BLOCK_LEN } else { m.len() };

                let mut padding_block = [
                    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ];
                
                if mlen < Self::BLOCK_LEN {
                    padding_block[..mlen].copy_from_slice(&m);
                    padding_block[mlen] = 0x80;

                    xor_si128_inplace(&mut padding_block, &self.cmac_k2);

                    self.cmac_cipher.encrypt(&mut padding_block);
                    return padding_block;
                }

                if mlen == Self::BLOCK_LEN {
                    let data = match last_block {
                        Some(data) => &data[..],
                        None => &m[..],
                    };

                    let mut block = self.cmac_k1.clone();
                    xor_si128_inplace(&mut block, data);

                    self.cmac_cipher.encrypt(&mut block);
                    return block;
                }

                // process M_i
                let n = mlen / Self::BLOCK_LEN;
                let r = mlen % Self::BLOCK_LEN;

                let mut x = [0u8; Self::BLOCK_LEN];

                match last_block {
                    Some(last_block) => {
                        let chunks = m.chunks_exact(Self::BLOCK_LEN);
                        let rem = chunks.remainder();
                        for chunk in chunks {
                            // M_n
                            xor_si128_inplace(&mut x, chunk);
                            self.cmac_cipher.encrypt(&mut x);
                        }

                        let rlen = rem.len();
                        if rlen == 0 {
                            // M_last
                            xor_si128_inplace(&mut x, last_block);
                            xor_si128_inplace(&mut x, &self.cmac_k1);
                        } else {
                            let mut block = [0u8; Self::BLOCK_LEN];
                            block[..rlen].copy_from_slice(rem);
                            block[rlen..Self::BLOCK_LEN].copy_from_slice(&last_block[..Self::BLOCK_LEN - rlen]);

                            // M_n
                            xor_si128_inplace(&mut x, &block);
                            self.cmac_cipher.encrypt(&mut x);

                            // M_last
                            let mut block = [0u8; Self::BLOCK_LEN];
                            let rem = &last_block[Self::BLOCK_LEN - rlen..];
                            let rlen = rem.len();
                            block[..rlen].copy_from_slice(rem);
                            block[rlen] = 0x80;

                            xor_si128_inplace(&mut x, &block);
                            xor_si128_inplace(&mut x, &self.cmac_k2);
                        }
                    },
                    None => {
                        let mn = if r == 0 { n - 1 } else { n };
                        for i in 0..mn {
                            // M_n
                            let start = i * Self::BLOCK_LEN;
                            let end   = start + Self::BLOCK_LEN;
                            let block = &m[start..end];

                            debug_assert_eq!(block.len(), Self::BLOCK_LEN);

                            xor_si128_inplace(&mut x, &block);

                            self.cmac_cipher.encrypt(&mut x);
                        }

                        let last_block_offset = mn * Self::BLOCK_LEN;
                        let last_block = &m[last_block_offset..];
                        let last_block_len = last_block.len();

                        if last_block_len == Self::BLOCK_LEN {
                            let block = last_block;

                            xor_si128_inplace(&mut x, &block);
                            xor_si128_inplace(&mut x, &self.cmac_k1);
                        } else {
                            let mut block = padding_block;
                            block[..last_block_len].copy_from_slice(&last_block);
                            block[last_block_len] = 0x80;

                            xor_si128_inplace(&mut x, &block);
                            xor_si128_inplace(&mut x, &self.cmac_k2);
                        }
                    }
                }

                self.cmac_cipher.encrypt(&mut x);

                return x;
            }

            #[inline]
            fn siv(&self, components: &[&[u8]], payload: &[u8]) -> [u8; Self::BLOCK_LEN] {
                // 2.4.  S2V
                // https://tools.ietf.org/html/rfc5297#section-2.4
                if components.is_empty() && payload.is_empty() {
                    // indicates a string that is 127 zero bits concatenated with a
                    // single one bit, that is 0^127 || 1^1.
                    let one = 1u128.to_be_bytes();
                    return self.cmac(&one, None);
                }

                let mut d = self.cmac(&Self::BLOCK_ZERO, None);
                for aad in components.iter() {
                    d = dbl(u128::from_be_bytes(d)).to_be_bytes();
                    let d2 = self.cmac(aad, None);

                    xor_si128_inplace(&mut d, &d2);
                }

                let plen = payload.len();
                if plen < Self::BLOCK_LEN {
                    // T = dbl(D) xor pad(Sn)
                    let mut t = dbl(u128::from_be_bytes(d)).to_be_bytes();

                    for i in 0..plen {
                        t[i] ^= payload[i];
                    }
                    t[plen] ^= 0b1000_0000;

                    return self.cmac(&t, None);
                } else if plen == Self::BLOCK_LEN {
                    let mut block = [0u8; Self::BLOCK_LEN];
                    block.copy_from_slice(payload);

                    xor_si128_inplace(&mut block, &d);
                    return self.cmac(&block, None);
                } else if plen > Self::BLOCK_LEN {
                    let n = plen - Self::BLOCK_LEN;
                    
                    let m1 = &payload[..n];
                    let mut m2 = [0u8; Self::BLOCK_LEN];
                    m2.copy_from_slice(&payload[n..]);

                    xor_si128_inplace(&mut m2, &d);
                    return self.cmac(&m1, Some(&m2));
                } else {
                    unreachable!()
                }
            }

            // NOTE: 
            //      SIV 分组模式的加密分为2种：
            // 
            //      1. Nonce-Based Authenticated Encryption with SIV
            //      2. Deterministic Authenticated Encryption with SIV
            // 
            // 其中 `Nonce-Based Authenticated Encryption with SIV` 模式比
            // `Deterministic Authenticated Encryption with SIV` 多了一个参数叫做 `nonce`，
            // 这里不再为这种模式提供独立的接口，`nonce` 数据应该放在 `components` 列表里面的最后一项。
            // 
            // SIV 分组工作模式的 Packet 跟其它的AEAD模式有些许不同，为：`V || Plaintext`
            pub fn encrypt_slice(&self, components: &[&[u8]], aead_pkt: &mut [u8]) {
                debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

                let (tag_out, plaintext_and_ciphertext) = aead_pkt.split_at_mut(Self::TAG_LEN);

                self.encrypt_slice_detached(components, plaintext_and_ciphertext, tag_out)
            }

            // SIV 分组工作模式的 Packet 跟其它的AEAD模式有些许不同，为：`V || Ciphertext`
            pub fn decrypt_slice(&self, components: &[&[u8]], aead_pkt: &mut [u8]) -> bool {
                debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

                let (tag_in, ciphertext_and_plaintext) = aead_pkt.split_at_mut(Self::TAG_LEN);

                self.decrypt_slice_detached(components, ciphertext_and_plaintext, &tag_in)
            }

            pub fn encrypt_slice_detached(&self, components: &[&[u8]], plaintext_and_ciphertext: &mut [u8], tag_out: &mut [u8]) {
                let plen = plaintext_and_ciphertext.len();
                let tlen = tag_out.len();

                debug_assert!(plen <= Self::P_MAX);
                debug_assert!(tlen == Self::TAG_LEN);

                assert!(components.len() < Self::COMPONENTS_MAX);

                // V = S2V(K1, AD1, ..., ADn, P)
                let v = self.siv(components, &plaintext_and_ciphertext);
                // Q = V bitand (1^64 || 0^1 || 1^31 || 0^1 || 1^31)
                let mut q = v.clone();
                and_si128_inplace(&mut q, &Self::V1);

                // CTR Counter
                let mut counter = u128::from_be_bytes(q);

                let n = plen / Self::BLOCK_LEN;
                for i in 0..n {
                    let chunk = &mut plaintext_and_ciphertext[i * Self::BLOCK_LEN..i * Self::BLOCK_LEN + Self::BLOCK_LEN];

                    let mut keystream_block = counter.to_be_bytes();
                    self.cipher.encrypt(&mut keystream_block);

                    xor_si128_inplace(chunk, &keystream_block);

                    counter = counter.wrapping_add(1);
                }

                if plen % Self::BLOCK_LEN != 0 {
                    let rem = &mut plaintext_and_ciphertext[n * Self::BLOCK_LEN..];
                    let rlen = rem.len();

                    let mut keystream_block = counter.to_be_bytes();
                    self.cipher.encrypt(&mut keystream_block);

                    for i in 0..rlen {
                        rem[i] ^= keystream_block[i];
                    }

                    // counter = counter.wrapping_add(1);
                }
                
                tag_out.copy_from_slice(&v[..Self::TAG_LEN]);
            }

            pub fn decrypt_slice_detached(&self, components: &[&[u8]], ciphertext_and_plaintext: &mut [u8], tag_in: &[u8]) -> bool {
                let clen = ciphertext_and_plaintext.len();
                let tlen = tag_in.len();

                debug_assert!(clen <= Self::P_MAX);
                debug_assert!(tlen == Self::TAG_LEN);

                assert!(components.len() < Self::COMPONENTS_MAX);

                let mut q = [0u8; Self::BLOCK_LEN];
                q[..Self::TAG_LEN].copy_from_slice(tag_in);
                and_si128_inplace(&mut q, &Self::V1);

                // CTR Counter
                let mut counter = u128::from_be_bytes(q);

                let n = clen / Self::BLOCK_LEN;
                for i in 0..n {
                    let chunk = &mut ciphertext_and_plaintext[i * Self::BLOCK_LEN..i * Self::BLOCK_LEN + Self::BLOCK_LEN];

                    let mut keystream_block = counter.to_be_bytes();
                    self.cipher.encrypt(&mut keystream_block);

                    xor_si128_inplace(chunk, &keystream_block);

                    counter = counter.wrapping_add(1);
                }

                if clen % Self::BLOCK_LEN != 0 {
                    let rem = &mut ciphertext_and_plaintext[n * Self::BLOCK_LEN..];
                    let rlen = rem.len();

                    let mut keystream_block = counter.to_be_bytes();
                    self.cipher.encrypt(&mut keystream_block);

                    for i in 0..rlen {
                        rem[i] ^= keystream_block[i];
                    }

                    // counter = counter.wrapping_add(1);
                }

                // T = S2V(K1, AD1, ..., ADn, P)
                let tag = self.siv(components, &ciphertext_and_plaintext);
                
                // Verify
                constant_time_eq(tag_in, &tag[..Self::TAG_LEN])
            }
        }
    }
}

impl_block_cipher_with_siv_cmac_mode!(AesSivCmac256, Aes128);
impl_block_cipher_with_siv_cmac_mode!(AesSivCmac384, Aes192);
impl_block_cipher_with_siv_cmac_mode!(AesSivCmac512, Aes256);


#[test]
fn test_aes128_cmac() {
    // NOTE: CMAC-KEY 为 前面的一半。
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c\
fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0").unwrap();
    
    let cipher = AesSivCmac256::new(&key);

    let k1 = &cipher.cmac_k1;
    let k2 = &cipher.cmac_k2;
    assert_eq!(&k1[..], &hex::decode("fbeed618357133667c85e08f7236a8de").unwrap()[..]);
    assert_eq!(&k2[..], &hex::decode("f7ddac306ae266ccf90bc11ee46d513b").unwrap()[..]);

    let m = hex::decode("").unwrap();
    let tag = cipher.cmac(&m, None);
    assert_eq!(&tag[..], &hex::decode("bb1d6929e95937287fa37d129b756746").unwrap()[..] );

    let m = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let tag = cipher.cmac(&m, None);
    assert_eq!(&tag[..], &hex::decode("070a16b46b4d4144f79bdd9dd04a287c").unwrap()[..] );

    let m = hex::decode("6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411").unwrap();
    let tag = cipher.cmac(&m, None);
    assert_eq!(&tag[..], &hex::decode("dfa66747de9ae63030ca32611497c827").unwrap()[..] );

    let m = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710").unwrap();
    let tag = cipher.cmac(&m, None);
    assert_eq!(&tag[..], &hex::decode("51f0bebf7e3b9d92fc49741779363cfe").unwrap()[..] );
}

#[test]
fn test_aes_siv_cmac256_dec() {
    let key       = hex::decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0\
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
    let aad       = hex::decode("101112131415161718191a1b1c1d1e1f\
2021222324252627").unwrap();
    let plaintext = hex::decode("112233445566778899aabbccddee").unwrap();
    let mut ciphertext_and_tag = hex::decode("85632d07c6e8f37f950acd320a2ecc93\
40c02b9690c4dc04daef7f6afe5c").unwrap();

    let cipher = AesSivCmac256::new(&key);
    let ret = cipher.decrypt_slice(&[&aad], &mut ciphertext_and_tag);
    assert_eq!(ret, true);
    assert_eq!(&ciphertext_and_tag[AesSivCmac256::TAG_LEN..], &plaintext[..]);
}

#[test]
fn test_aes_siv_cmac256_enc() {
    // A.1.  Deterministic Authenticated Encryption Example
    // https://tools.ietf.org/html/rfc5297#appendix-A.1
    let key       = hex::decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0\
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
    let aad       = hex::decode("101112131415161718191a1b1c1d1e1f\
2021222324252627").unwrap();
    let plaintext = hex::decode("112233445566778899aabbccddee").unwrap();

    // NOTE: Layout = IV || C
    let mut ciphertext_and_tag = plaintext.clone();
    for _ in 0..AesSivCmac256::TAG_LEN {
        ciphertext_and_tag.insert(0, 0);
    }

    let cipher = AesSivCmac256::new(&key);
    cipher.encrypt_slice(&[&aad], &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..],
        &hex::decode("85632d07c6e8f37f950acd320a2ecc93\
40c02b9690c4dc04daef7f6afe5c").unwrap()[..]);

    
    // A.2.  Nonce-Based Authenticated Encryption Example
    // https://tools.ietf.org/html/rfc5297#appendix-A.2
    let key       = hex::decode("7f7e7d7c7b7a79787776757473727170\
404142434445464748494a4b4c4d4e4f").unwrap();
    let ad1       = hex::decode("\
00112233445566778899aabbccddeeff\
deaddadadeaddadaffeeddccbbaa9988\
7766554433221100").unwrap();
    let ad2       = hex::decode("102030405060708090a0").unwrap();
    let nonce     = hex::decode("09f911029d74e35bd84156c5635688c0").unwrap();
    let plaintext = hex::decode("7468697320697320736f6d6520706c61\
696e7465787420746f20656e63727970\
74207573696e67205349562d414553").unwrap();
    // NOTE: Layout = IV || C
    let mut ciphertext_and_tag = plaintext.clone();
    for _ in 0..AesSivCmac256::TAG_LEN {
        ciphertext_and_tag.insert(0, 0);
    }
    let cipher = AesSivCmac256::new(&key);
    cipher.encrypt_slice(&[&ad1, &ad2, &nonce], &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("7bdb6e3b432667eb06f4d14bff2fbd0f\
cb900f2fddbe404326601965c889bf17\
dba77ceb094fa663b7a3f748ba8af829\
ea64ad544a272e9c485b62a3fd5c0d").unwrap()[..]);
}




// TODO: 将来考虑将 Cmac 独立出来？
