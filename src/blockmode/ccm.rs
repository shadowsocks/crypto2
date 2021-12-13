// Counter with CBC-MAC (CCM)
// https://tools.ietf.org/html/rfc3610
//
// Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
//
// CCM
// Counter with Cipher Block Chaining-Message Authentication Code.
//
// CBC-MAC
// Cipher Block Chaining-Message Authentication Code
use crate::blockcipher::{Aes128, Aes256, Aria128, Aria256, Camellia128, Camellia256, Sm4};
use crate::mem::constant_time_eq;
use crate::util::xor_si128_inplace;

macro_rules! impl_block_cipher_with_ccm_mode {
    ($name:tt, $cipher:tt, $nlen:tt, $tlen:tt, $q:tt) => {
        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
        }

        // 6.  AES GCM Algorithms for Secure Shell
        // https://tools.ietf.org/html/rfc5647#section-6
        impl $name {
            pub const KEY_LEN: usize = $cipher::KEY_LEN;
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const NONCE_LEN: usize = $nlen;
            pub const TAG_LEN: usize = $tlen;

            #[cfg(target_pointer_width = "64")]
            pub const A_MAX: usize = usize::MAX; // 2^64 - 1
            #[cfg(target_pointer_width = "32")]
            pub const A_MAX: usize = usize::MAX; // 2^32 - 1

            pub const P_MAX: usize = 16777215; // 2^24 - 1
            pub const C_MAX: usize = Self::P_MAX + Self::TAG_LEN; // 2^24 + 15

            pub const N_MIN: usize = Self::NONCE_LEN;
            pub const N_MAX: usize = Self::NONCE_LEN;

            // Parameter L
            pub const Q: u8 = $q;
            // the size of the authentication field.
            // Valid values are 4, 6, 8, 10, 12, 14, and 16 octets.
            pub const M: u8 = (Self::TAG_LEN as u8 - 2) / 2; // (M-2)/2
                                                             // the size of the length field.
                                                             // This value requires a trade-off between the maximum message size and the size of the Nonce.
                                                             // Valid values of L range between 2 octets and 8 octets
                                                             // (the value L=1 is reserved).
                                                             // ParameterL - 1
            pub const L: u8 = Self::Q - 1;

            pub fn new(key: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);

                let cipher = $cipher::new(key);

                Self { cipher }
            }

            // CBC-Mac
            #[inline]
            fn cbc_mac(&self, nonce: &[u8], aad: &[u8], m: &[u8]) -> [u8; Self::BLOCK_LEN] {
                let alen = aad.len();
                let mlen = m.len();

                let mut b0 = [0u8; Self::BLOCK_LEN];
                // Octet Number   Contents
                // ------------   ---------
                // 0              Flags
                // 1 ... 15-L     Nonce N
                // 16-L ... 15    l(m)
                //
                // Within the first block B_0, the Flags field is formatted as follows:
                //
                // Bit Number   Contents
                // ----------   ----------------------
                // 7            Reserved (always zero)
                // 6            Adata
                // 5 ... 3      M'
                // 2 ... 0      L'
                //
                // The Reserved bit is reserved for future expansions and should always be set to zero.
                // The Adata bit is set to zero if l(a)=0, and set to one if l(a)>0.
                //
                let adata_bit = if alen == 0 {
                    0b_0000_0000
                } else {
                    0b_0100_0000
                };
                let m_bit = Self::M << 3; // 3-bit
                let l_bit = Self::L;

                b0[0] = adata_bit | m_bit | l_bit; // Flags
                b0[1..Self::NONCE_LEN + 1].copy_from_slice(nonce); // Nonce N

                let n = Self::BLOCK_LEN - (Self::NONCE_LEN + 1);
                let mlen_octets = mlen.to_be_bytes();
                let offset = mlen_octets.len() - n;
                b0[Self::NONCE_LEN + 1..].copy_from_slice(&mlen_octets[offset..]); // l(m)

                // Auth Tag
                let mut tag = b0;
                self.cipher.encrypt(&mut tag);

                let mut block = [0u8; Self::BLOCK_LEN];

                // Associated Data
                if alen > 0 {
                    let mut n = 0usize;
                    if alen < 65280 {
                        // 0 < l(a) < (2^16 - 2^8)
                        n = 2;
                        block[0..2].copy_from_slice(&(alen as u16).to_be_bytes());
                    } else if alen <= core::u32::MAX as usize {
                        // (2^16 - 2^8) <= l(a) < 2^32
                        n = 6;
                        block[0] = 0xFF;
                        block[1] = 0xFE;
                        block[2..6].copy_from_slice(&(alen as u32).to_be_bytes());
                    } else {
                        // 2^32 <= l(a) < 2^64
                        if cfg!(target_pointer_width = "64") {
                            n = 10;
                            block[0] = 0xFF;
                            block[1] = 0xFF;
                            block[2..10].copy_from_slice(&(alen as u64).to_be_bytes());
                        } else {
                            unreachable!()
                        }
                    }

                    let r = block.len() - n;
                    if r >= alen {
                        block[n..n + alen].copy_from_slice(aad);

                        xor_si128_inplace(&mut tag, &block);

                        self.cipher.encrypt(&mut tag);
                    } else {
                        block[n..].copy_from_slice(&aad[..Self::BLOCK_LEN - n]);

                        xor_si128_inplace(&mut tag, &block);
                        self.cipher.encrypt(&mut tag);

                        let aad = &aad[r..];
                        let n = aad.len() / Self::BLOCK_LEN;
                        for i in 0..n {
                            let chunk =
                                &aad[i * Self::BLOCK_LEN..i * Self::BLOCK_LEN + Self::BLOCK_LEN];
                            xor_si128_inplace(&mut tag, chunk);
                            self.cipher.encrypt(&mut tag);
                        }

                        if aad.len() % Self::BLOCK_LEN != 0 {
                            let rem = &aad[n * Self::BLOCK_LEN..];
                            let rlen = rem.len();

                            let mut last_block = [0u8; Self::BLOCK_LEN];
                            last_block[..rlen].copy_from_slice(rem);

                            xor_si128_inplace(&mut tag, &last_block);
                            self.cipher.encrypt(&mut tag);
                        }
                    }
                }

                // Payload
                let mlen = m.len();
                let n = mlen / Self::BLOCK_LEN;
                for i in 0..n {
                    let chunk = &m[i * Self::BLOCK_LEN..i * Self::BLOCK_LEN + Self::BLOCK_LEN];
                    xor_si128_inplace(&mut tag, chunk);
                    self.cipher.encrypt(&mut tag);
                }

                if mlen % Self::BLOCK_LEN != 0 {
                    let rem = &m[n * Self::BLOCK_LEN..];
                    let rlen = rem.len();

                    let mut last_block = [0u8; Self::BLOCK_LEN];
                    last_block[..rlen].copy_from_slice(rem);

                    xor_si128_inplace(&mut tag, &last_block);
                    self.cipher.encrypt(&mut tag);
                }

                tag
            }

            // formatting function (encoding function)
            #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
            #[inline]
            fn ctr(nonce: &[u8], block: &mut [u8; Self::BLOCK_LEN], block_idx: usize) {
                block[0] = Self::L; // Flags
                block[1..Self::NONCE_LEN + 1].copy_from_slice(nonce); // Nonce N

                // Counter i
                let b = &mut block[Self::NONCE_LEN + 1..];
                let block_idx_octets = block_idx.to_be_bytes();
                // NOTE: 4 Bytes or 8 Bytes
                let block_idx_octets_len = core::mem::size_of::<usize>();

                let offset = block_idx_octets_len - b.len();
                b.copy_from_slice(&block_idx_octets[offset..]);
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
                let (ciphertext_and_plaintext, tag_in) = aead_pkt.split_at_mut(clen);

                self.decrypt_slice_detached(nonce, aad, ciphertext_and_plaintext, &tag_in)
            }

            pub fn encrypt_slice_detached(
                &self,
                nonce: &[u8],
                aad: &[u8],
                plaintext_in_ciphertext_out: &mut [u8],
                tag_out: &mut [u8],
            ) {
                assert_eq!(nonce.len(), Self::NONCE_LEN);

                let alen = aad.len();
                let plen = plaintext_in_ciphertext_out.len();
                let tlen = tag_out.len();

                debug_assert!(alen <= Self::A_MAX);
                debug_assert!(plen <= Self::P_MAX);
                debug_assert!(tlen == Self::TAG_LEN);

                let mut tag = self.cbc_mac(nonce, aad, &plaintext_in_ciphertext_out);

                let mut counter_block = [0u8; Self::BLOCK_LEN];

                Self::ctr(nonce, &mut counter_block, 0);
                self.cipher.encrypt(&mut counter_block);
                xor_si128_inplace(&mut tag, &counter_block);

                let n = plen / Self::BLOCK_LEN;
                for i in 0..n {
                    let chunk = &mut plaintext_in_ciphertext_out
                        [i * Self::BLOCK_LEN..i * Self::BLOCK_LEN + Self::BLOCK_LEN];

                    Self::ctr(nonce, &mut counter_block, i + 1);
                    self.cipher.encrypt(&mut counter_block);

                    xor_si128_inplace(chunk, &counter_block);
                }

                if plen % Self::BLOCK_LEN != 0 {
                    let rem = &mut plaintext_in_ciphertext_out[n * Self::BLOCK_LEN..];
                    let rlen = rem.len();

                    Self::ctr(nonce, &mut counter_block, n + 1);
                    self.cipher.encrypt(&mut counter_block);

                    for i in 0..rlen {
                        rem[i] ^= counter_block[i];
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
                assert_eq!(nonce.len(), Self::NONCE_LEN);

                let alen = aad.len();
                let clen = ciphertext_in_plaintext_out.len();
                let tlen = tag_in.len();

                debug_assert!(alen <= Self::A_MAX);
                debug_assert!(clen <= Self::P_MAX);
                debug_assert!(tlen == Self::TAG_LEN);

                let mut counter_block = [0u8; Self::BLOCK_LEN];

                Self::ctr(nonce, &mut counter_block, 0);
                self.cipher.encrypt(&mut counter_block);

                let b0 = counter_block.clone();

                let n = clen / Self::BLOCK_LEN;
                for i in 0..n {
                    let chunk = &mut ciphertext_in_plaintext_out
                        [i * Self::BLOCK_LEN..i * Self::BLOCK_LEN + Self::BLOCK_LEN];

                    Self::ctr(nonce, &mut counter_block, i + 1);
                    self.cipher.encrypt(&mut counter_block);

                    xor_si128_inplace(chunk, &counter_block);
                }

                if clen % Self::BLOCK_LEN != 0 {
                    let rem = &mut ciphertext_in_plaintext_out[n * Self::BLOCK_LEN..];
                    let rlen = rem.len();

                    Self::ctr(nonce, &mut counter_block, n + 1);
                    self.cipher.encrypt(&mut counter_block);

                    for i in 0..rlen {
                        rem[i] ^= counter_block[i];
                    }
                }

                let mut tag = self.cbc_mac(nonce, aad, &ciphertext_in_plaintext_out);
                xor_si128_inplace(&mut tag, &b0);

                // Verify
                constant_time_eq(tag_in, &tag[..Self::TAG_LEN])
            }
        }
    };
}

// NOTE: 测试案例里面的 Nonce-Len 和 Tag-Len 跟 AEAD 里面的不一样，
//       所以 `Aes128CcmNLen13TagLen8` 和 `Aes128CcmNLen13TagLen12`
//       只是为了通过测试案例的数据而定义。
#[cfg(test)]
impl_block_cipher_with_ccm_mode!(Aes128CcmNLen13TagLen8, Aes128, 13, 8, 2); // NONCE-LEN=13, TAG-LEN= 8, Q=2
#[cfg(test)]
impl_block_cipher_with_ccm_mode!(Aes128CcmNLen13TagLen10, Aes128, 13, 10, 2); // NONCE-LEN=13, TAG-LEN=10, Q=2

// 3            AEAD_AES_128_CCM            [RFC5116]
impl_block_cipher_with_ccm_mode!(Aes128Ccm, Aes128, 12, 16, 3); // NONCE-LEN=12, TAG-LEN=16, Q=3
                                                                // 9            AEAD_AES_128_CCM_SHORT      [RFC5282]
impl_block_cipher_with_ccm_mode!(Aes128CcmShort, Aes128, 11, 16, 3); // NONCE-LEN=11, TAG-LEN=16, Q=3
                                                                     // 11           AEAD_AES_128_CCM_SHORT_8    [RFC5282]
impl_block_cipher_with_ccm_mode!(Aes128CcmShort8, Aes128, 11, 8, 3); // NONCE-LEN=11, TAG-LEN= 8, Q=3
                                                                     // 13           AEAD_AES_128_CCM_SHORT_12   [RFC5282]
impl_block_cipher_with_ccm_mode!(Aes128CcmShort12, Aes128, 11, 12, 3); // NONCE-LEN=11, TAG-LEN=12, Q=3
                                                                       // 18           AEAD_AES_128_CCM_8          [RFC6655]
impl_block_cipher_with_ccm_mode!(Aes128Ccm8, Aes128, 12, 8, 3); // NONCE-LEN=12, TAG-LEN= 8, Q=3

// 3            AEAD_AES_128_CCM            [RFC5116]
impl_block_cipher_with_ccm_mode!(Aes256Ccm, Aes256, 12, 16, 3); // NONCE-LEN=12, TAG-LEN=16, Q=3
                                                                // 9            AEAD_AES_128_CCM_SHORT      [RFC5282]
impl_block_cipher_with_ccm_mode!(Aes256CcmShort, Aes256, 11, 16, 3); // NONCE-LEN=11, TAG-LEN=16, Q=3
                                                                     // 11           AEAD_AES_128_CCM_SHORT_8    [RFC5282]
impl_block_cipher_with_ccm_mode!(Aes256CcmShort8, Aes256, 11, 8, 3); // NONCE-LEN=11, TAG-LEN= 8, Q=3
                                                                     // 13           AEAD_AES_128_CCM_SHORT_12   [RFC5282]
impl_block_cipher_with_ccm_mode!(Aes256CcmShort12, Aes256, 11, 12, 3); // NONCE-LEN=11, TAG-LEN=12, Q=3
                                                                       // 18           AEAD_AES_128_CCM_8          [RFC6655]
impl_block_cipher_with_ccm_mode!(Aes256Ccm8, Aes256, 12, 8, 3); // NONCE-LEN=12, TAG-LEN= 8, Q=3

impl_block_cipher_with_ccm_mode!(Sm4Ccm, Sm4, 12, 16, 3); // NONCE-LEN=12, TAG-LEN=16, Q=3
impl_block_cipher_with_ccm_mode!(Camellia128Ccm, Camellia128, 12, 16, 3); // NONCE-LEN=12, TAG-LEN=16, Q=3
impl_block_cipher_with_ccm_mode!(Aria128Ccm, Aria128, 12, 16, 3); // NONCE-LEN=12, TAG-LEN=16, Q=3
impl_block_cipher_with_ccm_mode!(Camellia256Ccm, Camellia256, 12, 16, 3); // NONCE-LEN=12, TAG-LEN=16, Q=3
impl_block_cipher_with_ccm_mode!(Aria256Ccm, Aria256, 12, 16, 3); // NONCE-LEN=12, TAG-LEN=16, Q=3

#[cfg(test)]
fn hex_decode<T: AsRef<str>>(s: T) -> Vec<u8> {
    let h = s
        .as_ref()
        .replace(" ", "")
        .replace("\n", "")
        .replace("\r", "");
    hex::decode(&h).unwrap()
}

#[test]
fn test_aes128_ccm_nlen_13_taglen_8_dec() {
    let key = hex_decode("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF");
    let nonce = hex_decode("00 00 00 03  02 01 00 A0  A1 A2 A3 A4  A5");
    let aad = hex_decode("00 01 02 03 04 05 06 07");
    let plaintext = hex_decode(
        "08 09 0A 0B  0C 0D 0E 0F
    10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen8::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen8::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "58 8C 97 9A  61 C6 63 D2
    F0 66 D0 C2  C0 F9 89 80  6D 5F 6B 61  DA C3 84 17
    E8 D1 2C FD  F9 26 E0"
        )[..]
    );

    cipher.decrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..plen], &plaintext[..]);
}

#[test]
fn test_aes128_ccm_nlen_13_taglen_8() {
    // 8.  Test Vectors
    // https://tools.ietf.org/html/rfc3610#section-8

    // Packet Vector #1
    let key = hex_decode("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF");
    let nonce = hex_decode("00 00 00 03  02 01 00 A0  A1 A2 A3 A4  A5");
    let aad = hex_decode("00 01 02 03 04 05 06 07");
    let plaintext = hex_decode(
        "08 09 0A 0B  0C 0D 0E 0F
    10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen8::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen8::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "58 8C 97 9A  61 C6 63 D2
    F0 66 D0 C2  C0 F9 89 80  6D 5F 6B 61  DA C3 84 17
    E8 D1 2C FD  F9 26 E0"
        )[..]
    );

    // Packet Vector #2
    let key = hex_decode("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF");
    let nonce = hex_decode("00 00 00 04  03 02 01 A0  A1 A2 A3 A4  A5");
    let aad = hex_decode("00 01 02 03  04 05 06 07");
    let plaintext = hex_decode(
        "08 09 0A 0B  0C 0D 0E 0F
    10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen8::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen8::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "72 C9 1A 36  E1 35 F8 CF
    29 1C A8 94  08 5C 87 E3  CC 15 C4 39  C9 E4 3A 3B
    A0 91 D5 6E  10 40 09 16"
        )[..]
    );

    // Packet Vector #3
    let key = hex_decode("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF");
    let nonce = hex_decode("00 00 00 05  04 03 02 A0  A1 A2 A3 A4  A5");
    let aad = hex_decode("00 01 02 03  04 05 06 07");
    let plaintext = hex_decode(
        "08 09 0A 0B  0C 0D 0E 0F
    10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F
    20",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen8::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen8::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "51 B1 E5 F4  4A 19 7D 1D
    A4 6B 0F 8E  2D 28 2A E8  71 E8 38 BB  64 DA 85 96
    57 4A DA A7  6F BD 9F B0  C5"
        )[..]
    );

    // Packet Vector #4
    let key = hex_decode("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF");
    let nonce = hex_decode("00 00 00 06  05 04 03 A0  A1 A2 A3 A4  A5");
    let aad = hex_decode("00 01 02 03  04 05 06 07  08 09 0A 0B");
    let plaintext = hex_decode(
        "0C 0D 0E 0F
    10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen8::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen8::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "A2 8C 68 65
    93 9A 9A 79  FA AA 5C 4C  2A 9D 4A 91  CD AC 8C 96
    C8 61 B9 C9  E6 1E F1"
        )[..]
    );

    // Packet Vector #5
    let key = hex_decode("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF");
    let nonce = hex_decode("00 00 00 07  06 05 04 A0  A1 A2 A3 A4  A5");
    let aad = hex_decode("00 01 02 03  04 05 06 07  08 09 0A 0B");
    let plaintext = hex_decode("0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F");
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen8::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen8::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "DC F1 FB 7B
    5D 9E 23 FB  9D 4E 13 12  53 65 8A D8  6E BD CA 3E
    51 E8 3F 07  7D 9C 2D 93"
        )[..]
    );

    // Packet Vector #6
    let key = hex_decode("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF");
    let nonce = hex_decode("00 00 00 08  07 06 05 A0  A1 A2 A3 A4  A5");
    let aad = hex_decode("00 01 02 03  04 05 06 07  08 09 0A 0B");
    let plaintext =
        hex_decode("0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F  20");
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen8::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen8::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "6F C1 B0 11
    F0 06 56 8B  51 71 A4 2D  95 3D 46 9B  25 70 A4 BD
    87 40 5A 04  43 AC 91 CB  94"
        )[..]
    );

    // Packet Vector #13
    let key = hex_decode("D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B");
    let nonce = hex_decode("00 41 2B 4E  A9 CD BE 3C  96 96 76 6C  FA");
    let aad = hex_decode("0B E1 A8 8B  AC E0 18 B1");
    let plaintext = hex_decode(
        "08 E8 CF 97  D8 20 EA 25
    84 60 E9 6A  D9 CF 52 89  05 4D 89 5C  EA C4 7C",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen8::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen8::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "4C B9 7F 86  A2 A4 68 9A
    87 79 47 AB  80 91 EF 53  86 A6 FF BD  D0 80 F8 E7
    8C F7 CB 0C  DD D7 B3"
        )[..]
    );

    // Packet Vector #14
    let key = hex_decode("D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B");
    let nonce = hex_decode("00 33 56 8E  F7 B2 63 3C  96 96 76 6C  FA");
    let aad = hex_decode("63 01 8F 76  DC 8A 1B CB");
    let plaintext = hex_decode(
        "90 20 EA 6F  91 BD D8 5A
    FA 00 39 BA  4B AF F9 BF  B7 9C 70 28  94 9C D0 EC",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen8::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen8::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "4C CB 1E 7C  A9 81 BE FA
    A0 72 6C 55  D3 78 06 12  98 C8 5C 92  81 4A BC 33
    C5 2E E8 1D  7D 77 C0 8A"
        )[..]
    );

    // Packet Vector #15
    let key = hex_decode("D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B");
    let nonce = hex_decode("00 10 3F E4  13 36 71 3C  96 96 76 6C  FA");
    let aad = hex_decode("AA 6C FA 36  CA E8 6B 40");
    let plaintext = hex_decode(
        "B9 16 E0 EA  CC 1C 00 D7
    DC EC 68 EC  0B 3B BB 1A  02 DE 8A 2D  1A A3 46 13
    2E",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen8::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen8::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "B1 D2 3A 22  20 DD C0 AC
    90 0D 9A A0  3C 61 FC F4  A5 59 A4 41  77 67 08 97
    08 A7 76 79  6E DB 72 35  06"
        )[..]
    );

    // Packet Vector #16
    let key = hex_decode("D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B");
    let nonce = hex_decode("00 76 4C 63  B8 05 8E 3C  96 96 76 6C  FA");
    let aad = hex_decode("D0 D0 73 5C  53 1E 1B EC  F0 49 C2 44");
    let plaintext = hex_decode(
        "12 DA AC 56
    30 EF A5 39  6F 77 0C E1  A6 6B 21 F7  B2 10 1C",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen8::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen8::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "14 D2 53 C3
    96 7B 70 60  9B 7C BB 7C  49 91 60 28  32 45 26 9A
    6F 49 97 5B  CA DE AF"
        )[..]
    );

    // Packet Vector #17
    let key = hex_decode("D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B");
    let nonce = hex_decode("00 F8 B6 78  09 4E 3B 3C  96 96 76 6C  FA");
    let aad = hex_decode("77 B6 0F 01  1C 03 E1 52  58 99 BC AE");
    let plaintext = hex_decode(
        "E8 8B 6A 46
    C7 8D 63 E5  2E B8 C5 46  EF B5 DE 6F  75 E9 CC 0D",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen8::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen8::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "55 45 FF 1A
    08 5E E2 EF  BF 52 B2 E0  4B EE 1E 23  36 C7 3E 3F
    76 2C 0C 77  44 FE 7E 3C"
        )[..]
    );

    // Packet Vector #18
    let key = hex_decode("D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B");
    let nonce = hex_decode("00 D5 60 91  2D 3F 70 3C  96 96 76 6C  FA");
    let aad = hex_decode("CD 90 44 D2  B7 1F DB 81  20 EA 60 C0");
    let plaintext = hex_decode(
        "64 35 AC BA
    FB 11 A8 2E  2F 07 1D 7C  A4 A5 EB D9  3A 80 3B A8
    7F",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen8::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen8::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "00 97 69 EC
    AB DF 48 62  55 94 C5 92  51 E6 03 57  22 67 5E 04
    C8 47 09 9E  5A E0 70 45  51"
        )[..]
    );
}

#[test]
fn test_aes128_ccm_nlen_13_taglen_10() {
    // Packet Vector #7
    let key = hex_decode("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF");
    let nonce = hex_decode("00 00 00 09  08 07 06 A0  A1 A2 A3 A4  A5");
    let aad = hex_decode("00 01 02 03  04 05 06 07");
    let plaintext = hex_decode(
        "08 09 0A 0B  0C 0D 0E 0F
    10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen10::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen10::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "01 35 D1 B2  C9 5F 41 D5
    D1 D4 FE C1  85 D1 66 B8  09 4E 99 9D  FE D9 6C 04
    8C 56 60 2C  97 AC BB 74  90"
        )[..]
    );

    // Packet Vector #8
    let key = hex_decode("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF");
    let nonce = hex_decode("00 00 00 0A  09 08 07 A0  A1 A2 A3 A4  A5");
    let aad = hex_decode("00 01 02 03  04 05 06 07");
    let plaintext = hex_decode(
        "08 09 0A 0B  0C 0D 0E 0F
    10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen10::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen10::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "7B 75 39 9A  C0 83 1D D2
    F0 BB D7 58  79 A2 FD 8F  6C AE 6B 6C  D9 B7 DB 24
    C1 7B 44 33  F4 34 96 3F  34 B4"
        )[..]
    );

    // Packet Vector #9
    let key = hex_decode("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF");
    let nonce = hex_decode("00 00 00 0B  0A 09 08 A0  A1 A2 A3 A4  A5");
    let aad = hex_decode("00 01 02 03  04 05 06 07");
    let plaintext = hex_decode(
        "08 09 0A 0B  0C 0D 0E 0F
    10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F
    20",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen10::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen10::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "82 53 1A 60  CC 24 94 5A
    4B 82 79 18  1A B5 C8 4D  F2 1C E7 F9  B7 3F 42 E1
    97 EA 9C 07  E5 6B 5E B1  7E 5F 4E"
        )[..]
    );

    // Packet Vector #10
    let key = hex_decode("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF");
    let nonce = hex_decode("00 00 00 0C  0B 0A 09 A0  A1 A2 A3 A4  A5");
    let aad = hex_decode("00 01 02 03  04 05 06 07  08 09 0A 0B");
    let plaintext = hex_decode(
        "0C 0D 0E 0F
    10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen10::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen10::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "07 34 25 94
    15 77 85 15  2B 07 40 98  33 0A BB 14  1B 94 7B 56
    6A A9 40 6B  4D 99 99 88  DD"
        )[..]
    );

    // Packet Vector #11
    let key = hex_decode("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF");
    let nonce = hex_decode("00 00 00 0D  0C 0B 0A A0  A1 A2 A3 A4  A5");
    let aad = hex_decode("00 01 02 03  04 05 06 07  08 09 0A 0B");
    let plaintext = hex_decode(
        "0C 0D 0E 0F
    10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen10::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen10::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "67 6B B2 03
    80 B0 E3 01  E8 AB 79 59  0A 39 6D A7  8B 83 49 34
    F5 3A A2 E9  10 7A 8B 6C  02 2C"
        )[..]
    );

    // Packet Vector #12
    let key = hex_decode("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF");
    let nonce = hex_decode("00 00 00 0E  0D 0C 0B A0  A1 A2 A3 A4  A5");
    let aad = hex_decode("00 01 02 03  04 05 06 07  08 09 0A 0B");
    let plaintext = hex_decode(
        "0C 0D 0E 0F
    10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F
    20",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen10::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen10::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "C0 FF A0 D6
    F0 5B DB 67  F2 4D 43 A4  33 8D 2A A4  BE D7 B2 0E
    43 CD 1A A3  16 62 E7 AD  65 D6 DB"
        )[..]
    );

    // Packet Vector #19
    let key = hex_decode("D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B");
    let nonce = hex_decode("00 42 FF F8  F1 95 1C 3C  96 96 76 6C  FA");
    let aad = hex_decode("D8 5B C7 E6  9F 94 4F B8");
    let plaintext = hex_decode(
        "8A 19 B9 50  BC F7 1A 01
    8E 5E 67 01  C9 17 87 65  98 09 D6 7D  BE DD 18",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen10::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen10::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "BC 21 8D AA  94 74 27 B6
    DB 38 6A 99  AC 1A EF 23  AD E0 B5 29  39 CB 6A 63
    7C F9 BE C2  40 88 97 C6  BA"
        )[..]
    );

    // Packet Vector #20
    let key = hex_decode("D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B");
    let nonce = hex_decode("00 92 0F 40  E5 6C DC 3C  96 96 76 6C  FA");
    let aad = hex_decode("74 A0 EB C9  06 9F 5B 37");
    let plaintext = hex_decode(
        "17 61 43 3C  37 C5 A3 5F
    C1 F3 9F 40  63 02 EB 90  7C 61 63 BE  38 C9 84 37",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen10::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen10::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "58 10 E6 FD  25 87 40 22
    E8 03 61 A4  78 E3 E9 CF  48 4A B0 4F  44 7E FF F6
    F0 A4 77 CC  2F C9 BF 54  89 44"
        )[..]
    );

    // Packet Vector #21
    let key = hex_decode("D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B");
    let nonce = hex_decode("00 27 CA 0C  71 20 BC 3C  96 96 76 6C  FA");
    let aad = hex_decode("44 A3 AA 3A  AE 64 75 CA");
    let plaintext = hex_decode(
        "A4 34 A8 E5  85 00 C6 E4
    15 30 53 88  62 D6 86 EA  9E 81 30 1B  5A E4 22 6B
    FA",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen10::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen10::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "F2 BE ED 7B  C5 09 8E 83
    FE B5 B3 16  08 F8 E2 9C  38 81 9A 89  C8 E7 76 F1
    54 4D 41 51  A4 ED 3A 8B  87 B9 CE"
        )[..]
    );

    // Packet Vector #22
    let key = hex_decode("D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B");
    let nonce = hex_decode("00 5B 8C CB  CD 9A F8 3C  96 96 76 6C  FA");
    let aad = hex_decode("EC 46 BB 63  B0 25 20 C3  3C 49 FD 70");
    let plaintext = hex_decode(
        "B9 6B 49 E2
    1D 62 17 41  63 28 75 DB  7F 6C 92 43  D2 D7 C2",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen10::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen10::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "31 D7 50 A0
    9D A3 ED 7F  DD D4 9A 20  32 AA BF 17  EC 8E BF 7D
    22 C8 08 8C  66 6B E5 C1  97"
        )[..]
    );

    // Packet Vector #23
    let key = hex_decode("D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B");
    let nonce = hex_decode("00 3E BE 94  04 4B 9A 3C  96 96 76 6C  FA");
    let aad = hex_decode("47 A6 5A C7  8B 3D 59 42  27 E8 5E 71");
    let plaintext = hex_decode(
        "E2 FC FB B8
    80 44 2C 73  1B F9 51 67  C8 FF D7 89  5E 33 70 76",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen10::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen10::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "E8 82 F1 DB
    D3 8C E3 ED  A7 C2 3F 04  DD 65 07 1E  B4 13 42 AC
    DF 7E 00 DC  CE C7 AE 52  98 7D"
        )[..]
    );

    // Packet Vector #24
    let key = hex_decode("D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B");
    let nonce = hex_decode("00 8D 49 3B  30 AE 8B 3C  96 96 76 6C  FA");
    let aad = hex_decode("6E 37 A6 EF  54 6D 95 5D  34 AB 60 59");
    let plaintext = hex_decode(
        "AB F2 1C 0B
    02 FE B8 8F  85 6D F4 A3  73 81 BC E3  CC 12 85 17
    D4",
    );
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128CcmNLen13TagLen10::TAG_LEN, 0);
    let cipher = Aes128CcmNLen13TagLen10::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(
        &ciphertext_and_tag[..],
        &hex_decode(
            "F3 29 05 B8
    8A 64 1B 04  B9 C9 FF B5  8C C3 90 90  0F 3D A1 2A
    B1 6D CE 9E  82 EF A1 6D  A6 20 59"
        )[..]
    );
}
