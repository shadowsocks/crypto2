use crate::mem::Zeroize;
use crate::mem::constant_time_eq;
use crate::mac::Poly1305;
use crate::streamcipher::Chacha20;


/// ChaCha20 and Poly1305 for IETF Protocols
/// 
/// <https://tools.ietf.org/html/rfc8439>
#[derive(Clone)]
pub struct Chacha20Poly1305 {
    chacha20: Chacha20,
}

impl Zeroize for Chacha20Poly1305 {
    fn zeroize(&mut self) {
        self.chacha20.zeroize();
    }
}
impl Drop for Chacha20Poly1305 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for Chacha20Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Chacha20Poly1305").finish()
    }
}

impl Chacha20Poly1305 {
    pub const KEY_LEN: usize   = Chacha20::KEY_LEN;   // 32 bytes
    pub const BLOCK_LEN: usize = Chacha20::BLOCK_LEN; // 64 bytes
    pub const NONCE_LEN: usize = Chacha20::NONCE_LEN; // 12 bytes
    pub const TAG_LEN: usize   = Poly1305::TAG_LEN;   // 16 bytes
    
    #[cfg(target_pointer_width = "64")]
    pub const A_MAX: usize = u64::MAX as usize;           // 2^64 - 1
    #[cfg(target_pointer_width = "32")]
    pub const A_MAX: usize = usize::MAX;                  // 2^32 - 1
    pub const P_MAX: usize = 274877906880;                // (2^32 - 1) * BLOCK_LEN
    pub const C_MAX: usize = Self::P_MAX + Self::TAG_LEN; // 274,877,906,896
    pub const N_MIN: usize = Self::NONCE_LEN;
    pub const N_MAX: usize = Self::NONCE_LEN;
    
    
    pub fn new(key: &[u8]) -> Self {
        assert_eq!(Self::KEY_LEN, Poly1305::KEY_LEN);
        assert_eq!(key.len(), Self::KEY_LEN);
        
        let chacha20 = Chacha20::new(key);

        Self { chacha20 }
    }
    
    pub fn encrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) {
        debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

        let plen = aead_pkt.len() - Self::TAG_LEN;
        let (plaintext_in_ciphertext_out, tag_out) = aead_pkt.split_at_mut(plen);

        self.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out)
    }

    pub fn decrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
        debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

        let clen = aead_pkt.len() - Self::TAG_LEN;
        let (ciphertext_in_plaintext_out, tag_in) = aead_pkt.split_at_mut(clen);

        self.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, &tag_in)
    }

    pub fn encrypt_slice_detached(&self, nonce: &[u8], aad: &[u8], plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8]) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let alen = aad.len();
        let plen = plaintext_in_ciphertext_out.len();
        let tlen = tag_out.len();

        debug_assert!(alen <= Self::A_MAX);
        debug_assert!(plen <= Self::P_MAX);
        debug_assert!(tlen == Self::TAG_LEN);

        // NOTE: 初始 BlockCounter = 1;
        self.chacha20.encrypt_slice(1, &nonce, plaintext_in_ciphertext_out);

        let mut poly1305 = {
            let mut keystream = [0u8; Self::BLOCK_LEN];
            // NOTE: 初始 BlockCounter = 0;
            self.chacha20.encrypt_slice(0, &nonce, &mut keystream);
            let mut poly1305_key = [0u8; Poly1305::KEY_LEN];
            poly1305_key.copy_from_slice(&keystream[..Poly1305::KEY_LEN][..]);

            Poly1305::new(&poly1305_key[..])
        };

        // NOTE: Poly1305 会自动 对齐数据。
        poly1305.update(aad);
        poly1305.update(&plaintext_in_ciphertext_out);

        let mut len_block = [0u8; 16];
        len_block[0.. 8].copy_from_slice(&(alen as u64).to_le_bytes());
        len_block[8..16].copy_from_slice(&(plen as u64).to_le_bytes());

        poly1305.update(&len_block);

        let tag = poly1305.finalize();

        tag_out.copy_from_slice(&tag[..Self::TAG_LEN]);
    }

    pub fn decrypt_slice_detached(&self, nonce: &[u8], aad: &[u8], ciphertext_in_plaintext_out: &mut [u8], tag_in: &[u8]) -> bool {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let alen = aad.len();
        let clen = ciphertext_in_plaintext_out.len();
        let tlen = tag_in.len();

        debug_assert!(alen <= Self::A_MAX);
        debug_assert!(clen <= Self::P_MAX);
        debug_assert!(tlen == Self::TAG_LEN);

        let mut poly1305 = {
            let mut keystream = [0u8; Self::BLOCK_LEN];
            // NOTE: 初始 BlockCounter = 0;
            self.chacha20.encrypt_slice(0, &nonce, &mut keystream);
            let mut poly1305_key = [0u8; Poly1305::KEY_LEN];
            poly1305_key.copy_from_slice(&keystream[..Poly1305::KEY_LEN][..]);

            Poly1305::new(&poly1305_key[..])
        };
        
        // NOTE: Poly1305 会自动 对齐数据。
        poly1305.update(aad);
        poly1305.update(&ciphertext_in_plaintext_out);

        let mut len_block = [0u8; 16];
        len_block[0.. 8].copy_from_slice(&(alen as u64).to_le_bytes());
        len_block[8..16].copy_from_slice(&(clen as u64).to_le_bytes());

        poly1305.update(&len_block);

        let tag = poly1305.finalize();
        
        // Verify
        let is_match = constant_time_eq(tag_in, &tag[..Self::TAG_LEN]);
        
        if is_match {
            // NOTE: 初始 BlockCounter = 1;
            self.chacha20.decrypt_slice(1, &nonce, ciphertext_in_plaintext_out);
        }
        
        is_match
    }
}


#[test]
fn test_poly1305_key_generation() {
    // 2.6.2.  Poly1305 Key Generation Test Vector
    // https://tools.ietf.org/html/rfc8439#section-2.6.2
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 
        0x04, 0x05, 0x06, 0x07 
    ];

    let mut keystream = [0u8; Chacha20::BLOCK_LEN];

    let chacha20 = Chacha20::new(&key);
    // NOTE: 初始 BlockCounter = 0;
    chacha20.encrypt_slice(0, &nonce, &mut keystream);

    assert_eq!(&keystream[..Poly1305::KEY_LEN], &[
        0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 
        0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2, 0x94, 0x71,
        0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5, 
        0x08, 0xdb, 0xb8, 0xe2, 0xfd, 0xd1, 0xa6, 0x46,
    ]);
}

#[test]
fn test_aead_chacha20_poly1305_encrypt() {
    // 2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305
    // https://tools.ietf.org/html/rfc8439#section-2.8.2
    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
    let aad = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 
        0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce = [
        0x07, 0x00, 0x00, 0x00,                         // Constants
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, // IV
    ];

    let chacha20_poly1305 = Chacha20Poly1305::new(&key);

    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.to_vec();
    ciphertext_and_tag.resize(plen + Chacha20Poly1305::TAG_LEN, 0);
    
    chacha20_poly1305.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);

    assert_eq!(&ciphertext_and_tag[..], &[
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
        // TAG
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ][..]);
}

#[test]
fn test_aead_chacha20_poly1305_decrypt() {
    // A.5.  ChaCha20-Poly1305 AEAD Decryption
    // https://tools.ietf.org/html/rfc8439#appendix-A.5
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];
    let aad = [
        0xf3, 0x33, 0x88, 0x86, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x4e, 0x91,
    ];
    
    let plaintext = b"Internet-Drafts are draft documents valid for a \
maximum of six months and may be updated, replaced, or obsoleted \
by other documents at any time. It is inappropriate to use Internet-Drafts as \
reference material or to cite them other than as \x2f\xe2\x80\x9c\
work in progress.\x2f\xe2\x80\x9d";
    
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.to_vec();
    ciphertext_and_tag.resize(plen + Chacha20Poly1305::TAG_LEN, 0);

    let chacha20_poly1305 = Chacha20Poly1305::new(&key);

    chacha20_poly1305.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &[
        0x64, 0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4, 
        0x60, 0xf0, 0x62, 0xc7, 0x9b, 0xe6, 0x43, 0xbd,
        0x5e, 0x80, 0x5c, 0xfd, 0x34, 0x5c, 0xf3, 0x89, 
        0xf1, 0x08, 0x67, 0x0a, 0xc7, 0x6c, 0x8c, 0xb2,
        0x4c, 0x6c, 0xfc, 0x18, 0x75, 0x5d, 0x43, 0xee, 
        0xa0, 0x9e, 0xe9, 0x4e, 0x38, 0x2d, 0x26, 0xb0,
        0xbd, 0xb7, 0xb7, 0x3c, 0x32, 0x1b, 0x01, 0x00, 
        0xd4, 0xf0, 0x3b, 0x7f, 0x35, 0x58, 0x94, 0xcf,
        0x33, 0x2f, 0x83, 0x0e, 0x71, 0x0b, 0x97, 0xce, 
        0x98, 0xc8, 0xa8, 0x4a, 0xbd, 0x0b, 0x94, 0x81,
        0x14, 0xad, 0x17, 0x6e, 0x00, 0x8d, 0x33, 0xbd, 
        0x60, 0xf9, 0x82, 0xb1, 0xff, 0x37, 0xc8, 0x55,
        0x97, 0x97, 0xa0, 0x6e, 0xf4, 0xf0, 0xef, 0x61, 
        0xc1, 0x86, 0x32, 0x4e, 0x2b, 0x35, 0x06, 0x38,
        0x36, 0x06, 0x90, 0x7b, 0x6a, 0x7c, 0x02, 0xb0, 
        0xf9, 0xf6, 0x15, 0x7b, 0x53, 0xc8, 0x67, 0xe4,
        0xb9, 0x16, 0x6c, 0x76, 0x7b, 0x80, 0x4d, 0x46, 
        0xa5, 0x9b, 0x52, 0x16, 0xcd, 0xe7, 0xa4, 0xe9,
        0x90, 0x40, 0xc5, 0xa4, 0x04, 0x33, 0x22, 0x5e, 
        0xe2, 0x82, 0xa1, 0xb0, 0xa0, 0x6c, 0x52, 0x3e,
        0xaf, 0x45, 0x34, 0xd7, 0xf8, 0x3f, 0xa1, 0x15, 
        0x5b, 0x00, 0x47, 0x71, 0x8c, 0xbc, 0x54, 0x6a,
        0x0d, 0x07, 0x2b, 0x04, 0xb3, 0x56, 0x4e, 0xea, 
        0x1b, 0x42, 0x22, 0x73, 0xf5, 0x48, 0x27, 0x1a,
        0x0b, 0xb2, 0x31, 0x60, 0x53, 0xfa, 0x76, 0x99, 
        0x19, 0x55, 0xeb, 0xd6, 0x31, 0x59, 0x43, 0x4e,
        0xce, 0xbb, 0x4e, 0x46, 0x6d, 0xae, 0x5a, 0x10, 
        0x73, 0xa6, 0x72, 0x76, 0x27, 0x09, 0x7a, 0x10,
        0x49, 0xe6, 0x17, 0xd9, 0x1d, 0x36, 0x10, 0x94, 
        0xfa, 0x68, 0xf0, 0xff, 0x77, 0x98, 0x71, 0x30,
        0x30, 0x5b, 0xea, 0xba, 0x2e, 0xda, 0x04, 0xdf, 
        0x99, 0x7b, 0x71, 0x4d, 0x6c, 0x6f, 0x2c, 0x29,
        0xa6, 0xad, 0x5c, 0xb4, 0x02, 0x2b, 0x02, 0x70, 
        0x9b,
        0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb, 0x22, 
        0x39, 0x23, 0x36, 0xfe, 0xa1, 0x85, 0x1f, 0x38,
    ][..]);

    let chacha20_poly1305 = Chacha20Poly1305::new(&key);
    
    let ret = chacha20_poly1305.decrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(ret, true);

    let cleartext = &ciphertext_and_tag[..plen];
    assert_eq!(&plaintext[..], &cleartext[..]);
}

// Appendix A.  Additional Test Vectors
// https://tools.ietf.org/html/rfc8439#appendix-A