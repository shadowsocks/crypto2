use crate::mem::Zeroize;
use crate::mem::constant_time_eq;
use crate::mac::Poly1305;

mod chacha20;
use self::chacha20::Chacha20;


/// ChaCha20 and Poly1305 for OpenSSH Protocols (chacha20-poly1305@openssh.com)
/// 
/// <https://github.com/openbsd/src/blob/master/usr.bin/ssh/PROTOCOL.chacha20poly1305>
#[derive(Clone)]
pub struct Chacha20Poly1305 {
    c1: Chacha20,
    c2: Chacha20,
}

impl Zeroize for Chacha20Poly1305 {
    fn zeroize(&mut self) {
        self.c1.zeroize();
        self.c2.zeroize();
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
    pub const KEY_LEN: usize   = Chacha20::KEY_LEN * 2; // 64 bytes
    pub const BLOCK_LEN: usize = Chacha20::BLOCK_LEN;   // 64 bytes
    pub const NONCE_LEN: usize = Chacha20::NONCE_LEN;   //  8 bytes
    pub const TAG_LEN: usize   = Poly1305::TAG_LEN;     // 16 bytes

    pub const P_MAX: usize = 274877906880;                // (2^32 - 1) * BLOCK_LEN
    pub const C_MAX: usize = Self::P_MAX + Self::TAG_LEN; // 274,877,906,896
    pub const N_MIN: usize = Self::NONCE_LEN;
    pub const N_MAX: usize = Self::NONCE_LEN;
    
    pub const PKT_OCTETS_LEN: usize = 4;
    

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(Self::KEY_LEN / 2, Poly1305::KEY_LEN);
        assert_eq!(key.len(), Self::KEY_LEN);

        // K_2 is used in conjunction with poly1305 to build an AEAD 
        // that is used to encrypt and authenticate the entire packet.
        let k2 = &key[..Chacha20::KEY_LEN];
        // K_1 is used only to encrypt the 4 byte packet length field.
        let k1 = &key[Chacha20::KEY_LEN..Self::KEY_LEN];

        let c2 = Chacha20::new(k2);
        let c1 = Chacha20::new(k1);

        Self { c1, c2 }
    }

    pub fn encrypt_slice(&mut self, pkt_seq_num: u32, aead_pkt: &mut [u8]) {
        debug_assert!(aead_pkt.len() >= Self::TAG_LEN + Self::PKT_OCTETS_LEN);

        let (pkt_len, plaintext_and_tag) = aead_pkt.split_at_mut(Self::PKT_OCTETS_LEN);

        let plen = plaintext_and_tag.len() - Self::TAG_LEN;
        let (plaintext_in_ciphertext_out, tag_out) = plaintext_and_tag.split_at_mut(plen);

        self.encrypt_slice_detached(pkt_seq_num, pkt_len, plaintext_in_ciphertext_out, tag_out)
    }

    pub fn decrypt_slice(&mut self, pkt_seq_num: u32, aead_pkt: &mut [u8]) -> bool {
        debug_assert!(aead_pkt.len() >= Self::TAG_LEN + Self::PKT_OCTETS_LEN);

        let (pkt_len, ciphertext_and_tag) = aead_pkt.split_at_mut(Self::PKT_OCTETS_LEN);

        let clen = ciphertext_and_tag.len() - Self::TAG_LEN;
        let (ciphertext_in_plaintext_out, tag_in) = ciphertext_and_tag.split_at_mut(clen);

        self.decrypt_slice_detached(pkt_seq_num, pkt_len, ciphertext_in_plaintext_out, &tag_in)
    }

    pub fn encrypt_slice_detached(&mut self, pkt_seq_num: u32, pkt_len: &mut [u8], plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8]) {
        let plen = plaintext_in_ciphertext_out.len();
        let tlen = tag_out.len();

        debug_assert_eq!(pkt_len.len(), Self::PKT_OCTETS_LEN);
        debug_assert!(plen <= Self::P_MAX);
        debug_assert!(tlen == Self::TAG_LEN);

        let mut poly1305_key = [0u8; Poly1305::KEY_LEN];
        self.c2.encrypt_slice(pkt_seq_num, 0, &mut poly1305_key);

        // The length in bytes of the `packet_length` field in a SSH packet.
        self.c1.encrypt_slice(pkt_seq_num, 0, pkt_len);

        // Set Chacha's block counter to 1
        self.c2.encrypt_slice(pkt_seq_num, 1, plaintext_in_ciphertext_out);

        // calculate and append tag
        // void poly1305_auth(unsigned char out[POLY1305_TAGLEN], const unsigned char *m, size_t inlen, const unsigned char key[POLY1305_KEYLEN]) {
        // poly1305_auth(dest + aadlen + len, dest, aadlen + len, poly_key);
        let mut poly1305 = Poly1305::new(&poly1305_key);
        poly1305.update(&pkt_len);
        poly1305.update(&plaintext_in_ciphertext_out);

        let tag = poly1305.finalize();

        tag_out.copy_from_slice(&tag[..Self::TAG_LEN]);
    }

    pub fn decrypt_slice_detached(&mut self, pkt_seq_num: u32, pkt_len: &mut [u8], ciphertext_in_plaintext_out: &mut [u8], tag_in: &[u8]) -> bool {
        let clen = ciphertext_in_plaintext_out.len();
        let tlen = tag_in.len();

        debug_assert_eq!(pkt_len.len(), Self::PKT_OCTETS_LEN);
        debug_assert!(clen <= Self::P_MAX);
        debug_assert!(tlen == Self::TAG_LEN);

        let mut poly1305_key = [0u8; Poly1305::KEY_LEN];
        self.c2.encrypt_slice(pkt_seq_num, 0, &mut poly1305_key);

        let mut poly1305 = Poly1305::new(&poly1305_key);
        poly1305.update(&pkt_len);
        poly1305.update(&ciphertext_in_plaintext_out);

        let tag = poly1305.finalize();

        // Verify
        let is_match = constant_time_eq(tag_in, &tag[..Self::TAG_LEN]);

        if is_match {
            // The length in bytes of the `packet_length` field in a SSH packet.
            self.c1.decrypt_slice(pkt_seq_num, 0, pkt_len);

            // Set Chacha's block counter to 1
            self.c2.decrypt_slice(pkt_seq_num, 1, ciphertext_in_plaintext_out);
        }

        is_match
    }
}
