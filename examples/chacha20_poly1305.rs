extern crate crypto2;

use crypto2::aeadcipher::Chacha20Poly1305;


fn main() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 
        0x00, 0x00, 0x00, 0x00, 
    ];
    let aad = [1u8; Chacha20Poly1305::BLOCK_LEN];
    let plaintext = [1u8; 64];
    let plen = plaintext.len();

    let cipher = Chacha20Poly1305::new(&key);
    
    let mut ciphertext_and_tag = plaintext.to_vec();
    ciphertext_and_tag.resize(plen + Chacha20Poly1305::TAG_LEN, 0);
    
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag[..]);
    
    println!("plaintext : {:?}", &plaintext[..]);
    println!("ciphertext: {:?}", &ciphertext_and_tag[..plen]);
    println!("tag: {:?}", &ciphertext_and_tag[plen..]);
}
