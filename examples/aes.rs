extern crate crypto2;

use crypto2::blockcipher::Aes128;


fn main() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let plaintext = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    
    let cipher = Aes128::new(&key);

    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);
    
    let mut cleartext = ciphertext.clone();
    cipher.decrypt(&mut cleartext);
    
    println!("plaintext : {:?}", &plaintext[..]);
    println!("ciphertext: {:?}", &ciphertext[..]);
    println!("cleartext : {:?}", &cleartext[..]);
}
