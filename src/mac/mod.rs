mod hmac;
mod ghash;
mod polyval;
mod poly1305;

pub use self::hmac::*;
pub use self::ghash::GHash;
pub use self::polyval::Polyval;
pub use self::poly1305::Poly1305;



#[cfg(test)]
#[bench]
fn bench_poly1305(b: &mut test::Bencher) {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let message = test::black_box([1u8; Poly1305::BLOCK_LEN]);

    let mut poly1305 = Poly1305::new(&key);
    
    b.bytes = Poly1305::BLOCK_LEN as u64;
    b.iter(|| {
        test::black_box(poly1305.update(&message))
    })
}

#[cfg(test)]
#[bench]
fn bench_polyval(b: &mut test::Bencher) {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
    ];
    let message = test::black_box([128u8; Polyval::BLOCK_LEN]);

    let mut polyval = Polyval::new(&key);
    
    b.bytes = Polyval::BLOCK_LEN as u64;
    b.iter(|| {
        test::black_box(polyval.update(&message))
    })
}

#[cfg(test)]
#[bench]
fn bench_ghash(b: &mut test::Bencher) {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
    ];
    let message = test::black_box([128u8; GHash::BLOCK_LEN]);
    
    let mut ghash = GHash::new(&key);

    b.bytes = GHash::BLOCK_LEN as u64;
    b.iter(|| {
        test::black_box(ghash.update(&message))
    })
}