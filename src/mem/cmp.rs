

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut x = 0u8;
    
    for i in 0..a.len() {
        x |= a[i] ^ b[i];
    }

    if x == 0 { true } else { false }
}