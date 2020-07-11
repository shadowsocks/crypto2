pub const AES_NB: usize = 4;

#[inline]
pub fn gf_mul(x: u8, y: u8) -> u8 {
    // encrypt: y has only 2 bits: can be 1, 2 or 3
    // decrypt: y could be any value of 9, b, d, or e
    fn xtime(x: u8) -> u8 {
        (x << 1) ^ (((x >> 7) & 1) * 0x1b)
    }

    fn xtimes(x: u8, ts: u8) -> u8 {
        let mut x = x;
        for _ in 0..ts {
            x = xtime(x);
        }
        x
    }

      (((y >> 0) & 1) * xtimes(x, 0)) 
    ^ (((y >> 1) & 1) * xtimes(x, 1)) 
    ^ (((y >> 2) & 1) * xtimes(x, 2)) 
    ^ (((y >> 3) & 1) * xtimes(x, 3)) 
    ^ (((y >> 4) & 1) * xtimes(x, 4)) 
    ^ (((y >> 5) & 1) * xtimes(x, 5)) 
    ^ (((y >> 6) & 1) * xtimes(x, 6)) 
    ^ (((y >> 7) & 1) * xtimes(x, 7)) 
}

fn mix_columns(state: &mut [u8; 16]) {
    const Y: [u8; 16] = [
        2, 3, 1, 1,  
        1, 2, 3, 1,
        1, 1, 2, 3, 
        3, 1, 1, 2,
    ];
    let mut s = [0u8; 4];

    for i in 0..AES_NB {
        for r in 0..4 {
            s[r] =    gf_mul(state[i * 4 + 0], Y[r * 4 + 0])
                    ^ gf_mul(state[i * 4 + 1], Y[r * 4 + 1])
                    ^ gf_mul(state[i * 4 + 2], Y[r * 4 + 2])
                    ^ gf_mul(state[i * 4 + 3], Y[r * 4 + 3]);
            // if i == 0 {
                println!("c[{}] = gf_mul{}(state[{}]) ^ gf_mul{}(state[{}]) ^ gf_mul{}(state[{}]) ^ gf_mul{}(state[{}]);",
                    i * 4 + r,
                    Y[r * 4 + 0], i * 4 + 0,
                    Y[r * 4 + 1], i * 4 + 1,
                    Y[r * 4 + 2], i * 4 + 2,
                    Y[r * 4 + 3], i * 4 + 3,
                    );
            // }
        }
        for r in 0..4 {
            state[i * 4 + r] = s[r];
        }
    }
}

fn inv_mix_columns(state: &mut [u8; 16]) {
    const Y: [u8; 16] = [
        14, 11, 13, 09, 
        09, 14, 11, 13, 
        13, 09, 14, 11, 
        11, 13, 09, 14,
    ];
    let mut s = [0u8; 4];
    
    for i in 0..AES_NB {
        for r in 0..4 {
            s[r] =    gf_mul(state[i * 4 + 0], Y[r * 4 + 0])
                    ^ gf_mul(state[i * 4 + 1], Y[r * 4 + 1])
                    ^ gf_mul(state[i * 4 + 2], Y[r * 4 + 2])
                    ^ gf_mul(state[i * 4 + 3], Y[r * 4 + 3]);
            // if i == 0 {
                println!("c[{}] = gf_mul{}(state[{}]) ^ gf_mul{}(state[{}]) ^ gf_mul{}(state[{}]) ^ gf_mul{}(state[{}]);",
                    i * 4 + r,
                    Y[r * 4 + 0], i * 4 + 0,
                    Y[r * 4 + 1], i * 4 + 1,
                    Y[r * 4 + 2], i * 4 + 2,
                    Y[r * 4 + 3], i * 4 + 3,
                    );
            // }
        }
        for r in 0..4 {
            state[i * 4 + r] = s[r];
        }
    }
}


fn main() {
    // Gen GF_MUL
    println!("pub const GF_MUL2: [u8; 256] = [");
    for n in 0u8..=255 {
        if n != 0 && n % 16 == 0 {
            print!("\n    ");
        }
        if n == 0 {
            print!("    ");
        }
        print!("0x{:02x}, ", gf_mul(n, 2));
    }
    println!("\n];");

    println!("pub const GF_MUL3: [u8; 256] = [");
    for n in 0u8..=255 {
        if n != 0 && n % 16 == 0 {
            print!("\n    ");
        }
        if n == 0 {
            print!("    ");
        }
        print!("0x{:02x}, ", gf_mul(n, 3));
    }
    println!("\n];");

    println!("pub const GF_MUL9: [u8; 256] = [");
    for n in 0u8..=255 {
        if n != 0 && n % 16 == 0 {
            print!("\n    ");
        }
        if n == 0 {
            print!("    ");
        }
        print!("0x{:02x}, ", gf_mul(n, 9));
    }
    println!("\n];");

    println!("pub const GF_MUL11: [u8; 256] = [");
    for n in 0u8..=255 {
        if n != 0 && n % 16 == 0 {
            print!("\n    ");
        }
        if n == 0 {
            print!("    ");
        }
        print!("0x{:02x}, ", gf_mul(n, 11));
    }
    println!("\n];");

    println!("pub const GF_MUL13: [u8; 256] = [");
    for n in 0u8..=255 {
        if n != 0 && n % 16 == 0 {
            print!("\n    ");
        }
        if n == 0 {
            print!("    ");
        }
        print!("0x{:02x}, ", gf_mul(n, 13));
    }
    println!("\n];");

    println!("pub const GF_MUL14: [u8; 256] = [");
    for n in 0u8..=255 {
        if n != 0 && n % 16 == 0 {
            print!("\n    ");
        }
        if n == 0 {
            print!("    ");
        }
        print!("0x{:02x}, ", gf_mul(n, 14));
    }
    println!("\n];");


    println!("\n\n");


    // Gen mix_columns && inv_mix_columns
    let mut state = [0u8; 16];

    println!("mix_columns");
    mix_columns(&mut state);

    println!("inv_mix_columns");
    inv_mix_columns(&mut state);
}
