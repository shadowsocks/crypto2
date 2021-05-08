// 8.  Base 16 Encoding
// https://tools.ietf.org/html/rfc4648#section-8
// 
//                          Table 5: The Base 16 Alphabet
// 
//          Value Encoding  Value Encoding  Value Encoding  Value Encoding
//              0 0             4 4             8 8            12 C
//              1 1             5 5             9 9            13 D
//              2 2             6 6            10 A            14 E
//              3 3             7 7            11 B            15 F
// 
// Essentially, Base 16 encoding is the standard case-insensitive hex encoding 
// and may be referred to as "base16" or "hex".
static HEX_ENCODE_TABLE_UPPER_CASE: [u8; 16] = [
//     0     1     2     3     4     5     6     7
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 
//     8     9     A     B     C     D     E     F
    0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
];

static HEX_ENCODE_TABLE_LOWER_CASE: [u8; 16] = [
//     0     1     2     3     4     5     6     7
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 
//     8     9     a     b     c     d     e     f
    0x38, 0x39, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];


pub(crate) const ____: u8 = 0xff;
pub(crate) static HEX_DECODE_TABLE: [u8; 256] = [
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
//    0     1     2     3     4     5     6     7     8     9  
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, ____, ____, ____, ____, ____, ____,
//          A     B     C     D     E     F  
    ____, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
// NOTE: [RFC4648] 制定的 base16 规范当中，并未采用小写的 a .. f 字符
//       但是大多数实现都忽略大小写。
// 12.  Security Considerations
// https://tools.ietf.org/html/rfc4648#section-12
// 
// Similarly, when the base 16 and base 32 alphabets are handled case
// insensitively, alteration of case can be used to leak information or
// make string equality comparisons fail.
//          a     b     c     d     e     f
    ____, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
];

// encode_upper
// to_lowercase

pub struct HexOptions {
    use_lower_case: bool,
    ignore_ascii_case: bool,
}

pub fn hex_encode<R: AsRef<[u8]>>(input: R) -> String {
    let len = input.as_ref().len() * 2;
    if len == 0 {
        return String::new();
    }

    let mut output = Vec::with_capacity(len);
    unsafe { output.set_len(len); }

    hex_encode_to_slice(input, &mut output);

    unsafe { String::from_utf8_unchecked(output) }
}

pub fn hex_decode<R: AsRef<[u8]>>(input: R) -> Result<Vec<u8>, ()> {
    let ilen = input.as_ref().len();
    let olen = ilen / 2;

    if ilen == 0 {
        return Ok(Vec::new());
    }

    // NOTE: 经过 HEX 编码过后的数据，长度应为 2 的倍数。
    if ilen % 2 > 0 {
        return Err(());
    }

    let mut output = Vec::with_capacity(olen);
    unsafe { output.set_len(olen); }

    hex_decode_to_slice(input, &mut output)?;

    Ok(output)
}

pub fn hex_encode_to_slice<R: AsRef<[u8]>, W: AsMut<[u8]>>(input: R, output: &mut W) {
    let input = input.as_ref();
    let output = output.as_mut();

    let mut i = 0usize;
    while i < input.len() {
        let v = input[i];

        let offset = i * 2;
        output[offset + 0] = HEX_ENCODE_TABLE_UPPER_CASE[(v >>    4) as usize];
        output[offset + 1] = HEX_ENCODE_TABLE_UPPER_CASE[(v  & 0x0f) as usize];

        i += 1;
    }
}

pub fn hex_decode_to_slice<R: AsRef<[u8]>, W: AsMut<[u8]>>(input: R, output: &mut W) -> Result<(), ()> {
    let input = input.as_ref();
    let output = output.as_mut();

    let mut i = 0usize;
    while i < input.len() {
        let hi = HEX_DECODE_TABLE[input[i + 0] as usize];
        let lo = HEX_DECODE_TABLE[input[i + 1] as usize];
        
        // An invalid character was found.
        // InvalidDigit
        if hi == ____ || lo == ____ {
            return Err(());
        }

        let offset = i / 2;
        output[offset] = (hi << 4) | lo;

        i += 2;
    }

    Ok(())
}

#[test]
fn test_base16() {
    // 10.  Test Vectors
    // https://tools.ietf.org/html/rfc4648#section-10
    assert_eq!(hex_encode(""), "");
    assert_eq!(hex_encode("f"), "66");
    assert_eq!(hex_encode("fo"), "666F");
    assert_eq!(hex_encode("foo"), "666F6F");
    assert_eq!(hex_encode("foob"), "666F6F62");
    assert_eq!(hex_encode("fooba"), "666F6F6261");
    assert_eq!(hex_encode("foobar"), "666F6F626172");

    assert_eq!(hex_decode("").unwrap(), b"");
    assert_eq!(hex_decode("66").unwrap(), b"f");
    assert_eq!(hex_decode("666F").unwrap(), b"fo");
    assert_eq!(hex_decode("666F6F").unwrap(), b"foo");
    assert_eq!(hex_decode("666F6F62").unwrap(), b"foob");
    assert_eq!(hex_decode("666F6F6261").unwrap(), b"fooba");
    assert_eq!(hex_decode("666F6F626172").unwrap(), b"foobar");

    // NOTE: 忽略大小写
    assert_eq!(hex_decode("666f").unwrap(), b"fo");
    assert_eq!(hex_decode("666f6f626172").unwrap(), b"foobar");
}

#[cfg(test)]
#[bench]
fn bench_encode(b: &mut test::Bencher) {
    let s = "abcdefg";
    let mut output = [0u8; 14];
    b.iter(|| {
        hex_encode_to_slice(s, &mut output)
    })
}

#[cfg(test)]
#[bench]
fn bench_decode(b: &mut test::Bencher) {
    let s = "666F6F626172";
    let mut output = [0u8; 6];
    b.iter(|| {
        hex_decode_to_slice(s, &mut output).unwrap()
    })
}

#[cfg(test)]
#[bench]
fn bench_crate_io_hex_encode(b: &mut test::Bencher) {
    let s = "abcdefg";
    let mut output = [0u8; 14];
    b.iter(|| {
        hex::encode_to_slice(s, &mut output).unwrap()
    })
}

#[cfg(test)]
#[bench]
fn bench_crate_io_hex_decode(b: &mut test::Bencher) {
    let s = "666F6F626172";
    let mut output = [0u8; 6];
    b.iter(|| {
        hex::decode_to_slice(s, &mut output).unwrap()
    })
}
