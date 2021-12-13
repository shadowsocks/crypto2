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
static HEXDIGITS_UPPERCASE: [u8; 16] = [
    //     0     1     2     3     4     5     6     7
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    //     8     9     A     B     C     D     E     F
    0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
];

static HEXDIGITS_LOWERCASE: [u8; 16] = [
    //     0     1     2     3     4     5     6     7
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    //     8     9     a     b     c     d     e     f
    0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
];

// Invalid base16 characters
const ____: u8 = 0xff;

// NOTE: 大小写不敏感
static INV_HEXDIGITS: [u8; 256] = [
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    //    0     1     2     3     4     5     6     7     8     9
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, ____, ____, ____, ____, ____, ____,
    //          A     B     C     D     E     F
    ____, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ErrorKind {
    InvalidHexDigit,
    InvalidInputLength,
    InvalidOutputLength,
}

#[derive(Debug, Clone)]
pub struct Error {
    pos: usize,
    hi: u8,
    lo: u8,
    kind: ErrorKind,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self.kind {
            ErrorKind::InvalidHexDigit => {
                write!(
                    f,
                    "invalid hex character one of ({}, {}) at position {}",
                    self.hi as char, self.lo as char, self.pos
                )
            }
            ErrorKind::InvalidInputLength => {
                write!(f, "invalid input data length")
            }
            ErrorKind::InvalidOutputLength => {
                write!(f, "invalid output data length")
            }
        }
    }
}

impl std::error::Error for Error {}

#[inline]
pub fn to_hexdigit_lowercase(val: u8) -> [u8; 2] {
    let hi = HEXDIGITS_LOWERCASE[(val >> 4) as usize];
    let lo = HEXDIGITS_LOWERCASE[(val & 0x0f) as usize];
    [hi, lo]
}

#[inline]
pub fn to_hexdigit_uppercase(val: u8) -> [u8; 2] {
    let hi = HEXDIGITS_UPPERCASE[(val >> 4) as usize];
    let lo = HEXDIGITS_UPPERCASE[(val & 0x0f) as usize];
    [hi, lo]
}

// ignore case
#[inline]
pub fn from_hexdigits(hi: u8, lo: u8) -> Result<u8, Error> {
    let hi = INV_HEXDIGITS[hi as usize];
    let lo = INV_HEXDIGITS[lo as usize];
    if hi == ____ || lo == ____ {
        let e = Error {
            pos: 0,
            hi,
            lo,
            kind: ErrorKind::InvalidHexDigit,
        };
        return Err(e);
    }
    Ok((hi << 4) | lo)
}

pub fn encode<R: AsRef<[u8]>>(input: R) -> String {
    encode_uppercase(input)
}

pub fn encode_uppercase<R: AsRef<[u8]>>(input: R) -> String {
    let len = input.as_ref().len() * 2;
    if len == 0 {
        return String::new();
    }

    let mut output = vec![0u8; len];
    let _ = encode_to_slice_uppercase(input, &mut output).unwrap();

    unsafe { String::from_utf8_unchecked(output) }
}

pub fn encode_lowercase<R: AsRef<[u8]>>(input: R) -> String {
    let len = input.as_ref().len() * 2;
    if len == 0 {
        return String::new();
    }

    let mut output = vec![0u8; len];
    let _ = encode_to_slice_lowercase(input, &mut output).unwrap();

    unsafe { String::from_utf8_unchecked(output) }
}

pub fn encode_to_slice<R: AsRef<[u8]>, W: AsMut<[u8]>>(
    input: R,
    output: &mut W,
) -> Result<usize, Error> {
    encode_to_slice_uppercase(input, output)
}

pub fn encode_to_slice_uppercase<R: AsRef<[u8]>, W: AsMut<[u8]>>(
    input: R,
    output: &mut W,
) -> Result<usize, Error> {
    let input = input.as_ref();
    let output = output.as_mut();

    let ilen = input.len();
    let olen = output.len();

    if olen % 2 > 0 || olen / 2 < ilen {
        let e = Error {
            pos: 0,
            hi: 0,
            lo: 0,
            kind: ErrorKind::InvalidOutputLength,
        };
        return Err(e);
    }

    let mut ipos = 0usize;
    let mut opos = 0usize;

    while ipos < ilen {
        let val = input[ipos];
        let digits = to_hexdigit_uppercase(val);

        output[opos + 0] = digits[0];
        output[opos + 1] = digits[1];

        ipos += 1;
        opos += 2;
    }

    Ok(opos)
}

pub fn encode_to_slice_lowercase<R: AsRef<[u8]>, W: AsMut<[u8]>>(
    input: R,
    output: &mut W,
) -> Result<usize, Error> {
    let input = input.as_ref();
    let output = output.as_mut();

    let ilen = input.len();
    let olen = output.len();

    if olen % 2 > 0 || olen / 2 < ilen {
        let e = Error {
            pos: 0,
            hi: 0,
            lo: 0,
            kind: ErrorKind::InvalidOutputLength,
        };
        return Err(e);
    }

    let mut ipos = 0usize;
    let mut opos = 0usize;

    while ipos < ilen {
        let val = input[ipos];
        let digits = to_hexdigit_lowercase(val);

        output[opos + 0] = digits[0];
        output[opos + 1] = digits[1];

        ipos += 1;
        opos += 2;
    }

    Ok(opos)
}

pub fn decode<R: AsRef<[u8]>>(input: R) -> Result<Vec<u8>, Error> {
    let ilen = input.as_ref().len();
    let olen = ilen / 2;

    if ilen == 0 {
        return Ok(Vec::new());
    }

    let mut output = vec![0u8; olen];

    let _ = decode_to_slice(input, &mut output)?;

    Ok(output)
}

pub fn decode_to_slice<R: AsRef<[u8]>, W: AsMut<[u8]>>(
    input: R,
    output: &mut W,
) -> Result<usize, Error> {
    let input = input.as_ref();
    let output = output.as_mut();

    let ilen = input.len();
    let olen = output.len();

    if ilen % 2 > 0 {
        let e = Error {
            pos: 0,
            hi: 0,
            lo: 0,
            kind: ErrorKind::InvalidInputLength,
        };
        return Err(e);
    }
    if ilen / 2 > olen {
        let e = Error {
            pos: 0,
            hi: 0,
            lo: 0,
            kind: ErrorKind::InvalidOutputLength,
        };
        return Err(e);
    }

    let mut ipos = 0usize;
    let mut opos = 0usize;

    while ipos < ilen {
        output[opos] = from_hexdigits(input[ipos], input[ipos + 1]).map_err(|mut e| {
            e.pos = ipos;
            e
        })?;

        opos += 1;
        ipos += 2;
    }

    Ok(opos)
}

#[test]
fn test_base16() {
    // 10.  Test Vectors
    // https://tools.ietf.org/html/rfc4648#section-10
    assert_eq!(encode(""), "");
    assert_eq!(encode("f"), "66");
    assert_eq!(encode("fo"), "666F");
    assert_eq!(encode("foo"), "666F6F");
    assert_eq!(encode("foob"), "666F6F62");
    assert_eq!(encode("fooba"), "666F6F6261");
    assert_eq!(encode("foobar"), "666F6F626172");

    assert_eq!(encode_lowercase(""), "".to_lowercase());
    assert_eq!(encode_lowercase("f"), "66".to_lowercase());
    assert_eq!(encode_lowercase("fo"), "666F".to_lowercase());
    assert_eq!(encode_lowercase("foo"), "666F6F".to_lowercase());
    assert_eq!(encode_lowercase("foob"), "666F6F62".to_lowercase());
    assert_eq!(encode_lowercase("fooba"), "666F6F6261".to_lowercase());
    assert_eq!(encode_lowercase("foobar"), "666F6F626172".to_lowercase());

    assert_eq!(decode("").unwrap(), b"");
    assert_eq!(decode("66").unwrap(), b"f");
    assert_eq!(decode("666F").unwrap(), b"fo");
    assert_eq!(decode("666F6F").unwrap(), b"foo");
    assert_eq!(decode("666F6F62").unwrap(), b"foob");
    assert_eq!(decode("666F6F6261").unwrap(), b"fooba");
    assert_eq!(decode("666F6F626172").unwrap(), b"foobar");

    // NOTE: 忽略大小写
    assert_eq!(decode("666f").unwrap(), b"fo");
    assert_eq!(decode("666f6f626172").unwrap(), b"foobar");
}

// #[cfg(test)]
// #[bench]
// fn bench_encode(b: &mut test::Bencher) {
//     let s = "abcdefg";
//     let mut output = [0u8; 14];
//     b.iter(|| {
//         encode_to_slice_uppercase(s, &mut output)
//     })
// }

// #[cfg(test)]
// #[bench]
// fn bench_decode(b: &mut test::Bencher) {
//     let s = "666F6F626172";
//     let mut output = [0u8; 6];
//     b.iter(|| {
//         decode_to_slice(s, &mut output).unwrap()
//     })
// }

// #[cfg(test)]
// #[bench]
// fn bench_crate_io_hex_encode(b: &mut test::Bencher) {
//     let s = "abcdefg";
//     let mut output = [0u8; 14];
//     b.iter(|| {
//         hex::encode_to_slice(s, &mut output).unwrap()
//     })
// }

// #[cfg(test)]
// #[bench]
// fn bench_crate_io_hex_decode(b: &mut test::Bencher) {
//     let s = "666F6F626172";
//     let mut output = [0u8; 6];
//     b.iter(|| {
//         hex::decode_to_slice(s, &mut output).unwrap()
//     })
// }
