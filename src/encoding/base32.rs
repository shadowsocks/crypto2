// 6.  Base 32 Encoding
// https://tools.ietf.org/html/rfc4648#section-6
// 
//                      Table 3: The Base 32 Alphabet
// 
//      Value Encoding  Value Encoding  Value Encoding  Value Encoding
//          0 A             9 J            18 S            27 3
//          1 B            10 K            19 T            28 4
//          2 C            11 L            20 U            29 5
//          3 D            12 M            21 V            30 6
//          4 E            13 N            22 W            31 7
//          5 F            14 O            23 X
//          6 G            15 P            24 Y         (pad) =
//          7 H            16 Q            25 Z
//          8 I            17 R            26 2
// 
// 7.  Base 32 Encoding with Extended Hex Alphabet
// https://tools.ietf.org/html/rfc4648#section-7
// 
//                  Table 4: The "Extended Hex" Base 32 Alphabet
// 
//          Value Encoding  Value Encoding  Value Encoding  Value Encoding
//              0 0             9 9            18 I            27 R
//              1 1            10 A            19 J            28 S
//              2 2            11 B            20 K            29 T
//              3 3            12 C            21 L            30 U
//              4 4            13 D            22 M            31 V
//              5 5            14 E            23 N
//              6 6            15 F            24 O         (pad) =
//              7 7            16 G            25 P
//              8 8            17 H            26 Q
pub use super::base64::Config;
pub use super::base64::DEFAULT_CONFIG;
pub use super::base64::Error;
pub use super::base64::ErrorKind;


static STANDARD_TABLE: [u8; 32] = [
//    A     B     C     D     E     F     G     H     I     J     K     L     M     N     O     P   
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
//    Q     R     S     T     U     V     W     X     Y     Z     2     3     4     5     6     7
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
];
static URL_SAFE_TABLE: [u8; 32] = [
//     0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
//    G     H     I     J     K     L     M     N     O     P      Q     R     S     T     U     V
    0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
];

// Invalid base32 characters
const ____: u8 = 0xff;
const _EXT: u8 = 0xfe; // PADDED.

// NOTE: 大小写不敏感
static STANDARD_DECODE_TABLE: [u8; 256] = [
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
//                2     3     4     5     6     7                                 b'='
    ____, ____, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, ____, ____, ____, ____, ____, _EXT, ____, ____,
//          A     B     C     D     E     F     G     H     I     J     K     L     M     N     O  
    ____, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
//    P     Q     R     S     T     U     V     W     X     Y     Z
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, ____, ____, ____, ____, ____,
//          a     b     c     d     e     f     g     h     i     j     k     l     m     n     o
    ____, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
//    p     q     r     s     t     u     v     w     x     y     z
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
];

// NOTE: 大小写不敏感
static URL_SAFE_DECODE_TABLE: [u8; 256] = [
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
//    0     1     2     3     4     5     6     7     8     9                     b'='
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, ____, ____, ____, _EXT, ____, ____,
//          A     B     C     D     E     F     G     H     I     J     K     L     M     N     O  
    ____, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
//    P     Q     R     S     T     U     V  
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, ____, ____, ____, ____, ____, ____, ____, ____, ____,
//          a     b     c     d     e     f     g     h     i     j     k     l     m     n     o
    ____, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
//    p     q     r     s     t     u     v
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
];


#[inline]
fn encode_buffer_len(ilen: usize, config: Config) -> usize {
    // Groups Len ( 5 * 8 = 40-bits )
    let n = ilen / 5;
    let r = ilen % 5;

    // NO-PAD
    if config.no_padding {
        match r {
            0 => n * 8,
            1 => n * 8 + 2,
            2 => n * 8 + 4,
            3 => n * 8 + 5,
            4 => n * 8 + 7,
            _ => unreachable!(),
        }
    } else {
        // PAD
        if r > 0 {
            n * 8 + 8
        } else {
            n * 8
        }
    }
}

#[inline]
fn decode_buffer_len(ilen: usize) -> usize {
    let n = ilen / 8;
    let r = ilen % 8;
    
    let olen = if r > 0 { n * 5 + 5 } else { n * 5 };

    olen
}


pub fn encode<D: AsRef<[u8]>>(input: D) -> String {
    encode_with_config(input, DEFAULT_CONFIG)
}

pub fn urlsafe_encode<D: AsRef<[u8]>>(input: D) -> String {
    urlsafe_encode_with_config(input, DEFAULT_CONFIG)
}

pub fn encode_with_config<D: AsRef<[u8]>>(input: D, config: Config) -> String {
    let input = input.as_ref();
    if input.is_empty() {
        return String::new();
    }

    let ilen = input.len();

    let olen = encode_buffer_len(ilen, config);
    let mut output = vec![0u8; olen];

    let amt = encode_to_slice_inner(&STANDARD_TABLE, input, &mut output, config);
    if amt < olen {
        output.truncate(amt);
    }

    unsafe { String::from_utf8_unchecked(output) }
}

pub fn urlsafe_encode_with_config<D: AsRef<[u8]>>(input: D, config: Config) -> String {
    let input = input.as_ref();
    if input.is_empty() {
        return String::new();
    }

    let ilen = input.len();
    let olen = encode_buffer_len(ilen, DEFAULT_CONFIG);

    let mut output = vec![0u8; olen];

    let amt = encode_to_slice_inner(&URL_SAFE_TABLE, input, &mut output, config);
    if amt < olen {
        output.truncate(amt);
    }

    unsafe { String::from_utf8_unchecked(output) }
}

pub fn encode_to_slice<R: AsRef<[u8]>, W: AsMut<[u8]>>(input: R, output: &mut W) -> usize {
    encode_to_slice_with_config(input, output, DEFAULT_CONFIG)
}

pub fn urlsafe_encode_to_slice<R: AsRef<[u8]>, W: AsMut<[u8]>>(input: R, output: &mut W) -> usize {
    urlsafe_encode_to_slice_with_config(input, output, DEFAULT_CONFIG)
}

pub fn encode_to_slice_with_config<R: AsRef<[u8]>, W: AsMut<[u8]>>(input: R, output: &mut W, config: Config) -> usize {
    encode_to_slice_inner(&STANDARD_TABLE, input, output, config)
}

pub fn urlsafe_encode_to_slice_with_config<R: AsRef<[u8]>, W: AsMut<[u8]>>(input: R, output: &mut W, config: Config) -> usize {
    encode_to_slice_inner(&URL_SAFE_TABLE, input, output, config)
}




pub fn decode<D: AsRef<[u8]>>(input: D) -> Result<Vec<u8>, Error> {
    decode_with_config(input, DEFAULT_CONFIG)
}

pub fn urlsafe_decode<D: AsRef<[u8]>>(input: D) -> Result<Vec<u8>, Error> {
    urlsafe_decode_with_config(input, DEFAULT_CONFIG)
}

pub fn decode_with_config<D: AsRef<[u8]>>(input: D, config: Config) -> Result<Vec<u8>, Error> {
    let input = input.as_ref();
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let olen = decode_buffer_len(input.len());

    let mut output = vec![0u8; olen];
    let amt = decode_to_slice_inner(&STANDARD_DECODE_TABLE, input, &mut output, config)?;
    if amt < olen {
        output.truncate(amt);
    }

    Ok(output)
}

pub fn urlsafe_decode_with_config<D: AsRef<[u8]>>(input: D, config: Config) -> Result<Vec<u8>, Error> {
    let input = input.as_ref();
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let olen = decode_buffer_len(input.len());
    
    let mut output = vec![0u8; olen];
    let amt = decode_to_slice_inner(&URL_SAFE_DECODE_TABLE, input, &mut output, config)?;
    if amt < olen {
        output.truncate(amt);
    }

    Ok(output)
}


pub fn decode_to_slice<R: AsRef<[u8]>, W: AsMut<[u8]>>(input: R, output: &mut W) -> Result<usize, Error> {
    decode_to_slice_with_config(input, output, DEFAULT_CONFIG)
}

pub fn urlsafe_decode_to_slice<R: AsRef<[u8]>, W: AsMut<[u8]>>(input: R, output: &mut W) -> Result<usize, Error> {
    urlsafe_decode_to_slice_with_config(input, output, DEFAULT_CONFIG)
}

pub fn decode_to_slice_with_config<R: AsRef<[u8]>, W: AsMut<[u8]>>(input: R, output: &mut W, config: Config) -> Result<usize, Error> {
    decode_to_slice_inner(&STANDARD_DECODE_TABLE, input, output, config)
}

pub fn urlsafe_decode_to_slice_with_config<R: AsRef<[u8]>, W: AsMut<[u8]>>(input: R, output: &mut W, config: Config) -> Result<usize, Error> {
    decode_to_slice_inner(&URL_SAFE_DECODE_TABLE, input, output, config)
}


#[inline]
fn decode_to_slice_inner<R: AsRef<[u8]>, W: AsMut<[u8]>>(table: &[u8; 256], input: R, output: &mut W, config: Config) -> Result<usize, Error> {
    let input  = input.as_ref();
    let output = output.as_mut();

    let ilen = input.len();

    let mut ipos  = 0usize; // input data index
    let mut opos  = 0usize; // output data index

    let mut group = 0u64;   // 5 bytes encode to 8 base32 character.
    let mut gpos  = 0u8;    // group bit index

    // PADDING-LEN
    let mut plen = 0usize;

    while ipos < ilen {
        let val = table[input[ipos] as usize];
        match val {
            ____ => {
                return Err(Error {
                    pos: ipos,
                    byte: input[ipos],
                    kind: ErrorKind::InvalidCodedCharacter,
                });
            },
            _EXT => {
                // DECODE-PADDING DATA
                plen  = 1;
                ipos += 1;

                const MAX_PADDING_LEN: usize = 7;

                while ipos < ilen && plen < MAX_PADDING_LEN {
                    let val = table[input[ipos] as usize];
                    if val != _EXT {
                        return Err(Error {
                            pos: ipos,
                            byte: input[ipos],
                            kind: ErrorKind::InvalidPaddingCharacter,
                        });
                    }

                    plen += 1;
                    ipos += 1;
                }

                // NOTE: 忽略后续的字符，即便它不是合法的填充字符 `=`。
                break;
            },
            _ => {
                match gpos {
                    0 => {
                        group = (val as u64) << 59;
                        gpos = 5;
                    },
                    5 => {
                        group |= (val as u64) << 54;
                        gpos = 10;
                    },
                    10 => {
                        group |= (val as u64) << 49;
                        gpos = 15;
                    },
                    15 => {
                        group |= (val as u64) << 44;
                        gpos = 20;
                    },
                    20 => {
                        group |= (val as u64) << 39;
                        gpos = 25;
                    },
                    25 => {
                        group |= (val as u64) << 34;
                        gpos = 30;
                    },
                    30 => {
                        group |= (val as u64) << 29;
                        gpos = 35;
                    },
                    35 => {
                        group |= (val as u64) << 24;
                        let [b1, b2, b3, b4, b5, _, _, _] = group.to_be_bytes();

                        output[opos + 0] = b1;
                        output[opos + 1] = b2;
                        output[opos + 2] = b3;
                        output[opos + 3] = b4;
                        output[opos + 4] = b5;

                        opos += 5;
                        gpos  = 0;
                    },
                    _ => unreachable!(),
                }

                ipos += 1;
            }
        }
    }

    // NOTE: 预期需要填充的长度。
    let mut expected_padding_len = 0usize;
    
    // Check trailing bits
    match gpos {
        0 => {
            group = 0;
        },
        5 => {
            // rem 5-bits
            // NOTE: 这种情况，大部分属于数据被截断了。
            expected_padding_len = 7;
        },
        10 => {
            // rem 2-bits
            let [b1, b2, _, _,  _, _, _, _] = group.to_be_bytes();
            
            output[opos + 0] = b1;
            opos += 1;

            group = b2 as u64;
            expected_padding_len = 6; // 8 - (10 / 5)
        },
        15 => {
            // rem 7-bits
            let [b1, b2, _, _,  _, _, _, _] = group.to_be_bytes();
            
            output[opos + 0] = b1;
            opos += 1;

            group = b2 as u64;
            expected_padding_len = 5; // 8 - (15 / 5)
        },
        20 => {
            // rem 4-bits
            let [b1, b2, b3, _,  _, _, _, _] = group.to_be_bytes();
            
            output[opos + 0] = b1;
            output[opos + 1] = b2;
            opos += 2;

            group = b3 as u64;
            expected_padding_len = 4; // 8 - (20 / 5)
        },
        25 => {
            // rem 1-bits
            let [b1, b2, b3, b4,  _, _, _, _] = group.to_be_bytes();
            
            output[opos + 0] = b1;
            output[opos + 1] = b2;
            output[opos + 2] = b3;
            opos += 3;

            group = b4 as u64;
            expected_padding_len = 3; // 8 - (25 / 5)
        },
        30 => {
            // rem 6-bits
            let [b1, b2, b3, b4,  _, _, _, _] = group.to_be_bytes();
            
            output[opos + 0] = b1;
            output[opos + 1] = b2;
            output[opos + 2] = b3;
            opos += 3;

            group = b4 as u64;
            expected_padding_len = 2; // 8 - (30 / 5)
        },
        35 => {
            // rem 3-bits
            let [b1, b2, b3, b4,  b5, _, _, _] = group.to_be_bytes();
            
            output[opos + 0] = b1;
            output[opos + 1] = b2;
            output[opos + 2] = b3;
            output[opos + 3] = b4;
            opos += 4;

            group = b5 as u64;
            expected_padding_len = 1; // 8 - (35 / 5)
        },
        _ => unreachable!(),
    }

    if !config.no_padding {
        // NOTE: 检查 PADDING 长度.
        if expected_padding_len > 0 && plen != expected_padding_len {
            ipos -= 1;
            return Err(Error {
                pos: ipos,
                byte: input[ipos],
                kind: ErrorKind::InvalidPaddingLength,
            });
        }
    }

    if !config.allow_trailing_non_zero_bits && group > 0 {
        // NOTE: 不允许直接忽略尾随的 NonZero bits.
        ipos -= 1;
        return Err(Error {
            pos: ipos,
            byte: input[ipos],
            kind: ErrorKind::TrailingNonZeroBits,
        });
    }

    Ok(opos)
}


#[inline]
fn encode_to_slice_inner<R: AsRef<[u8]>, W: AsMut<[u8]>>(table: &[u8; 32], input: R, output: &mut W, config: Config) -> usize {
    let input  = input.as_ref();
    let output = output.as_mut();

    let ilen = input.len();

    // Groups Len ( 5 * 8 = 40-bits )
    let n = ilen / 5;
    let r = ilen % 5;

    let mut ipos = 0usize;
    let mut opos = 0usize;

    while ipos < n * 5 {
        let group = u64::from_be_bytes([
            input[ipos + 0], 
            input[ipos + 1], 
            input[ipos + 2], 
            input[ipos + 3], 
            input[ipos + 4], 
            0, 
            0, 
            0, 
        ]);

        output[opos + 0] = table[((group >> 59) & 0x1F) as usize];
        output[opos + 1] = table[((group >> 54) & 0x1F) as usize];
        output[opos + 2] = table[((group >> 49) & 0x1F) as usize];
        output[opos + 3] = table[((group >> 44) & 0x1F) as usize];
        output[opos + 4] = table[((group >> 39) & 0x1F) as usize];
        output[opos + 5] = table[((group >> 34) & 0x1F) as usize];
        output[opos + 6] = table[((group >> 29) & 0x1F) as usize];
        output[opos + 7] = table[((group >> 24) & 0x1F) as usize];

        ipos += 5;
        opos += 8;
    }

    
    // Last bytes ( 0、1、2、4 bytes )
    match r {
        0 => { },
        1 => {
            let group = u64::from_be_bytes([
                input[ipos + 0], 
                0,
                0,
                0,
                0,
                0, 
                0,
                0,
            ]);

            output[opos + 0] = table[((group >> 59) & 0x1F) as usize];
            output[opos + 1] = table[((group >> 54) & 0x1F) as usize];

            if config.no_padding {
                opos += 2;
            } else {
                // PAD-LEN: 6
                output[opos + 2] = b'=';
                output[opos + 3] = b'=';
                output[opos + 4] = b'=';
                output[opos + 5] = b'=';
                output[opos + 6] = b'=';
                output[opos + 7] = b'=';

                opos += 8;
            }
        },
        2 => {
            let group = u64::from_be_bytes([
                input[ipos + 0], 
                input[ipos + 1], 
                0,
                0,
                0,
                0,
                0,
                0,
            ]);

            output[opos + 0] = table[((group >> 59) & 0x1F) as usize];
            output[opos + 1] = table[((group >> 54) & 0x1F) as usize];
            output[opos + 2] = table[((group >> 49) & 0x1F) as usize];
            output[opos + 3] = table[((group >> 44) & 0x1F) as usize];

            if config.no_padding {
                opos += 4;
            } else {
                // PAD-LEN: 4
                output[opos + 4] = b'=';
                output[opos + 5] = b'=';
                output[opos + 6] = b'=';
                output[opos + 7] = b'=';

                opos += 8;
            }
        },
        3 => {
            let group = u64::from_be_bytes([
                input[ipos + 0], 
                input[ipos + 1], 
                input[ipos + 2], 
                0,
                0,
                0,
                0,
                0,
            ]);

            output[opos + 0] = table[((group >> 59) & 0x1F) as usize];
            output[opos + 1] = table[((group >> 54) & 0x1F) as usize];
            output[opos + 2] = table[((group >> 49) & 0x1F) as usize];
            output[opos + 3] = table[((group >> 44) & 0x1F) as usize];
            output[opos + 4] = table[((group >> 39) & 0x1F) as usize];

            if config.no_padding {
                opos += 5;
            } else {
                // PAD-LEN: 3
                output[opos + 5] = b'=';
                output[opos + 6] = b'=';
                output[opos + 7] = b'=';

                opos += 8;
            }
        },
        4 => {
            let group = u64::from_be_bytes([
                input[ipos + 0], 
                input[ipos + 1], 
                input[ipos + 2], 
                input[ipos + 3], 
                0,
                0,
                0,
                0,
            ]);

            output[opos + 0] = table[((group >> 59) & 0x1F) as usize];
            output[opos + 1] = table[((group >> 54) & 0x1F) as usize];
            output[opos + 2] = table[((group >> 49) & 0x1F) as usize];
            output[opos + 3] = table[((group >> 44) & 0x1F) as usize];
            output[opos + 4] = table[((group >> 39) & 0x1F) as usize];
            output[opos + 5] = table[((group >> 34) & 0x1F) as usize];
            output[opos + 6] = table[((group >> 29) & 0x1F) as usize];

            if config.no_padding {
                opos += 7;
            } else {
                // PAD-LEN: 1
                output[opos + 7] = b'=';

                opos += 8;
            }
        },
        _ => unreachable!(),
    }
    
    opos
}


#[test]
fn test_base32() {
    // 10.  Test Vectors
    // https://tools.ietf.org/html/rfc4648#section-10

    // Standard encode/decode
    assert_eq!(encode(""), "");
    assert_eq!(encode("f"), "MY======");
    assert_eq!(encode("fo"), "MZXQ====");
    assert_eq!(encode("foo"), "MZXW6===");
    assert_eq!(encode("foob"), "MZXW6YQ=");
    assert_eq!(encode("fooba"), "MZXW6YTB");
    assert_eq!(encode("foobar"), "MZXW6YTBOI======");

    assert_eq!(decode("").unwrap(), b"");
    assert_eq!(decode("MY======").unwrap(), b"f");
    assert_eq!(decode("MZXQ====").unwrap(), b"fo");
    assert_eq!(decode("MZXW6===").unwrap(), b"foo");
    assert_eq!(decode("MZXW6YQ=").unwrap(), b"foob");
    assert_eq!(decode("MZXW6YTB").unwrap(), b"fooba");
    assert_eq!(decode("MZXW6YTBOI======").unwrap(), b"foobar");

    // URL-SAFE encode/decode (BASE32-HEX)
    assert_eq!(urlsafe_encode(""), "");
    assert_eq!(urlsafe_encode("f"), "CO======");
    assert_eq!(urlsafe_encode("fo"), "CPNG====");
    assert_eq!(urlsafe_encode("foo"), "CPNMU===");
    assert_eq!(urlsafe_encode("foob"), "CPNMUOG=");
    assert_eq!(urlsafe_encode("fooba"), "CPNMUOJ1");
    assert_eq!(urlsafe_encode("foobar"), "CPNMUOJ1E8======");

    assert_eq!(urlsafe_decode("").unwrap(), b"");
    assert_eq!(urlsafe_decode("CO======").unwrap(), b"f");
    assert_eq!(urlsafe_decode("CPNG====").unwrap(), b"fo");
    assert_eq!(urlsafe_decode("CPNMU===").unwrap(), b"foo");
    assert_eq!(urlsafe_decode("CPNMUOG=").unwrap(), b"foob");
    assert_eq!(urlsafe_decode("CPNMUOJ1").unwrap(), b"fooba");
    assert_eq!(urlsafe_decode("CPNMUOJ1E8======").unwrap(), b"foobar");
}


#[cfg(test)]
#[bench]
fn bench_encode_slice(b: &mut test::Bencher) {
    let input = b"foobar";
    let ilen = input.len();
    let olen = encode_buffer_len(ilen, DEFAULT_CONFIG);

    let mut output = vec![0u8; olen];

    b.iter(|| {
        encode_to_slice(input, &mut output)
    })
}

#[cfg(test)]
#[bench]
fn bench_decode_slice(b: &mut test::Bencher) {
    let input = b"MZXW6YTBOI======";
    let ilen = input.len();
    let olen = decode_buffer_len(ilen);

    let mut output = vec![0u8; olen];

    b.iter(|| {
        decode_to_slice(input, &mut output).unwrap()
    })
}

#[cfg(test)]
#[bench]
fn bench_encode(b: &mut test::Bencher) {
    let input = b"foobar";

    b.iter(|| {
        encode(input)
    })
}

#[cfg(test)]
#[bench]
fn bench_decode(b: &mut test::Bencher) {
    let input = b"MZXW6YTBOI======";

    b.iter(|| {
        decode(input).unwrap()
    })
}


#[cfg(test)]
#[bench]
fn bench_crate_encode(b: &mut test::Bencher) {
    use base32::Alphabet;

    let input = b"foobar";

    let alphabet = Alphabet::RFC4648 { padding: true };
    b.iter(|| {
        base32::encode(alphabet, input)
    })
}

#[cfg(test)]
#[bench]
fn bench_crate_decode(b: &mut test::Bencher) {
    use base32::Alphabet;

    let input = "MZXW6YTBOI======";

    let alphabet = Alphabet::RFC4648 { padding: true };
    b.iter(|| {
        base32::decode(alphabet, input).unwrap()
    })
}