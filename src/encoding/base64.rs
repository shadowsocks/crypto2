// The Base16, Base32, and Base64 Data Encodings
// https://tools.ietf.org/html/rfc3548

// 4.  Base 64 Encoding
// https://tools.ietf.org/html/rfc4648#section-4
// 
//                       Table 1: The Base 64 Alphabet
// 
//      Value Encoding  Value Encoding  Value Encoding  Value Encoding
//          0 A            17 R            34 i            51 z
//          1 B            18 S            35 j            52 0
//          2 C            19 T            36 k            53 1
//          3 D            20 U            37 l            54 2
//          4 E            21 V            38 m            55 3
//          5 F            22 W            39 n            56 4
//          6 G            23 X            40 o            57 5
//          7 H            24 Y            41 p            58 6
//          8 I            25 Z            42 q            59 7
//          9 J            26 a            43 r            60 8
//         10 K            27 b            44 s            61 9
//         11 L            28 c            45 t            62 +
//         12 M            29 d            46 u            63 /
//         13 N            30 e            47 v
//         14 O            31 f            48 w         (pad) =
//         15 P            32 g            49 x
//         16 Q            33 h            50 y
// 
// 5.  Base 64 Encoding with URL and Filename Safe Alphabet
// https://tools.ietf.org/html/rfc4648#section-5
// 
//          Table 2: The "URL and Filename safe" Base 64 Alphabet
// 
//      Value Encoding  Value Encoding  Value Encoding  Value Encoding
//          0 A            17 R            34 i            51 z
//          1 B            18 S            35 j            52 0
//          2 C            19 T            36 k            53 1
//          3 D            20 U            37 l            54 2
//          4 E            21 V            38 m            55 3
//          5 F            22 W            39 n            56 4
//          6 G            23 X            40 o            57 5
//          7 H            24 Y            41 p            58 6
//          8 I            25 Z            42 q            59 7
//          9 J            26 a            43 r            60 8
//         10 K            27 b            44 s            61 9
//         11 L            28 c            45 t            62 - (minus)
//         12 M            29 d            46 u            63 _
//         13 N            30 e            47 v           (underline)
//         14 O            31 f            48 w
//         15 P            32 g            49 x
//         16 Q            33 h            50 y         (pad) =
static URL_SAFE_TABLE: [u8; 64] = [
//    A     B     C     D     E     F     G     H     I     J     K     L     M     N     O     P   
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
//    Q     R     S     T     U     V     W     X     Y     Z     a     b     c     d     e     f  
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 
//    g     h     i     j     k     l     m     n     o     p     q     r     s     t     u     v 
    0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
//    w     x     y     z      0     1     2     3     4     5     6     7     8     9  b'-', b'_', 
    0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2d, 0x5f, 
];

static STANDARD_TABLE: [u8; 64] = [
//    A     B     C     D     E     F     G     H     I     J     K     L     M     N     O     P   
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
//    Q     R     S     T     U     V     W     X     Y     Z     a     b     c     d     e     f  
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 
//    g     h     i     j     k     l     m     n     o     p     q     r     s     t     u     v 
    0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
//    w     x     y     z      0     1     2     3     4     5     6     7     8     9  b'+', b'/', 
    0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2b, 0x2f, 
];


// invalid base64 characters
const ____: u8 = 0xff;
const _EXT: u8 = 0xfe; // PADDED.

static URL_SAFE_DECODE_TABLE: [u8; 256] = [
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
//                                                                                 b'-'
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 0x3e, ____, ____, 
//    0     1     2     3     4     5     6     7     8     9                     b'='
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, ____, ____, ____, _EXT, ____, ____, 
//          A     B     C     D     E     F     G     H     I     J     K     L     M     N     O
    ____, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 
//    P     Q     R     S     T     U     V     W     X     Y     Z                            b'_'
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, ____, ____, ____, ____, 0x3f, 
//          a     b     c     d     e     f     g     h     i     j     k     l     m     n     o
    ____, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 
//    p     q     r     s     t     u     v     w     x     y     z
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, ____, ____, ____, ____, ____, 

    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
];

static STANDARD_DECODE_TABLE: [u8; 256] = [
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
//                                                                    b'+'                    b'/'
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 0x3e, ____, ____, ____, 0x3f, 
//    0     1     2     3     4     5     6     7     8     9                     b'='
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, ____, ____, ____, _EXT, ____, ____, 
//          A     B     C     D     E     F     G     H     I     J     K     L     M     N     O
    ____, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 
//    P     Q     R     S     T     U     V     W     X     Y     Z
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, ____, ____, ____, ____, ____, 
//          a     b     c     d     e     f     g     h     i     j     k     l     m     n     o
    ____, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 
//    p     q     r     s     t     u     v     w     x     y     z
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, ____, ____, ____, ____, ____, 

    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
];





#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ErrorKind {
    InvalidCodedCharacter,
    InvalidPaddingCharacter,
    InvalidPaddingLength,
    TrailingSixBits,
    TrailingUnPaddedBits,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Error {
    pos: usize,
    byte: u8,
    kind: ErrorKind,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self.kind {
            ErrorKind::InvalidCodedCharacter => {
                write!(f, "invalid character `{}`({:#x}) at input postion {}", self.byte as char, self.byte, self.pos)
            },
            ErrorKind::InvalidPaddingCharacter => {
                write!(f, "invalid padding character `{}`({:#x}) at input postion {}", self.byte as char, self.byte, self.pos)
            },
            _ => {
                write!(f, "invalid data")
            },
        }
    }
}

impl std::error::Error for Error { }


#[inline]
pub fn decode_buffer_len(ilen: usize) -> usize {
    let n = ilen / 4;
    let r = ilen % 4;
    
    let olen = if r > 0 { n * 3 + 3 } else { n * 3 };

    olen
}

#[inline]
pub fn encode_buffer_len(ilen: usize) -> usize {
    // Groups Len ( 6 * 3 = 24-bits )
    let n = ilen / 3;
    let r = ilen % 3;

    // NO-PAD
    // let olen = match r {
    //     0 => n * 4,
    //     1 => n * 4 + 2,
    //     2 => n * 4 + 3,
    //     _ => unreachable!(),
    // };

    // PAD
    let olen = if r > 0 { n * 4 + 4 } else { n * 4 };

    olen
}

pub fn decode<D: AsRef<[u8]>>(input: D) -> Result<Vec<u8>, Error> {
    let input = input.as_ref();
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let ilen = input.len();
    let olen = decode_buffer_len(ilen);

    let mut output = vec![0u8; olen];

    let amt = decode_to_slice(input, &mut output)?;
    if amt < olen {
        output.truncate(amt);
    }

    Ok(output)
}

pub fn urlsafe_decode<D: AsRef<[u8]>>(input: D) -> Result<Vec<u8>, Error> {
    let input = input.as_ref();
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let ilen = input.len();
    let olen = decode_buffer_len(ilen);

    let mut output = vec![0u8; olen];

    let amt = urlsafe_decode_to_slice(input, &mut output)?;
    if amt < olen {
        output.truncate(amt);
    }

    Ok(output)
}

#[inline]
pub fn decode_to_slice<R: AsRef<[u8]>, W: AsMut<[u8]>>(input: R, output: &mut W) -> Result<usize, Error> {
    decode_to_slice_inner(&STANDARD_DECODE_TABLE, input, output)
}

#[inline]
pub fn urlsafe_decode_to_slice<R: AsRef<[u8]>, W: AsMut<[u8]>>(input: R, output: &mut W) -> Result<usize, Error> {
    decode_to_slice_inner(&URL_SAFE_DECODE_TABLE, input, output)
}

#[inline]
fn decode_to_slice_inner<R: AsRef<[u8]>, W: AsMut<[u8]>>(table: &[u8; 256], input: R, output: &mut W) -> Result<usize, Error> {
    let input  = input.as_ref();
    let output = output.as_mut();

    let ilen = input.len();

    let mut ipos  = 0usize; // input data index
    let mut opos  = 0usize; // output data index

    let mut group = 0u32;   // 3 bytes encode to 4 base64 character.
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
                const MAX_PADDING_LEN: usize = 2;

                plen  = 1;
                ipos += 1;

                while ipos < ilen {
                    let val = table[input[ipos] as usize];
                    // NOTE: 确保 PADDING-CHARACTER 为 字符 `=`，
                    //       以及确保 PADDING-LEN 没有超出最大值。
                    if val != _EXT || plen >= MAX_PADDING_LEN {
                        return Err(Error {
                            pos: ipos,
                            byte: input[ipos],
                            kind: if val != _EXT {
                                ErrorKind::InvalidPaddingCharacter
                            } else {
                                ErrorKind::InvalidPaddingLength
                            },
                        });
                    }

                    ipos += 1;
                    plen += 1;
                }

                // NOTE: 经过 PADDING 后的 input 数据，长度应为 4 的倍数。
                if ilen % 4 > 0 {
                    return Err(Error {
                        pos: ipos,
                        byte: input[ipos - 1],
                        kind: ErrorKind::InvalidPaddingLength,
                    });
                }

                break;
            },
            _ => {
                match gpos {
                    0 => {
                        group = (val as u32) << 26;
                        gpos = 6;
                    },
                    6 => {
                        group |= (val as u32) << 20;
                        gpos = 12;
                    },
                    12 => {
                        group |= (val as u32) << 14;
                        gpos = 18;
                    },
                    18 => {
                        group |= (val as u32) << 8;
                        let [b1, b2, b3, _] = group.to_be_bytes();

                        output[opos + 0] = b1;
                        output[opos + 1] = b2;
                        output[opos + 2] = b3;

                        opos += 3;
                        gpos  = 0;
                    },
                    _ => unreachable!(),
                }

                ipos += 1;
            }
        }
    }

    // Check trailing bits
    match gpos {
        0 => {

        },
        6 => {
            // Last 6-bits was droped.
            let [b1, _, _, _] = group.to_be_bytes();

            ipos -= 1;
            return Err(Error {
                pos: ipos,
                byte: input[ipos],
                kind: ErrorKind::TrailingSixBits,
            });
        },
        12 => {
            // Last 4-bits was droped.
            let [b1, b2, _, _] = group.to_be_bytes();
            
            output[opos + 0] = b1;

            opos += 1;

            if plen != 2 {
                ipos -= 1;
                return Err(Error {
                    pos: ipos,
                    byte: input[ipos],
                    kind: ErrorKind::TrailingUnPaddedBits,
                });
            }
        },
        18 => {
            // Last 2-bits was droped.
            let [b1, b2, b3, _] = group.to_be_bytes();

            output[opos + 0] = b1;
            output[opos + 1] = b2;

            opos += 2;

            if plen != 1 {
                ipos -= 1;
                return Err(Error {
                    pos: ipos,
                    byte: input[ipos],
                    kind: ErrorKind::TrailingUnPaddedBits,
                });
            }
        },
        _ => unreachable!(),
    }

    Ok(opos)
}



pub fn encode<D: AsRef<[u8]>>(input: D) -> String {
    let input = input.as_ref();
    if input.is_empty() {
        return String::new();
    }

    let ilen = input.len();
    let olen = encode_buffer_len(ilen);

    let mut output = vec![b'='; olen];

    encode_to_slice(input, &mut output);

    unsafe { String::from_utf8_unchecked(output) }
}

pub fn urlsafe_encode<D: AsRef<[u8]>>(input: D) -> String {
    let input = input.as_ref();
    if input.is_empty() {
        return String::new();
    }

    let ilen = input.len();
    let olen = encode_buffer_len(ilen);

    let mut output = vec![b'='; olen];

    urlsafe_encode_to_slice(input, &mut output);

    unsafe { String::from_utf8_unchecked(output) }
}

#[inline]
pub fn encode_to_slice<D: AsRef<[u8]>, W: AsMut<[u8]>>(input: D, output: &mut W) {
    encode_to_slice_inner(&STANDARD_TABLE, input, output);
}

#[inline]
pub fn urlsafe_encode_to_slice<D: AsRef<[u8]>, W: AsMut<[u8]>>(input: D, output: &mut W) {
    encode_to_slice_inner(&URL_SAFE_TABLE, input, output);
}

#[inline]
fn encode_to_slice_inner<R: AsRef<[u8]>, W: AsMut<[u8]>>(table: &[u8; 64], input: R, output: &mut W) {
    let input  = input.as_ref();
    let output = output.as_mut();

    let ilen = input.len();

    // Groups Len ( 6 * 3 = 24-bits )
    let n = ilen / 3;
    let r = ilen % 3;

    let mut i = 0usize;
    while i < n {
        let num = u32::from_be_bytes([
            input[i * 3 + 0], 
            input[i * 3 + 1], 
            input[i * 3 + 2], 
            0,
        ]);

        output[i * 4 + 0] = table[((num >> 26) & 0x3F) as usize];
        output[i * 4 + 1] = table[((num >> 20) & 0x3F) as usize];
        output[i * 4 + 2] = table[((num >> 14) & 0x3F) as usize];
        output[i * 4 + 3] = table[((num >>  8) & 0x3F) as usize];

        i += 1;
    }

    // Last bytes ( 1 or 2 bytes )
    match r {
        0 => { },
        1 => {
            let num = u32::from_be_bytes([
                input[i * 3 + 0], 
                0, 
                0,
                0,
            ]);

            output[i * 4 + 0] = table[((num >> 26) & 0x3F) as usize];
            output[i * 4 + 1] = table[((num >> 20) & 0x3F) as usize];

            // PAD-LEN: 2
            // output[i * 4 + 2] = b'=';
            // output[i * 4 + 3] = b'=';
        },
        2 => {
            let num = u32::from_be_bytes([
                input[i * 3 + 0], 
                input[i * 3 + 1], 
                0,
                0,
            ]);

            output[i * 4 + 0] = table[((num >> 26) & 0x3F) as usize];
            output[i * 4 + 1] = table[((num >> 20) & 0x3F) as usize];
            output[i * 4 + 2] = table[((num >> 14) & 0x3F) as usize];

            // PAD-LEN: 1
            // output[i * 4 + 3] = b'=';
        },
        _ => unreachable!(),
    }
}


// 7. Forgiving base64
// https://infra.spec.whatwg.org/#forgiving-base64
// 
// ASCII whitespace is U+0009 TAB, U+000A LF, U+000C FF, U+000D CR, or U+0020 SPACE.
// 0x09 0x0a 0x0c 0x0d 0x20
// 
// const TAB: u8   = 0x09; //  9 \t
// const LF: u8    = 0x0a; // 10 \n
// const FF: u8    = 0x0c; // 12
// const CR: u8    = 0x0d; // 13 \r
// const SPACE: u8 = 0x20; // 32

const SKIP: u8 = 0xfd;
const PADB: u8 = 0x3d; // b'='
static FORGIVING_TABLE_INV: [u8; 256] = [
//                                                        b'\t' b'\n'       0x0c  b'\r'
    ____, ____, ____, ____, ____, ____, ____, ____, ____, SKIP, SKIP, ____, SKIP, SKIP, ____, ____, 
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 
//  b' '                                                              b'+'                    b'/'
    SKIP, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, 0x3e, ____, ____, ____, 0x3f, 
//    0     1     2     3     4     5     6     7     8     9                     b'='
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, ____, ____, ____, ____, ____, ____, 
//          A     B     C     D     E     F     G     H     I     J     K     L     M     N     O
    ____, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 
//    P     Q     R     S     T     U     V     W     X     Y     Z
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, ____, ____, ____, ____, ____, 
//          a     b     c     d     e     f     g     h     i     j     k     l     m     n     o
    ____, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 
//    p     q     r     s     t     u     v     w     x     y     z
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, ____, ____, ____, ____, ____, 

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
pub fn forgiving_decode<R: AsRef<[u8]>>(input: R) -> Result<Vec<u8>, Error> {
    let input = input.as_ref();
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let ilen = input.len();
    let olen = decode_buffer_len(ilen);

    let mut output = vec![0u8; olen];

    let amt = forgiving_decode_to_slice(input, &mut output)?;
    if amt < olen {
        output.truncate(amt);
    }

    Ok(output)
}

#[inline]
fn forgiving_decode_to_slice<R: AsRef<[u8]>, W: AsMut<[u8]>>(input: R, output: &mut W) -> Result<usize, Error> {
    let input  = input.as_ref();
    let output = output.as_mut();

    let ilen = input.len();

    let mut ipos  = 0usize; // input data index
    let mut opos  = 0usize; // output data index

    let mut group = 0u32;   // 3 bytes encode to 4 base64 character.
    let mut gpos  = 0u8;    // group bit index

    // 1. Remove all ASCII whitespace from data.
    let mut sp_len  = 0usize;
    for i in 0..ilen {
        let v = FORGIVING_TABLE_INV[input[i] as usize];
        if v == SKIP {
            sp_len += 1;
        } 
    }

    // PADDING-LEN
    let pad_len = {
        let mut len = 0usize;
        let mut i = ilen;
        while i > 0 {
            if input[i - 1] == PADB {
                len += 1;
                i -= 1;
            } else {
                break;
            }
        }

        len
    };

    if pad_len > 2 {
        return Err(Error {
            pos: 0,
            byte: input[0],
            kind: ErrorKind::InvalidPaddingLength,
        });
    }

    // 2. If data’s code point length divides by 4 leaving no remainder, then:
    let mut dlen = ilen - sp_len;
    if dlen % 4 == 0 {
        // 2-1. If data ends with one or two U+003D (=) code points, then remove them from data.
        dlen -= pad_len;
    }
    // 3. If data’s code point length divides by 4 leaving a remainder of 1, then return failure.
    if dlen % 4 == 1 {
        return Err(Error {
            pos: 0,
            byte: input[0],
            kind: ErrorKind::TrailingUnPaddedBits,
        });
    }

    let input = &input[..ilen - pad_len];

    let ilen = input.len();

    while ipos < ilen {
        let val = FORGIVING_TABLE_INV[input[ipos] as usize];
        match val {
            ____ => {
                return Err(Error {
                    pos: ipos,
                    byte: input[ipos],
                    kind: ErrorKind::InvalidCodedCharacter,
                });
            },
            SKIP => {
                ipos += 1;
            },
            _ => {
                match gpos {
                    0 => {
                        group = (val as u32) << 26;
                        gpos = 6;
                    },
                    6 => {
                        group |= (val as u32) << 20;
                        gpos = 12;
                    },
                    12 => {
                        group |= (val as u32) << 14;
                        gpos = 18;
                    },
                    18 => {
                        group |= (val as u32) << 8;
                        let [b1, b2, b3, _] = group.to_be_bytes();

                        output[opos + 0] = b1;
                        output[opos + 1] = b2;
                        output[opos + 2] = b3;

                        opos += 3;
                        gpos  = 0;
                    },
                    _ => unreachable!(),
                }

                ipos += 1;
            }
        }
    }

    // Check trailing bits
    match gpos {
        0 => {

        },
        6 => {
            // Last 6-bits was droped.
            unreachable!()
        },
        12 => {
            // Last 4-bits was droped.
            // 
            // If it contains 12 bits, then discard the last four and interpret the remaining eight as an 8-bit big-endian number.
            let [b1, b2, _, _] = group.to_be_bytes();
            
            output[opos + 0] = b1;

            opos += 1;
        },
        18 => {
            // Last 2-bits was droped.
            // 
            // If it contains 18 bits, then discard the last two and interpret the remaining 16 as two 8-bit big-endian numbers.
            let [b1, b2, b3, _] = group.to_be_bytes();

            output[opos + 0] = b1;
            output[opos + 1] = b2;

            opos += 2;
        },
        _ => unreachable!(),
    }

    Ok(opos)
}

#[test]
fn test_base64() {
    // 10.  Test Vectors
    // https://tools.ietf.org/html/rfc4648#section-10

    // Standard encode/decode
    assert_eq!(encode(""), "");
    assert_eq!(encode("f"), "Zg==");
    assert_eq!(encode("fo"), "Zm8=");
    assert_eq!(encode("foo"), "Zm9v");
    assert_eq!(encode("foob"), "Zm9vYg==");
    assert_eq!(encode("fooba"), "Zm9vYmE=");
    assert_eq!(encode("foobar"), "Zm9vYmFy");
    
    assert_eq!(decode("").unwrap(), b"");
    assert_eq!(decode("Zg==").unwrap(), b"f");
    assert_eq!(decode("Zm8=").unwrap(), b"fo");
    assert_eq!(decode("Zm9v").unwrap(), b"foo");
    assert_eq!(decode("Zm9vYg==").unwrap(), b"foob");
    assert_eq!(decode("Zm9vYmE=").unwrap(), b"fooba");
    assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");

    // URL-SAFE encode/decode
    assert_eq!(urlsafe_decode(urlsafe_encode("")).unwrap(), b"");
    assert_eq!(urlsafe_decode(urlsafe_encode("f")).unwrap(), b"f");
    assert_eq!(urlsafe_decode(urlsafe_encode("fo")).unwrap(), b"fo");
    assert_eq!(urlsafe_decode(urlsafe_encode("foo")).unwrap(), b"foo");
    assert_eq!(urlsafe_decode(urlsafe_encode("foob")).unwrap(), b"foob");
    assert_eq!(urlsafe_decode(urlsafe_encode("fooba")).unwrap(), b"fooba");
    assert_eq!(urlsafe_decode(urlsafe_encode("foobar")).unwrap(), b"foobar");

    // Base64
    //   Examples
    // https://en.wikipedia.org/wiki/Base64#Examples
    let input = "Man is distinguished, not only by his reason, but by this singular passion from other animals, \
which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable \
generation of knowledge, exceeds the short vehemence of any carnal pleasure.";
    let output = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz\
IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg\
dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu\
dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo\
ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=";
    assert_eq!(encode(input), output);
}

#[test]
fn test_base64_trailing_bits() {
    assert_eq!(encode("a"), "YQ==");
    assert_eq!(encode("a\u{10}"), "YRA=");

    assert!(decode("YQ").is_err());
    assert!(decode("YQ=").is_err());
    assert_eq!(std::str::from_utf8(&decode("YQ==").unwrap()), Ok("a"));

    assert!(decode("YR").is_err());
    assert!(decode("YR=").is_err());
    assert!(decode("YRA").is_err());
    assert_eq!(std::str::from_utf8(&decode("YR==").unwrap()), Ok("a"));
    assert_eq!(std::str::from_utf8(&decode("YRA=").unwrap()), Ok("a\u{10}"));
}


#[test]
fn test_forgiving_decode() {
    // https://infra.spec.whatwg.org/#forgiving-base64
    assert_eq!(std::str::from_utf8(&forgiving_decode("YQ").unwrap()), Ok("a"));
    assert_eq!(std::str::from_utf8(&forgiving_decode("YR").unwrap()), Ok("a"));
}

#[cfg(test)]
#[bench]
fn bench_encode(b: &mut test::Bencher) {
    let input = b"fooba";
    let ilen = input.len();
    let olen = encode_buffer_len(ilen);

    let mut output = vec![b'='; olen];

    b.iter(|| {
        encode_to_slice(input, &mut output)
    })
}

#[cfg(test)]
#[bench]
fn bench_decode(b: &mut test::Bencher) {
    let input = b"Zm9vYmE=";
    let ilen = input.len();
    let olen = decode_buffer_len(ilen);

    let mut output = vec![0u8; olen];

    b.iter(|| {
        decode_to_slice(input, &mut output).unwrap()
    })
}

// Result:
// 
// test base64::bench_crate_decode     ... bench:          31 ns/iter (+/- 5)
// test base64::bench_crate_encode     ... bench:          14 ns/iter (+/- 1)
// test base64::bench_decode           ... bench:           7 ns/iter (+/- 2)
// test base64::bench_encode           ... bench:           4 ns/iter (+/- 0)
// 
// so fast :)


// #[bench]
// fn bench_crate_encode(b: &mut test::Bencher) {
//     use base64 as base64_raw;

//     let input = b"fooba";
//     let ilen = input.len();
//     let olen = encode_buffer_len(ilen);

//     let mut output = vec![b'='; olen];

//     b.iter(|| {
//         base64_raw::encode_config_slice(input, base64_raw::STANDARD, &mut output)
//     })
// }

// #[bench]
// fn bench_crate_decode(b: &mut test::Bencher) {
//     use base64 as base64_raw;

//     let input = b"Zm9vYmE=";
//     let ilen = input.len();
//     let olen = decode_buffer_len(ilen);

//     let mut output = vec![0u8; olen];

//     b.iter(|| {
//         base64_raw::decode_config_slice(input, base64_raw::STANDARD, &mut output).unwrap()
//     })
// }