// Uniform Resource Identifier (URI): Generic Syntax
//   2.1.  Percent-Encoding
// https://tools.ietf.org/html/rfc3986#section-2.1
// 
// 1.3. Percent-encoded bytes
// https://url.spec.whatwg.org/#percent-encoded-bytes
// 
// gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
// sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
// 
// reserved    = gen-delims / sub-delims
// unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
use super::base16::from_hexdigits;


static TABLE: [&[u8]; 256] = [
    b"%00" , b"%01" , b"%02" , b"%03" , b"%04" , b"%05" , b"%06" , b"%07" , b"%08" , b"%09" , b"%0a" , b"%0b" , b"%0c" , b"%0d" , b"%0e" , b"%0f" ,
    b"%10" , b"%11" , b"%12" , b"%13" , b"%14" , b"%15" , b"%16" , b"%17" , b"%18" , b"%19" , b"%1a" , b"%1b" , b"%1c" , b"%1d" , b"%1e" , b"%1f" ,
//                                                                                                                          b'-'    b'.'
    b"%20" , b"%21" , b"%22" , b"%23" , b"%24" , b"%25" , b"%26" , b"%27" , b"%28" , b"%29" , b"%2a" , b"%2b" , b"%2c" , b"\x2d", b"\x2e", b"%2f" ,
//       0        1        2        3        4        5        6        7        8        9
    b"\x30", b"\x31", b"\x32", b"\x33", b"\x34", b"\x35", b"\x36", b"\x37", b"\x38", b"\x39", b"%3a" , b"%3b" , b"%3c" , b"%3d" , b"%3e" , b"%3f" ,
//                A        B        C        D        E        F        G        H        I        J        K        L        M        N        O
    b"%40" , b"\x41", b"\x42", b"\x43", b"\x44", b"\x45", b"\x46", b"\x47", b"\x48", b"\x49", b"\x4a", b"\x4b", b"\x4c", b"\x4d", b"\x4e", b"\x4f",
//       P        Q        R        S        T        U        V        W        X        Y        Z                                          b'_'
    b"\x50", b"\x51", b"\x52", b"\x53", b"\x54", b"\x55", b"\x56", b"\x57", b"\x58", b"\x59", b"\x5a", b"%5b" , b"%5c" , b"%5d" , b"%5e" , b"\x5f",
//                a        b        c        d        e        f        g        h        i        j        k        l        m        n        o
    b"%60" , b"\x61", b"\x62", b"\x63", b"\x64", b"\x65", b"\x66", b"\x67", b"\x68", b"\x69", b"\x6a", b"\x6b", b"\x6c", b"\x6d", b"\x6e", b"\x6f",
//       p        q        r        s        t        u        v        w        x        y        z                                 b'~'
    b"\x70", b"\x71", b"\x72", b"\x73", b"\x74", b"\x75", b"\x76", b"\x77", b"\x78", b"\x79", b"\x7a", b"%7b" , b"%7c" , b"%7d" , b"\x7e", b"%7f" ,

    b"%80" , b"%81" , b"%82" , b"%83" , b"%84" , b"%85" , b"%86" , b"%87" , b"%88" , b"%89" , b"%8a" , b"%8b" , b"%8c" , b"%8d" , b"%8e" , b"%8f" ,
    b"%90" , b"%91" , b"%92" , b"%93" , b"%94" , b"%95" , b"%96" , b"%97" , b"%98" , b"%99" , b"%9a" , b"%9b" , b"%9c" , b"%9d" , b"%9e" , b"%9f" ,
    b"%a0" , b"%a1" , b"%a2" , b"%a3" , b"%a4" , b"%a5" , b"%a6" , b"%a7" , b"%a8" , b"%a9" , b"%aa" , b"%ab" , b"%ac" , b"%ad" , b"%ae" , b"%af" ,
    b"%b0" , b"%b1" , b"%b2" , b"%b3" , b"%b4" , b"%b5" , b"%b6" , b"%b7" , b"%b8" , b"%b9" , b"%ba" , b"%bb" , b"%bc" , b"%bd" , b"%be" , b"%bf" ,
    b"%c0" , b"%c1" , b"%c2" , b"%c3" , b"%c4" , b"%c5" , b"%c6" , b"%c7" , b"%c8" , b"%c9" , b"%ca" , b"%cb" , b"%cc" , b"%cd" , b"%ce" , b"%cf" ,
    b"%d0" , b"%d1" , b"%d2" , b"%d3" , b"%d4" , b"%d5" , b"%d6" , b"%d7" , b"%d8" , b"%d9" , b"%da" , b"%db" , b"%dc" , b"%dd" , b"%de" , b"%df" ,
    b"%e0" , b"%e1" , b"%e2" , b"%e3" , b"%e4" , b"%e5" , b"%e6" , b"%e7" , b"%e8" , b"%e9" , b"%ea" , b"%eb" , b"%ec" , b"%ed" , b"%ee" , b"%ef" ,
    b"%f0" , b"%f1" , b"%f2" , b"%f3" , b"%f4" , b"%f5" , b"%f6" , b"%f7" , b"%f8" , b"%f9" , b"%fa" , b"%fb" , b"%fc" , b"%fd" , b"%fe" , b"%ff" ,
];


#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ErrorKind {
    InvalidHexDigit,
    InvalidUtf8Sequence,
    InvalidEncodedSequence,
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
            ErrorKind::InvalidUtf8Sequence => {
                write!(f, "incomplete utf-8 byte sequence from index {}", self.pos)
            },
            ErrorKind::InvalidEncodedSequence => {
                write!(f, "incomplete percent-encoded sequence from index {}", self.pos)
            },
            ErrorKind::InvalidHexDigit => {
                write!(f, "invalid hex digit from index {}", self.pos)
            },
        }
    }
}

impl std::error::Error for Error { }


pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
    let input = input.as_ref();
    
    let ilen = input.len();
    let ocap = ilen + (6 - 2);
    
    let mut output = Vec::with_capacity(ocap);

    for i in 0..ilen {
        let val = TABLE[input[i] as usize];
        output.extend_from_slice(&val);
    }

    unsafe { String::from_utf8_unchecked(output) }
}

pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<String, Error> {
    let input = input.as_ref();

    let ilen = input.len();
    let ocap = ilen;

    let mut output = Vec::with_capacity(ocap);

    let mut i = 0usize;
    while i < ilen {
        let ch = input[i];
        if ch == b'%' {
            let epos = i + 2;
            if epos >= ilen {
                return Err(Error {
                    pos: i,
                    byte: ch,
                    kind: ErrorKind::InvalidEncodedSequence,
                });
            }

            let val = from_hexdigits(input[i], input[i + 1]).map_err(|_| {
                Error {
                    pos: i,
                    byte: ch,
                    kind: ErrorKind::InvalidHexDigit,
                }
            })?;

            output.push(val);

            i += 3;
        } else {
            output.push(ch);

            i += 1;
        }
    }

    match String::from_utf8(output) {
        Ok(s) => Ok(s),
        Err(e) => {
            let utf8_error = e.utf8_error();
            let bytes = e.into_bytes();
            
            let pos = utf8_error.valid_up_to();
            Err(Error {
                pos: pos,
                byte: bytes[pos],
                kind: ErrorKind::InvalidUtf8Sequence,
            })
        }
    }
}


#[cfg(test)]
#[bench]
fn bench_encode(b: &mut test::Bencher) {
    b.iter(|| {
        encode("foobar==/~")
    })
}

#[cfg(test)]
#[bench]
fn bench_crate_io_percent_encode(b: &mut test::Bencher) {
    use percent_encoding::NON_ALPHANUMERIC;
    use percent_encoding::utf8_percent_encode;

    b.iter(|| {
        utf8_percent_encode("foobar==/~", NON_ALPHANUMERIC).to_string()
    })
}
