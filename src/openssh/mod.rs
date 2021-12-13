// chacha20-poly1305@openssh.com
//
// http://bxr.su/OpenBSD/usr.bin/ssh/PROTOCOL.chacha20poly1305
// https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-03
//
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/PROTOCOL.chacha20poly1305
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/chacha.c
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/chacha.h
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/poly1305.c
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/poly1305.h
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/cipher-chachapoly.c
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/cipher-chachapoly.h
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/cipher-chachapoly-libcrypto.c

mod chacha20_poly1305;

pub use self::chacha20_poly1305::*;
