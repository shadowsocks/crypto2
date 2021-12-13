// This Standard specifies the Secure Hash Algorithm-3 (SHA-3)
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
//
// C code
// https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c

// 5 KECCAK
//   5.1 Specification of pad10*1
//
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
//
// Input:
//   positive integer x;
//   non-negative integer m.
//
// Output:
//   string P such that m + len(P) is a positive multiple of x.
//
// Steps:
//   1. Let k = (– m – 2) mod x.
//   2. Return P = 1 || 0ᵏ ｜｜ 1.
#[allow(dead_code)]
#[inline]
fn sha3_pad(mlen_bits: usize, x: usize) -> usize {
    let plen_bits = x - (mlen_bits + 2) % x + 2;
    debug_assert_eq!(plen_bits % 8, 0);
    // pad len, in bytes
    let plen = plen_bits / 8;
    debug_assert!(plen > 1);
    plen
}
