#![cfg_attr(test, feature(test))]
#![feature(stdsimd)]
#![allow(unused_macros, unused_assignments)]

#[cfg(test)]
extern crate test;


mod util;
pub mod mem;


// cryptographic hash function (CHF)
pub mod hash;

// Key derivation function (KDF)
pub mod kdf;

pub mod mac;

pub mod blockmode;

pub mod blockcipher;
pub mod streamcipher;
pub mod aeadcipher;


#[cfg(feature = "openssh")]
pub mod openssh;

pub mod encoding;

// pub mod simd;