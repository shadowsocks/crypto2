#![cfg_attr(test, feature(test))]
#![feature(stdsimd, llvm_asm)]
#![allow(unused_macros, unused_assignments)]

#[cfg(test)]
extern crate test;

#[cfg(test)]
extern crate hex;

pub mod mem;
mod util;

// cryptographic hash function (CHF)
pub mod hash;

// Key derivation function (KDF)
pub mod kdf;

pub mod mac;

pub mod blockmode;

pub mod aeadcipher;
pub mod blockcipher;
pub mod streamcipher;

#[cfg(feature = "openssh")]
pub mod openssh;
