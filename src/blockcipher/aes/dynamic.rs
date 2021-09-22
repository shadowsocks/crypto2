use std::fmt::{self, Debug};

use super::generic;
use super::platform;

macro_rules! impl_dynamic_dispatch {
    ($name:ident) => {
        #[derive(Clone)]
        pub enum $name {
            Generic(generic::$name),
            Platform(platform::$name),
        }

        impl Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match *self {
                    $name::Generic(ref d) => Debug::fmt(d, f),
                    $name::Platform(ref d) => Debug::fmt(d, f),
                }
            }
        }

        impl $name {
            pub const KEY_LEN: usize = generic::$name::KEY_LEN;
            pub const BLOCK_LEN: usize = generic::$name::BLOCK_LEN;

            #[inline]
            pub fn new(key: &[u8]) -> $name {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2") {
                    return $name::Platform(platform::$name::new(key));
                }

                #[cfg(target_arch = "aarch64")]
                if std::is_aarch64_feature_detected!("aes") {
                    return $name::Platform(platform::$name::new(key));
                }

                $name::Generic(generic::$name::new(key))
            }

            #[inline]
            pub fn encrypt(&self, plaintext_in_ciphertext_out: &mut [u8]) {
                match *self {
                    $name::Generic(ref c) => c.encrypt(plaintext_in_ciphertext_out),
                    $name::Platform(ref c) => c.encrypt(plaintext_in_ciphertext_out),
                }
            }

            #[inline]
            pub fn decrypt(&self, ciphertext_in_plaintext_out: &mut [u8]) {
                match *self {
                    $name::Generic(ref c) => c.decrypt(ciphertext_in_plaintext_out),
                    $name::Platform(ref c) => c.decrypt(ciphertext_in_plaintext_out),
                }
            }
        }
    };
}

impl_dynamic_dispatch!(Aes128);
impl_dynamic_dispatch!(Aes192);
impl_dynamic_dispatch!(Aes256);
