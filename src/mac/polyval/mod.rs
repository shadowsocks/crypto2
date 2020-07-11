#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), all(target_feature = "sse2", target_feature = "pclmulqdq")))]
#[path = "./x86.rs"]
mod platform;

// NOTE:
//      Crypto: AES + PMULL + SHA1 + SHA2
//      https://github.com/rust-lang/stdarch/blob/master/crates/std_detect/src/detect/arch/aarch64.rs#L26
#[cfg(all(target_arch = "aarch64", target_feature = "crypto"))]
#[path = "./aarch64.rs"]
mod platform;


#[cfg(not(any(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        all(target_feature = "sse2", target_feature = "pclmulqdq")
    ),
    all(target_arch = "aarch64", target_feature = "crypto")
)))]
#[path = "./generic.rs"]
mod platform;

pub use self::platform::Polyval;