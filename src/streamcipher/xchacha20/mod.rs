
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(target_feature = "sse2", target_feature = "avx2")
))]
#[path = "./x86.rs"]
mod platform;


#[cfg(not(any(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        any(target_feature = "sse2", target_feature = "avx2")
    ),
    // all(target_arch = "aarch64", target_feature = "crypto")
)))]
#[path = "./generic.rs"]
mod platform;

pub use self::platform::*;