use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"),
                 all(target_feature = "sse2", target_feature = "pclmulqdq")))] {
        mod x86;
        pub use self::x86::Polyval;
    } else if #[cfg(all(target_arch = "aarch64", target_feature = "pmull"))] {
        mod aarch64;
        pub use self::aarch64::Polyval;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))] {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        #[path = "./x86.rs"]
        mod platform;

        #[cfg(target_arch = "aarch64")]
        #[path = "./aarch64.rs"]
        mod platform;

        mod generic;
        mod dynamic;

        pub use self::dynamic::Polyval;
    } else {
        mod generic;
        pub use self::generic::Polyval;
    }
}
