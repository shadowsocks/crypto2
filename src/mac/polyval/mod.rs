use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(feature = "force-soft")))] {
        #[path = "./x86.rs"]
        mod platform;

        cfg_if! {
            if #[cfg(all(target_feature = "sse2", target_feature = "pclmulqdq"))] {
                pub use self::platform::Polyval;
            } else {
                mod generic;
                mod dynamic;

                pub use self::dynamic::Polyval;
            }
        }
    } else if #[cfg(all(target_arch = "aarch64", not(feature = "force-soft")))] {
        #[path = "./aarch64.rs"]
        mod platform;

        cfg_if! {
            if #[cfg(target_feature = "pmull")] {
                pub use self::platform::Polyval;
            } else {
                mod generic;
                mod dynamic;

                pub use self::dynamic::Polyval;
            }
        }
    } else {
        mod generic;
        pub use self::generic::Polyval;
    }
}
