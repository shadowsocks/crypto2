// https://github.com/randombit/botan/blob/master/src/lib/utils/ghash/ghash_vperm/ghash_vperm.cpp

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        #[path = "./x86.rs"]
        mod platform;

        cfg_if! {
            if #[cfg(all(target_feature = "sse2", target_feature = "pclmulqdq"))] {
                pub use self::platform::GHash;
            } else {
                mod generic;
                mod dynamic;

                pub use self::dynamic::GHash;
            }
        }
    } else if #[cfg(target_arch = "aarch64")] {
        #[path = "./aarch64.rs"]
        mod platform;

        cfg_if! {
            if #[cfg(target_feature = "pmull")] {
                pub use self::platform::GHash;
            } else {
                mod generic;
                mod dynamic;

                pub use self::dynamic::GHash;
            }
        }
    } else {
        mod generic;
        pub use self::generic::GHash;
    }
}
