
// AArch64 ARMv8.4-A
// https://en.wikipedia.org/wiki/AArch64#ARMv8.4-A
// 
// NOTE: 
//      AArch64 架构在 ARMv8.4-A 版本里面添加了对 SHA2-512 的加速指令。
//      在 Rust 的 `core::arch::aarch64` 里面增加了该指令后，可以考虑实现。
//      目前 Rust 的 `std_detect` 库只支持到 AArch64 v8.3a。
// 
// https://github.com/rust-lang/stdarch/blob/master/crates/std_detect/src/detect/arch/aarch64.rs#L13