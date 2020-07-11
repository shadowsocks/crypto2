#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::generic;

// TODO: 
//      SIMD 并行处理多个 BLOCK 数据参考: https://github.com/mjosaarinen/sm4ni

