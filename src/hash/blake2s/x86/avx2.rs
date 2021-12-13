#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::BLAKE2S_IV;
use super::BLAKE2S_256_IV;
use super::Blake2s;


#[cfg(all(target_feature = "sse2", target_feature = "sse4.1", target_feature = "avx2"))]
#[inline]
pub unsafe fn transform(state: &mut [__m128i; 4], block: &[u8], counter: u64, flags: u64) {
	
}