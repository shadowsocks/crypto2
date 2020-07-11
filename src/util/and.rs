#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;


#[cfg(not(any(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2",
    ),
    target_arch = "aarch64",
)))]
pub fn and_si128_inplace(a: &mut [u8], b: &[u8]) {
    for i in 0..16 {
        a[i] &= b[i]
    }
}

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    all(target_feature = "sse2"),
))]
pub fn and_si128_inplace(a: &mut [u8], b: &[u8]) {
    unsafe {
        let mut c = _mm_loadu_si128(a.as_ptr() as *const __m128i);
        let d = _mm_loadu_si128(b.as_ptr() as *const __m128i);
        c = _mm_and_si128(c, d);
        _mm_storeu_si128(a.as_mut_ptr() as *mut __m128i, c);
    }
}

#[cfg(target_arch = "aarch64")]
pub fn and_si128_inplace(a: &mut [u8], b: &[u8]) {
    unsafe {
        let c: *mut uint8x16_t = a.as_mut_ptr() as *mut uint8x16_t;
        let d: uint8x16_t = *(b.as_ptr() as *const uint8x16_t);
        
        *c = vandq_u8(*c, d);
    }
}