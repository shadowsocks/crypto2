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
pub fn xor_si128_inplace(a: &mut [u8], b: &[u8]) {
    for i in 0..16 {
        a[i] ^= b[i]
    }
}

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    all(target_feature = "sse2"),
))]
pub fn xor_si128_inplace(a: &mut [u8], b: &[u8]) {
    unsafe {
        let mut c = _mm_loadu_si128(a.as_ptr() as *const __m128i);
        let d = _mm_loadu_si128(b.as_ptr() as *const __m128i);
        c = _mm_xor_si128(c, d);
        _mm_storeu_si128(a.as_mut_ptr() as *mut __m128i, c);
    }
}

#[cfg(target_arch = "aarch64")]
pub fn xor_si128_inplace(a: &mut [u8], b: &[u8]) {
    unsafe {
        let c: *mut uint8x16_t = a.as_mut_ptr() as *mut uint8x16_t;
        let d: uint8x16_t = *(b.as_ptr() as *const uint8x16_t);
        
        *c = veorq_u8(*c, d);
    }
}




// #[cfg(all(
//     any(target_arch = "x86", target_arch = "x86_64"),
//     all(target_feature = "avx2"),
// ))]
// pub fn xor_si256_inplace(a: &mut [u8], b: &[u8]) {
//     unsafe {
//         let mut c = _mm256_loadu_si256(a.as_ptr() as *const __m256i);
//         let d = _mm256_loadu_si256(b.as_ptr() as *const __m256i);
//         c = _mm256_xor_si256(c, d);
//         _mm256_storeu_si256(a.as_mut_ptr() as *mut __m256i, c);
//     }
// }



// #[cfg(all(
//     any(target_arch = "x86", target_arch = "x86_64"),
//     all(target_feature = "avx512f"),
// ))]
// pub fn xor_si512_inplace(a: &mut [u8], b: &[u8]) {
//     // __m512i _mm512_loadu_si512 (void const* mem_addr)
//     // https://software.intel.com/sites/landingpage/IntrinsicsGuide/#text=_mm512_loadu_si512&expand=101,97,100,6171,94,97,100,3420
//     // 
//     // __m512i _mm512_xor_si512 (__m512i a, __m512i b)
//     // https://software.intel.com/sites/landingpage/IntrinsicsGuide/#text=_mm512_xor_si512&expand=101,97,100,6171,94,97,100,3420,6172
//     // 
//     // void _mm512_storeu_si512 (void* mem_addr, __m512i a)
//     // https://software.intel.com/sites/landingpage/IntrinsicsGuide/#text=_mm512_storeu_si512&expand=101,97,100,6171,94,97,100,3420,5657
//     unsafe {
//         let mut c = _mm512_loadu_si512(a.as_ptr() as *const __m512i);
//         let d = _mm512_loadu_si512(b.as_ptr() as *const __m512i);
//         c = _mm512_xor_si512(c, d);
//         _mm512_storeu_si512(a.as_mut_ptr() as *mut __m512i, c);
//     }
// }
