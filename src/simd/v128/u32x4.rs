#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;


#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Debug, Clone, Copy)]
pub struct u32x4(__m128i);

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy)]
pub struct u32x4(uint32x4_t);


#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2",
))]
impl u32x4 {
    #[inline]
    pub fn load(mem_addr: *const u8) -> Self {
        unsafe { Self(_mm_load_si128(mem_addr as *const __m128i)) }
    }
    #[inline]
    pub fn loadu(mem_addr: *const u8) -> Self {
        unsafe { Self(_mm_loadu_si128(mem_addr as *const __m128i)) }
    }

    #[inline]
    pub fn store(self, mem_addr: *mut u8) {
        unsafe { _mm_store_si128(mem_addr as *mut __m128i, self.0) }
    }
    #[inline]
    pub fn storeu(self, mem_addr: *mut u8) {
        unsafe { _mm_storeu_si128(mem_addr as *mut __m128i, self.0) }
    }

    // wrapping_add
    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        unsafe { Self(_mm_add_epi32(self.0, rhs.0)) }
    }

    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        unsafe { Self(_mm_sub_epi32(self.0, rhs.0)) }
    }

    #[inline]
    pub fn and(self, rhs: Self) -> Self {
        unsafe { Self(_mm_and_si128(self.0, rhs.0)) }
    }

    #[inline]
    pub fn xor(self, rhs: Self) -> Self {
        unsafe { Self(_mm_xor_si128(self.0, rhs.0)) }
    }

    #[inline]
    pub fn andnot(self, rhs: Self) -> Self {
        unsafe { Self(_mm_andnot_si128(self.0, rhs.0)) }
    }
}


#[cfg(target_arch = "aarch64")]
impl u32x4 {
    #[inline]
    pub fn load(mem_addr: *const u8) -> Self {
        unsafe { Self(vld1q_u32(mem_addr as *const u32)) }
    }

    #[inline]
    pub fn store(self, mem_addr: *mut u8) {
        // void vst1q_u8   (uint8_t * ptr, uint8x16_t val)
        // void vst1q_u32 (uint32_t * ptr, uint32x4_t val)
        unsafe {
            let dst = mem_addr as *mut uint32x4_t;
            *dst = self.0;
        }
    }
    
    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        unsafe { Self(vaddq_u32(self.0, rhs.0)) }
    }

    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        unsafe { Self(vsubq_u32(self.0, rhs.0)) }
    }

    #[inline]
    pub fn and(self, rhs: Self) -> Self {
        unsafe { Self(vandq_u32(self.0, rhs.0)) }
    }

    #[inline]
    pub fn xor(a: Self, b: Self) -> Self {
        unsafe { Self(veorq_u32(self.0, rhs.0)) }
    }
}