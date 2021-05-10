#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[cfg(target_arch = "aarch64")]
use crate::simd::v128::u32x4;


#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Debug, Clone, Copy)]
pub struct u32x8(__m256i);

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy)]
pub struct u32x8(u32x4, u32x4);


#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx",
))]
impl u32x8 {
    #[inline]
    pub fn load(mem_addr: *const u8) -> Self {
        unsafe { Self(_mm256_load_si256(mem_addr as *const __m256i)) }
    }
    #[inline]
    pub fn loadu(mem_addr: *const u8) -> Self {
        unsafe { Self(_mm256_loadu_si256(mem_addr as *const __m256i)) }
    }

    #[inline]
    pub fn store(self, mem_addr: *mut u8) {
        unsafe { _mm256_store_si256(mem_addr as *mut __m256i, self.0) }
    }
    #[inline]
    pub fn storeu(self, mem_addr: *mut u8) {
        unsafe { _mm256_storeu_si256(mem_addr as *mut __m256i, self.0) }
    }

    // wrapping_add
    #[cfg(target_feature = "avx2")]
    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        unsafe { Self(_mm256_add_epi32(self.0, rhs.0)) }
    }

    #[cfg(target_feature = "avx2")]
    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        unsafe { Self(_mm256_sub_epi32(self.0, rhs.0)) }
    }

    #[cfg(target_feature = "avx2")]
    #[inline]
    pub fn and(self, rhs: Self) -> Self {
        unsafe { Self(_mm256_and_si256(self.0, rhs.0)) }
    }

    #[cfg(target_feature = "avx2")]
    #[inline]
    pub fn xor(self, rhs: Self) -> Self {
        unsafe { Self(_mm256_xor_si256(self.0, rhs.0)) }
    }

    #[cfg(target_feature = "avx2")]
    #[inline]
    pub fn andnot(self, rhs: Self) -> Self {
        unsafe { Self(_mm256_andnot_si256(self.0, rhs.0)) }
    }
}

#[cfg(target_arch = "aarch64")]
impl u8x32 {
    #[inline]
    pub fn load(mem_addr: *const u8) -> Self {
        let a = u32x4::load(mem_addr);
        let b = u32x4::load(mem_addr.add(16));
        
        Self(a, b)
    }

    #[inline]
    pub fn store(self, mem_addr: *mut u8) {
        self.0.store(mem_addr);
        self.1.store(mem_addr.add(16));
    }
    
    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        self.0 = self.0.add(rhs.0);
        self.1 = self.1.add(rhs.1);
    }

    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        self.0 = self.0.sub(rhs.0);
        self.1 = self.1.sub(rhs.1);
    }

    #[inline]
    pub fn and(self, rhs: Self) -> Self {
        self.0 = self.0.and(rhs.0);
        self.1 = self.1.and(rhs.1);
    }

    #[inline]
    pub fn xor(a: Self, b: Self) -> Self {
        self.0 = self.0.xor(rhs.0);
        self.1 = self.1.xor(rhs.1);
    }
}