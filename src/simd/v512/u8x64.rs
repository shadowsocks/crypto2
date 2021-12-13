#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[cfg(target_arch = "aarch64")]
use crate::simd::v128::u8x16;


#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Debug, Clone, Copy)]
pub struct u8x64(__m512i);

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy)]
pub struct u8x64(u8x16, u8x16, u8x16, u8x16);


#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx512f",
))]
impl u8x64 {
    #[inline]
    pub fn load(mem_addr: *const u8) -> Self {
        unsafe { Self(_mm512_load_si512(mem_addr as *const __m512i)) }
    }
    #[inline]
    pub fn loadu(mem_addr: *const u8) -> Self {
        unsafe { Self(_mm512_loadu_si512(mem_addr as *const __m512i)) }
    }
    #[inline]
    pub fn store(self, mem_addr: *mut u8) {
        unsafe { _mm512_store_si512(mem_addr as *mut __m512i, self.0) }
    }
    #[inline]
    pub fn storeu(self, mem_addr: *mut u8) {
        unsafe { _mm512_storeu_si512(mem_addr as *mut __m512i, self.0) }
    }

    // wrapping_add
    #[cfg(target_feature = "avx512bw")]
    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        unsafe { Self(_mm512_add_epi8(self.0, rhs.0)) }
    }

    #[cfg(target_feature = "avx512bw")]
    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        unsafe { Self(_mm512_sub_epi8(self.0, rhs.0)) }
    }

    #[inline]
    pub fn and(self, rhs: Self) -> Self {
        unsafe { Self(_mm512_and_si512(self.0, rhs.0)) }
    }

    #[inline]
    pub fn xor(self, rhs: Self) -> Self {
        unsafe { Self(_mm512_xor_si512(self.0, rhs.0)) }
    }

    #[inline]
    pub fn andnot(self, rhs: Self) -> Self {
        unsafe { Self(_mm512_andnot_si512(self.0, rhs.0)) }
    }
}


#[cfg(target_arch = "aarch64")]
impl u8x64 {
    #[inline]
    pub fn load(mem_addr: *const u8) -> Self {
        let a = u8x16::load(mem_addr);
        let b = u8x16::load(mem_addr.add(16));
        let c = u8x16::load(mem_addr.add(32));
        let d = u8x16::load(mem_addr.add(48));

        Self(a, b, c, d)
    }

    #[inline]
    pub fn store(self, mem_addr: *mut u8) {
        self.0.store(mem_addr);
        self.1.store(mem_addr.add(16));
        self.2.store(mem_addr.add(32));
        self.3.store(mem_addr.add(48));
    }
    
    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        self.0 = self.0.add(rhs.0);
        self.1 = self.1.add(rhs.1);
        self.2 = self.2.add(rhs.2);
        self.3 = self.3.add(rhs.3);
    }

    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        self.0 = self.0.sub(rhs.0);
        self.1 = self.1.sub(rhs.1);
        self.2 = self.2.sub(rhs.2);
        self.3 = self.3.sub(rhs.3);
    }

    #[inline]
    pub fn and(self, rhs: Self) -> Self {
        self.0 = self.0.and(rhs.0);
        self.1 = self.1.and(rhs.1);
        self.2 = self.2.and(rhs.2);
        self.3 = self.3.and(rhs.3);
    }

    #[inline]
    pub fn xor(a: Self, b: Self) -> Self {
        self.0 = self.0.xor(rhs.0);
        self.1 = self.1.xor(rhs.1);
        self.2 = self.2.xor(rhs.2);
        self.3 = self.3.xor(rhs.3);
    }
}