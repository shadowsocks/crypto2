#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;


// Table 3: Admissible values for input d in the BLAKE3 compression function.
//     ------------------  ------
//     Flag name           Value
//     ------------------  ------
//     CHUNK_START         2**0
//     CHUNK_END           2**1
//     PARENT              2**2
//     ROOT                2**3
//     KEYED_HASH          2**4
//     DERIVE_KEY_CONTEXT  2**5
//     DERIVE_KEY_MATERIAL 2**6
//     ------------------- ------
const CHUNK_START: u32         =  1;
const CHUNK_END: u32           =  2;
const ROOT: u32                =  8;


const BLOCK_LEN: usize  = 64;
const DIGEST_LEN: usize = 32;
const CHUNK_LEN: usize  = 1024;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 
];

macro_rules! VG {
    ($va:expr, $vb:expr, $vc:expr, $vd:expr, $vmx:expr, $vmy:expr) => {
        // NOTE: _mm_rol_epi32 和 _mm_ror_epi32 需要 avx512f, avx512vl X86 target feature.
        //       因此我们使用模拟。
        $va = _mm_add_epi32(_mm_add_epi32($va, $vb), $vmx);
        $vd = _mm_xor_si128($vd, $va);
        $vd = _mm_xor_si128(_mm_srli_epi32::<16>($vd), _mm_slli_epi32::<16>($vd)); // rotate_right(16)
        
        $vc = _mm_add_epi32($vc, $vd);
        $vb = _mm_xor_si128($vb, $vc);
        $vb = _mm_xor_si128(_mm_srli_epi32::<12>($vb), _mm_slli_epi32::<20>($vb)); // rotate_right(12)
        
        $va = _mm_add_epi32(_mm_add_epi32($va, $vb), $vmy);
        $vd = _mm_xor_si128($vd, $va);
        $vd = _mm_xor_si128(_mm_srli_epi32::<8>($vd), _mm_slli_epi32::<24>($vd)); // rotate_right(8)
        
        $vc = _mm_add_epi32($vc, $vd);
        $vb = _mm_xor_si128($vb, $vc);
        $vb = _mm_xor_si128(_mm_srli_epi32::<7>($vb), _mm_slli_epi32::<25>($vb)); // rotate_right(7)
    }
}

macro_rules! ROUND {
    ($va:expr, $vb:expr, $vc:expr, $vd:expr, $vmx1:expr, $vmx2:expr, $vmy1:expr, $vmy2:expr) => {
        VG!($va, $vb, $vc, $vd, $vmx1, $vmy1);
        $vb = _mm_shuffle_epi32($vb, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
        $vc = _mm_shuffle_epi32($vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        $vd = _mm_shuffle_epi32($vd, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)

        VG!($va, $vb, $vc, $vd, $vmx2, $vmy2);
        $vb = _mm_shuffle_epi32($vb, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
        $vc = _mm_shuffle_epi32($vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        $vd = _mm_shuffle_epi32($vd, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    }
}


#[cfg(target_feature = "sse2")]
#[inline]
pub fn transform_half(chaining_value: &[u32; 8], block: &[u32; 16], counter: u64, flags: u32, blen: u32) -> [u32; 8] {
    unsafe {
        // debug_assert!(block.len() == BLOCK_LEN);

        let block = core::slice::from_raw_parts(block.as_ptr() as *const u8, 64);
        let [va, vb, _, _] = transform(chaining_value, block, counter, flags, blen);

        let mut out = [0u32; 8];

        _mm_storeu_si128(out.as_mut_ptr().add( 0) as *mut __m128i, va);
        _mm_storeu_si128(out.as_mut_ptr().add( 4) as *mut __m128i, vb);

        out
    }
}

#[cfg(target_feature = "sse2")]
#[inline]
pub fn transform_full(chaining_value: &[u32; 8], block: &[u32; 16], counter: u64, flags: u32, blen: u32) -> [u32; 16] {
    unsafe {
        // debug_assert!(block.len() == BLOCK_LEN);

        let block = core::slice::from_raw_parts(block.as_ptr() as *const u8, 64);

        let [va, vb, mut vc, mut vd] = transform(chaining_value, block, counter, flags, blen);

        let va_copy = _mm_loadu_si128(chaining_value.as_ptr().add(0) as *const __m128i);
        let vb_copy = _mm_loadu_si128(chaining_value.as_ptr().add(4) as *const __m128i);

        vc = _mm_xor_si128(vc, va_copy);
        vd = _mm_xor_si128(vd, vb_copy);

        let mut out = [0u32; 16];
        
        _mm_storeu_si128(out.as_mut_ptr().add( 0) as *mut __m128i, va);
        _mm_storeu_si128(out.as_mut_ptr().add( 4) as *mut __m128i, vb);
        _mm_storeu_si128(out.as_mut_ptr().add( 8) as *mut __m128i, vc);
        _mm_storeu_si128(out.as_mut_ptr().add(12) as *mut __m128i, vd);

        out
    }
}

#[cfg(test)]
#[bench]
fn bench_blake3_transform(b: &mut test::Bencher) {
    let key   = [7u32; 8];
    let block = [9u32; 16];
    let block_len = 64;
    let counter = 1;
    let flags = 4;

    b.bytes = 64;
    b.iter(|| unsafe {
        transform_full(&key, &block, counter, flags, block_len)
    })
}

#[cfg(target_feature = "sse2")]
#[inline]
unsafe fn transform(chaining_value: &[u32; 8], block: &[u8], counter: u64, flags: u32, blen: u32) -> [__m128i; 4] {
    debug_assert!(block.len() == BLOCK_LEN);
    
    let t0 = counter as u32 as i32;
    let t1 = (counter >> 32) as u32 as i32;
    let f0 = blen as i32;  // BLOCK-LEN
    let f1 = flags as i32;

    // let mut va = _mm_setr_epi32(0x6A09E667u32 as i32, 0xBB67AE85u32 as i32, 0x3C6EF372u32 as i32, 0xA54FF53Au32 as i32);
    // let mut vb = _mm_setr_epi32(0x510E527Fu32 as i32, 0x9B05688Cu32 as i32, 0x1F83D9ABu32 as i32, 0x5BE0CD19u32 as i32);
    // let mut vc = va.clone();
    let mut va = _mm_loadu_si128(chaining_value.as_ptr().add(0) as *const __m128i);
    let mut vb = _mm_loadu_si128(chaining_value.as_ptr().add(4) as *const __m128i);
    let mut vc = _mm_loadu_si128(IV.as_ptr().add(0) as *const __m128i);
    let mut vd = _mm_setr_epi32(t0, t1, f0, f1);

    // let va_copy = va.clone();
    // let vb_copy = vb.clone();

    let w0  = *(block.as_ptr().add( 0) as *const i32);
    let w1  = *(block.as_ptr().add( 4) as *const i32);
    let w2  = *(block.as_ptr().add( 8) as *const i32);
    let w3  = *(block.as_ptr().add(12) as *const i32);
    let w4  = *(block.as_ptr().add(16) as *const i32);
    let w5  = *(block.as_ptr().add(20) as *const i32);
    let w6  = *(block.as_ptr().add(24) as *const i32);
    let w7  = *(block.as_ptr().add(28) as *const i32);
    let w8  = *(block.as_ptr().add(32) as *const i32);
    let w9  = *(block.as_ptr().add(36) as *const i32);
    let w10 = *(block.as_ptr().add(40) as *const i32);
    let w11 = *(block.as_ptr().add(44) as *const i32);
    let w12 = *(block.as_ptr().add(48) as *const i32);
    let w13 = *(block.as_ptr().add(52) as *const i32);
    let w14 = *(block.as_ptr().add(56) as *const i32);
    let w15 = *(block.as_ptr().add(60) as *const i32);

    let mut vmx1: __m128i;
    let mut vmx2: __m128i;
    let mut vmy1: __m128i;
    let mut vmy2: __m128i;

    // Round-1
    vmx1 = _mm_setr_epi32(w0, w2, w4, w6);
    vmy1 = _mm_setr_epi32(w1, w3, w5, w7);
    vmx2 = _mm_setr_epi32(w8, w10, w12, w14);
    vmy2 = _mm_setr_epi32(w9, w11, w13, w15);
    ROUND!(va, vb, vc, vd, vmx1, vmx2, vmy1, vmy2);

    // Round-2
    vmx1 = _mm_setr_epi32(w2, w3, w7, w4);
    vmy1 = _mm_setr_epi32(w6, w10, w0, w13);
    vmx2 = _mm_setr_epi32(w1, w12, w9, w15);
    vmy2 = _mm_setr_epi32(w11, w5, w14, w8);
    ROUND!(va, vb, vc, vd, vmx1, vmx2, vmy1, vmy2);

    // Round-3
    vmx1 = _mm_setr_epi32(w3, w10, w13, w7);
    vmy1 = _mm_setr_epi32(w4, w12, w2, w14);
    vmx2 = _mm_setr_epi32(w6, w9, w11, w8);
    vmy2 = _mm_setr_epi32(w5, w0, w15, w1);
    ROUND!(va, vb, vc, vd, vmx1, vmx2, vmy1, vmy2);

    // Round-4
    vmx1 = _mm_setr_epi32(w10, w12, w14, w13);
    vmy1 = _mm_setr_epi32(w7, w9, w3, w15);
    vmx2 = _mm_setr_epi32(w4, w11, w5, w1);
    vmy2 = _mm_setr_epi32(w0, w2, w8, w6);
    ROUND!(va, vb, vc, vd, vmx1, vmx2, vmy1, vmy2);

    // Round-5
    vmx1 = _mm_setr_epi32(w12, w9, w15, w14);
    vmy1 = _mm_setr_epi32(w13, w11, w10, w8);
    vmx2 = _mm_setr_epi32(w7, w5, w0, w6);
    vmy2 = _mm_setr_epi32(w2, w3, w1, w4);
    ROUND!(va, vb, vc, vd, vmx1, vmx2, vmy1, vmy2);

    // Round-6
    vmx1 = _mm_setr_epi32(w9, w11, w8, w15);
    vmy1 = _mm_setr_epi32(w14, w5, w12, w1);
    vmx2 = _mm_setr_epi32(w13, w0, w2, w4);
    vmy2 = _mm_setr_epi32(w3, w10, w6, w7);
    ROUND!(va, vb, vc, vd, vmx1, vmx2, vmy1, vmy2);

    // Round-7
    vmx1 = _mm_setr_epi32(w11, w5, w1, w8);
    vmy1 = _mm_setr_epi32(w15, w0, w9, w6);
    vmx2 = _mm_setr_epi32(w14, w2, w3, w7);
    vmy2 = _mm_setr_epi32(w10, w12, w4, w13);
    ROUND!(va, vb, vc, vd, vmx1, vmx2, vmy1, vmy2);
    
    // XOR
    va = _mm_xor_si128(va, vc);
    vb = _mm_xor_si128(vb, vd);
    
    // NOTE: 由于只有最后才需要处理 vc 和 vd ，因此，在前期可以省略该处的计算。
    // vc = _mm_xor_si128(vc, va_copy);
    // vd = _mm_xor_si128(vd, vb_copy);

    [va, vb, vc, vd]
}