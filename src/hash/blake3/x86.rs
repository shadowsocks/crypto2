#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;


pub const BLOCK_LEN: usize  = 64;
pub const DIGEST_LEN: usize = 32;
pub const CHUNK_LEN: usize  = 1024;

pub const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 
];


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


macro_rules! VG {
    ($va:expr, $vb:expr, $vc:expr, $vd:expr, $vmx:expr, $vmy:expr) => {
        $va = _mm_add_epi32(_mm_add_epi32($va, $vb), $vmx);
        $vd = _mm_xor_si128($vd, $va); // _mm_xor_epi32
        $vd = _mm_xor_si128(_mm_srli_epi32::<16>($vd), _mm_slli_epi32::<16>($vd)); // rotate_right(16)
        $vc = _mm_add_epi32($vc, $vd);
        $vb = _mm_xor_si128($vb, $vc);

        // NOTE: _mm_ror_epi32 需要 avx512f,avx512vl
        $vb = _mm_xor_si128(_mm_srli_epi32::<12>($vb), _mm_slli_epi32::<20>($vb));

        $va = _mm_add_epi32(_mm_add_epi32($va, $vb), $vmy);
        $vd = _mm_xor_si128($vd, $va); // _mm_xor_epi32

        // NOTE: _mm_ror_epi32 需要 avx512f,avx512vl
        $vd = _mm_xor_si128(_mm_srli_epi32::<8>($vd), _mm_slli_epi32::<24>($vd)); // rotate_right(8)
        $vc = _mm_add_epi32($vc, $vd);
        $vb = _mm_xor_si128($vb, $vc);
        $vb = _mm_xor_si128(_mm_srli_epi32::<7>($vb), _mm_slli_epi32::<25>($vb));
    }
}


#[cfg(all(target_feature = "sse2", target_feature = "avx2"))]
#[allow(unused_variables)]
#[inline]
unsafe fn transform(chaining_value: &[u32; 8], block: &[u8], block_len: usize, counter: u64, flags: u32) -> [u8; DIGEST_LEN] {
    debug_assert!(block.len() == BLOCK_LEN);
    
    let t0   = 0i32;
    let t1   = 0i32;
    let blen = block_len as u32 as i32;

    let mut va = _mm_setr_epi32(0x6A09E667u32 as i32, 0xBB67AE85u32 as i32, 0x3C6EF372u32 as i32, 0xA54FF53Au32 as i32);
    let mut vb = _mm_setr_epi32(0x510E527Fu32 as i32, 0x9B05688Cu32 as i32, 0x1F83D9ABu32 as i32, 0x5BE0CD19u32 as i32);
    let mut vc = va.clone();
    let mut vd = _mm_setr_epi32(t0, t1, blen, flags as i32);

    let w = _mm256_load_si256(block.as_ptr().add( 0) as *const __m256i);
    let w0 = _mm256_extract_epi32::<0>(w);
    let w1 = _mm256_extract_epi32::<1>(w);
    let w2 = _mm256_extract_epi32::<2>(w);
    let w3 = _mm256_extract_epi32::<3>(w);
    let w4 = _mm256_extract_epi32::<4>(w);
    let w5 = _mm256_extract_epi32::<5>(w);
    let w6 = _mm256_extract_epi32::<6>(w);
    let w7 = _mm256_extract_epi32::<7>(w);
    drop(w);

    let w = _mm256_load_si256(block.as_ptr().add(32) as *const __m256i);
    let w8  = _mm256_extract_epi32::<0>(w);
    let w9  = _mm256_extract_epi32::<1>(w);
    let w10 = _mm256_extract_epi32::<2>(w);
    let w11 = _mm256_extract_epi32::<3>(w);
    let w12 = _mm256_extract_epi32::<4>(w);
    let w13 = _mm256_extract_epi32::<5>(w);
    let w14 = _mm256_extract_epi32::<6>(w);
    let w15 = _mm256_extract_epi32::<7>(w);
    drop(w);

    let mut vmx: __m128i;
    let mut vmy: __m128i;

    // VG!(va, vb, vc, vd,  w0, w2, w4, w6,  w1, w3, w5, w7,  );

    // Round-1
    vmx = _mm_setr_epi32(w0, w2, w4, w6);
    vmy = _mm_setr_epi32(w1, w3, w5, w7);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vmx = _mm_setr_epi32(w8, w10, w12, w14);
    vmy = _mm_setr_epi32(w9, w11, w13, w15);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)

    // Round-2
    vmx = _mm_setr_epi32(w2, w3, w7, w4);
    vmy = _mm_setr_epi32(w6, w10, w0, w13);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vmx = _mm_setr_epi32(w1, w12, w9, w15);
    vmy = _mm_setr_epi32(w11, w5, w14, w8);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)

    // Round-3
    vmx = _mm_setr_epi32(w3, w10, w13, w7);
    vmy = _mm_setr_epi32(w4, w12, w2, w14);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vmx = _mm_setr_epi32(w6, w9, w11, w8);
    vmy = _mm_setr_epi32(w5, w0, w15, w1);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)

    // Round-4
    vmx = _mm_setr_epi32(w10, w12, w14, w13);
    vmy = _mm_setr_epi32(w7, w9, w3, w15);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vmx = _mm_setr_epi32(w4, w11, w5, w1);
    vmy = _mm_setr_epi32(w0, w2, w8, w6);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)

    // Round-5
    vmx = _mm_setr_epi32(w12, w9, w15, w14);
    vmy = _mm_setr_epi32(w13, w11, w10, w8);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vmx = _mm_setr_epi32(w7, w5, w0, w6);
    vmy = _mm_setr_epi32(w2, w3, w1, w4);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)

    // Round-6
    vmx = _mm_setr_epi32(w9, w11, w8, w15);
    vmy = _mm_setr_epi32(w14, w5, w12, w1);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vmx = _mm_setr_epi32(w13, w0, w2, w4);
    vmy = _mm_setr_epi32(w3, w10, w6, w7);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)

    // Round-7
    vmx = _mm_setr_epi32(w11, w5, w1, w8);
    vmy = _mm_setr_epi32(w15, w0, w9, w6);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vmx = _mm_setr_epi32(w14, w2, w3, w7);
    vmy = _mm_setr_epi32(w10, w12, w4, w13);
    VG!(va, vb, vc, vd, vmx, vmy);
    vb = _mm_shuffle_epi32(vb, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    vc = _mm_shuffle_epi32(vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    vd = _mm_shuffle_epi32(vd, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)

    // let mut lo = _mm256_setr_m128i(va, vb);
    // let mut hi = _mm256_setr_m128i(vc, vd);
    // 
    // lo = _mm256_xor_si256(lo, hi);
    // hi = _mm256_xor_si256(hi, 
    //         _mm256_setr_epi32(
    //             0x6A09E667u32 as i32, 0xBB67AE85u32 as i32, 0x3C6EF372u32 as i32, 0xA54FF53Au32 as i32, 
    //             0x510E527Fu32 as i32, 0x9B05688Cu32 as i32, 0x1F83D9ABu32 as i32, 0x5BE0CD19u32 as i32,
    //         ),
    // );
    // 
    // let mut v = [0u32; 16];
    // _mm256_storeu_si256(v.as_mut_ptr() as *mut __m256i, lo);
    // _mm256_storeu_si256(v.as_mut_ptr().add(8) as *mut __m256i, hi);
    // 
    // v

    let mut out = [0u8; DIGEST_LEN];

    let mut lo = _mm256_setr_m128i(va, vb);
    let mut hi = _mm256_setr_m128i(vc, vd);

    lo = _mm256_xor_si256(lo, hi);
    _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, lo);

    out
}