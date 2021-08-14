#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;


// NOTE: 等待 std::arch::_MM_SHUFFLE 功能稳定。
#[allow(non_snake_case)]
const fn _MM_SHUFFLE(z: u32, y: u32, x: u32, w: u32) -> i32 {
    ((z << 6) | (y << 4) | (x << 2) | w) as i32
}

macro_rules! VG {
    ($va:expr, $vb:expr, $vc:expr, $vd:expr, $vmx:expr, $vmy:expr) => {
        // NOTE: _mm_rol_epi32 和 _mm_ror_epi32 需要 avx512f, avx512vl X86 target feature.
        //       因此我们使用模拟。
        $va = _mm_add_epi32(_mm_add_epi32($va, $vb), $vmx);
        $vd = _mm_xor_si128($vd, $va);
        $vd = _mm_or_si128(_mm_srli_epi32::<16>($vd), _mm_slli_epi32::<16>($vd)); // rotate_right(16)

        $vc = _mm_add_epi32($vc, $vd);
        $vb = _mm_xor_si128($vb, $vc);
        $vb = _mm_xor_si128(_mm_srli_epi32::<12>($vb), _mm_slli_epi32::<20>($vb)); // rotate_right(12)
        
        $va = _mm_add_epi32(_mm_add_epi32($va, $vb), $vmy);
        $vd = _mm_xor_si128($vd, $va);
        $vd = _mm_or_si128(_mm_srli_epi32::<8>($vd), _mm_slli_epi32::<24>($vd));  // rotate_right(8)

        $vc = _mm_add_epi32($vc, $vd);
        $vb = _mm_xor_si128($vb, $vc);
        $vb = _mm_or_si128(_mm_srli_epi32::<7>($vb), _mm_slli_epi32::<25>($vb));  // rotate_right(7)
    }
}

macro_rules! ROUND {
    ($va:expr, $vb:expr, $vc:expr, $vd:expr, $vmx1:expr, $vmx2:expr, $vmy1:expr, $vmy2:expr) => {
        VG!($va, $vb, $vc, $vd, $vmx1, $vmy1);
        $va = _mm_shuffle_epi32($va, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
        $vd = _mm_shuffle_epi32($vd, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        $vc = _mm_shuffle_epi32($vc, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
        
        VG!($va, $vb, $vc, $vd, $vmx2, $vmy2);
        $va = _mm_shuffle_epi32($va, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
        $vd = _mm_shuffle_epi32($vd, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        $vc = _mm_shuffle_epi32($vc, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    }
}


#[cfg(all(target_feature = "sse2", target_feature = "sse4.1"))]
#[inline]
pub unsafe fn transform_block(state: &mut [__m128i; 3], block: &[u8], counter: u64, blen: u32, flags: u32) {
    let m0 = _mm_loadu_si128(block.as_ptr().add( 0) as *const __m128i);
    let m1 = _mm_loadu_si128(block.as_ptr().add(16) as *const __m128i);
    let m2 = _mm_loadu_si128(block.as_ptr().add(32) as *const __m128i);
    let m3 = _mm_loadu_si128(block.as_ptr().add(48) as *const __m128i);

    transform_words(state, &[m0, m1, m2, m3], counter, blen, flags)
}

#[cfg(all(target_feature = "sse2", target_feature = "sse4.1"))]
#[inline]
pub unsafe fn transform_words(state: &mut [__m128i; 3], words: &[__m128i; 4], counter: u64, blen: u32, flags: u32) {
    let t0 = counter as u32 as i32;
    let t1 = (counter >> 32) as u32 as i32;
    let f0 = blen as i32;  // BLOCK-LEN
    let f1 = flags as i32;

    let vd = _mm_setr_epi32(t0, t1, f0, f1);

    let [va, vb, vc] = state;
    let mut temp = [*va, *vb, *vc, vd];
    transform::<false>(&mut temp, words);

    state[0] = temp[0];
    state[1] = temp[1];
}

#[cfg(all(target_feature = "sse2", target_feature = "sse4.1"))]
#[inline]
pub unsafe fn transform_root_node(state: &mut [__m128i; 4], words: &[__m128i; 4], counter: u64, blen: u32, flags: u32) {
    let t0 = counter as u32 as i32;
    let t1 = (counter >> 32) as u32 as i32;
    let f0 = blen as i32;  // BLOCK-LEN
    let f1 = flags as i32;

    state[3] = _mm_setr_epi32(t0, t1, f0, f1);

    transform::<true>(state, words);
}

#[cfg(all(target_feature = "sse2", target_feature = "sse4.1"))]
#[inline]
unsafe fn transform<const IS_ROOT: bool>(state: &mut [__m128i; 4], words: &[__m128i; 4]) {
    let mut va = state[0];
    let mut vb = state[1];
    let mut vc = state[2];
    let mut vd = state[3];

    let mut m0 = words[0];
    let mut m1 = words[1];
    let mut m2 = words[2];
    let mut m3 = words[3];

    let mut mx1;
    let mut mx2;
    let mut my1;
    let mut my2;

    const MASK_0033: i32 = _MM_SHUFFLE(0, 0, 3, 3);
    const MASK_0132: i32 = _MM_SHUFFLE(0, 1, 3, 2);
    const MASK_0321: i32 = _MM_SHUFFLE(0, 3, 2, 1);
    const MASK_1320: i32 = _MM_SHUFFLE(1, 3, 2, 0);
    const MASK_2020: i32 = _MM_SHUFFLE(2, 0, 2, 0);
    const MASK_2103: i32 = _MM_SHUFFLE(2, 1, 0, 3);
    const MASK_3112: i32 = _MM_SHUFFLE(3, 1, 1, 2);
    const MASK_3131: i32 = _MM_SHUFFLE(3, 1, 3, 1);
    const MASK_3322: i32 = _MM_SHUFFLE(3, 3, 2, 2);

    macro_rules! shuffle2 {
        ($a:expr, $b:expr, $c:expr) => {
            _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps($a), _mm_castsi128_ps($b), $c))
        };
    }
    
    // Roud 1
    mx1 = shuffle2!(m0, m1, MASK_2020);                               //  6  4  2  0
    my1 = shuffle2!(m0, m1, MASK_3131);                               //  7  5  3  1
    mx2 = _mm_shuffle_epi32(shuffle2!(m2, m3, MASK_2020), MASK_2103); // 12 10  8 14
    my2 = _mm_shuffle_epi32(shuffle2!(m2, m3, MASK_3131), MASK_2103); // 13 11  9 15
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);
    m0 = mx1; m1 = my1; m2 = mx2; m3 = my2;

    // Round 2
    mx1 = _mm_shuffle_epi32(shuffle2!(m0, m1, MASK_3112), MASK_0321);
    my1 = _mm_blend_epi16(_mm_shuffle_epi32(m0, MASK_0033), shuffle2!(m2, m3, MASK_3322), 0xCC);
    mx2 = _mm_shuffle_epi32(_mm_blend_epi16(_mm_unpacklo_epi64(m3, m1), m2, 0xC0), MASK_1320);
    my2 = _mm_shuffle_epi32(_mm_unpacklo_epi32(m2, _mm_unpackhi_epi32(m1, m3)), MASK_0132);
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);
    m0 = mx1; m1 = my1; m2 = mx2; m3 = my2;

    // Round 3
    mx1 = _mm_shuffle_epi32(shuffle2!(m0, m1, MASK_3112), MASK_0321);
    my1 = _mm_blend_epi16(_mm_shuffle_epi32(m0, MASK_0033), shuffle2!(m2, m3, MASK_3322), 0xCC);
    mx2 = _mm_shuffle_epi32(_mm_blend_epi16(_mm_unpacklo_epi64(m3, m1), m2, 0xC0), MASK_1320);
    my2 = _mm_shuffle_epi32(_mm_unpacklo_epi32(m2, _mm_unpackhi_epi32(m1, m3)), MASK_0132);
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);
    m0 = mx1; m1 = my1; m2 = mx2; m3 = my2;

    // Round 4
    mx1 = _mm_shuffle_epi32(shuffle2!(m0, m1, MASK_3112), MASK_0321);
    my1 = _mm_blend_epi16(_mm_shuffle_epi32(m0, MASK_0033), shuffle2!(m2, m3, MASK_3322), 0xCC);
    mx2 = _mm_shuffle_epi32(_mm_blend_epi16(_mm_unpacklo_epi64(m3, m1), m2, 0xC0), MASK_1320);
    my2 = _mm_shuffle_epi32(_mm_unpacklo_epi32(m2, _mm_unpackhi_epi32(m1, m3)), MASK_0132);
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);
    m0 = mx1; m1 = my1; m2 = mx2; m3 = my2;

    // Round 5
    mx1 = _mm_shuffle_epi32(shuffle2!(m0, m1, MASK_3112), MASK_0321);
    my1 = _mm_blend_epi16(_mm_shuffle_epi32(m0, MASK_0033), shuffle2!(m2, m3, MASK_3322), 0xCC);
    mx2 = _mm_shuffle_epi32(_mm_blend_epi16(_mm_unpacklo_epi64(m3, m1), m2, 0xC0), MASK_1320);
    my2 = _mm_shuffle_epi32(_mm_unpacklo_epi32(m2, _mm_unpackhi_epi32(m1, m3)), MASK_0132);
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);
    m0 = mx1; m1 = my1; m2 = mx2; m3 = my2;

    // Round 6
    mx1 = _mm_shuffle_epi32(shuffle2!(m0, m1, MASK_3112), MASK_0321);
    my1 = _mm_blend_epi16(_mm_shuffle_epi32(m0, MASK_0033), shuffle2!(m2, m3, MASK_3322), 0xCC);
    mx2 = _mm_shuffle_epi32(_mm_blend_epi16(_mm_unpacklo_epi64(m3, m1), m2, 0xC0), MASK_1320);
    my2 = _mm_shuffle_epi32(_mm_unpacklo_epi32(m2, _mm_unpackhi_epi32(m1, m3)), MASK_0132);
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);
    m0 = mx1; m1 = my1; m2 = mx2; m3 = my2;

    // Round 7
    mx1 = _mm_shuffle_epi32(shuffle2!(m0, m1, MASK_3112), MASK_0321);
    my1 = _mm_blend_epi16(_mm_shuffle_epi32(m0, MASK_0033), shuffle2!(m2, m3, MASK_3322), 0xCC);
    mx2 = _mm_shuffle_epi32(_mm_blend_epi16(_mm_unpacklo_epi64(m3, m1), m2, 0xC0), MASK_1320);
    my2 = _mm_shuffle_epi32(_mm_unpacklo_epi32(m2, _mm_unpackhi_epi32(m1, m3)), MASK_0132);
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);

    // XOR
    va = _mm_xor_si128(va, vc);
    vb = _mm_xor_si128(vb, vd);
    
    if IS_ROOT {
        let va_copy = state[0];
        let vb_copy = state[1];
        vc = _mm_xor_si128(vc, va_copy);
        vd = _mm_xor_si128(vd, vb_copy);
        
        state[0] = va;
        state[1] = vb;
        state[2] = vc;
        state[3] = vd;
    } else {
        state[0] = va;
        state[1] = vb;
    }
}