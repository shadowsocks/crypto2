#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;


use super::Blake2s;


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

macro_rules! _MM_SHUFFLE {
    ($z:expr, $y:expr, $x:expr, $w:expr) => {
        ($z << 6) | ($y << 4) | ($x << 2) | $w
    };
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
pub unsafe fn transform(state: &mut [__m128i; 4], block: &[u8], counter: u64, flags: u64) {
    debug_assert_eq!(state.len(), 4);
    debug_assert_eq!(block.len(), Blake2s::BLOCK_LEN);

    let t1 = (counter >> 32) as u32;
    let t0 = counter as u32;
    let f1 = (flags >> 32) as u32;
    let f0 = flags as u32;

    let mut va = state[0];
    let mut vb = state[1];
    let mut vc = state[2];
    let mut vd = state[3];
    
    vd = _mm_xor_si128(vd, _mm_setr_epi32(t0 as i32, t1 as i32, f0 as i32, f1 as i32));

    let m0 = _mm_loadu_si128(block.as_ptr().add( 0) as *const __m128i);
    let m1 = _mm_loadu_si128(block.as_ptr().add(16) as *const __m128i);
    let m2 = _mm_loadu_si128(block.as_ptr().add(32) as *const __m128i);
    let m3 = _mm_loadu_si128(block.as_ptr().add(48) as *const __m128i);

    // Roud-1
    let mx1 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(m0), _mm_castsi128_ps(m1), _MM_SHUFFLE!(2, 0, 2, 0)));
    let my1 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(m0), _mm_castsi128_ps(m1), _MM_SHUFFLE!(3, 1, 3, 1)));
    let t0 = _mm_shuffle_epi32(m2, _MM_SHUFFLE!(3, 2, 0, 1));
    let t1 = _mm_shuffle_epi32(m3, _MM_SHUFFLE!(0, 1, 3, 2));
    let mx2 = _mm_blend_epi16(t0, t1, 0xC3);
    let my2 = _mm_shuffle_epi32(t0, _MM_SHUFFLE!(2, 3, 0, 1));
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);

    // Round-2
    let t0 = _mm_blend_epi16(m1, m2, 0x0C);
    let t1 = _mm_slli_si128(m3, 4);
    let t2 = _mm_blend_epi16(t0, t1, 0xF0);
    let mx1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(2, 1, 0, 3));

    let t0 = _mm_shuffle_epi32(m2, _MM_SHUFFLE!(0, 0, 2, 0));
    let t1 = _mm_blend_epi16(m1, m3, 0xC0);
    let t2 = _mm_blend_epi16(t0, t1, 0xF0);
    let my1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(2, 3, 0, 1));

    let t0 = _mm_slli_si128(m1, 4);
    let t1 = _mm_blend_epi16(m2, t0, 0x30);
    let t2 = _mm_blend_epi16(m0, t1, 0xF0);
    let mx2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(3, 0, 1, 2));

    let t0 = _mm_unpackhi_epi32(m0, m1);
    let t1 = _mm_slli_si128(m3, 4);
    let t2 = _mm_blend_epi16(t0, t1, 0x0C);
    let my2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(3, 0, 1, 2));
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);

    // Round-3
    let t0 = _mm_unpackhi_epi32(m2, m3);
    let t1 = _mm_blend_epi16(m3, m1, 0x0C);
    let t2 = _mm_blend_epi16(t0, t1, 0x0F);
    let mx1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(3, 1, 0, 2));

    let t0 = _mm_unpacklo_epi32(m2, m0);
    let t1 = _mm_blend_epi16(t0, m0, 0xF0);
    let t2 = _mm_slli_si128(m3, 8);
    let my1 = _mm_blend_epi16(t1, t2, 0xC0);
    
    let t0 = _mm_blend_epi16(m0, m2, 0x3C);
    let t1 = _mm_srli_si128(m1, 12);
    let t2 = _mm_blend_epi16(t0, t1, 0x03);
    let mx2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(0, 3, 2, 1));

    let t0 = _mm_slli_si128(m3, 4);
    let t1 = _mm_blend_epi16(m0, m1, 0x33);
    let t2 = _mm_blend_epi16(t1, t0, 0xC0);
    let my2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(1, 2, 3, 0));
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);


    // Round-4
    let t0 = _mm_unpackhi_epi32(m0, m1);
    let t1 = _mm_unpackhi_epi32(t0, m2);
    let t2 = _mm_blend_epi16(t1, m3, 0x0C);
    let mx1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(3, 1, 0, 2));

    let t0 = _mm_slli_si128(m2, 8);
    let t1 = _mm_blend_epi16(m3, m0, 0x0C);
    let t2 = _mm_blend_epi16(t1, t0, 0xC0);
    let my1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(2, 0, 1, 3));

    let t0 = _mm_blend_epi16(m0, m1, 0x0F);
    let t1 = _mm_blend_epi16(t0, m3, 0xC0);
    let mx2 = _mm_shuffle_epi32(t1, _MM_SHUFFLE!(0, 1, 2, 3));
    let t0 = _mm_alignr_epi8(m0, m1, 4);
    let my2 = _mm_blend_epi16(t0, m2, 0x33);
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);

    // Round-5
    let t0 = _mm_unpacklo_epi64(m1, m2);
    let t1 = _mm_unpackhi_epi64(m0, m2);
    let t2 = _mm_blend_epi16(t0, t1, 0x33);
    let mx1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(2, 0, 1, 3));

    let t0 = _mm_unpackhi_epi64(m1, m3);
    let t1 = _mm_unpacklo_epi64(m0, m1);
    let my1 = _mm_blend_epi16(t0, t1, 0x33);

    let t0 = _mm_unpackhi_epi64(m3, m1);
    let t1 = _mm_unpackhi_epi64(m2, m0);
    let t2 = _mm_blend_epi16(t1, t0, 0x33);
    let mx2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(2, 1, 0, 3));

    let t0 = _mm_blend_epi16(m0, m2, 0x03);
    let t1 = _mm_slli_si128(t0, 8);
    let t2 = _mm_blend_epi16(t1, m3, 0x0F);
    let my2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(2, 0, 3, 1));
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);

    // Round-6
    let t0 = _mm_unpackhi_epi32(m0, m1);
    let t1 = _mm_unpacklo_epi32(m0, m2);
    let mx1 = _mm_unpacklo_epi64(t0, t1);

    let t0 = _mm_srli_si128(m2, 4);
    let t1 = _mm_blend_epi16(m0, m3, 0x03);
    let my1 = _mm_blend_epi16(t1, t0, 0x3C);

    let t0 = _mm_blend_epi16(m1, m0, 0x0C);
    let t1 = _mm_srli_si128(m3, 4);
    let t2 = _mm_blend_epi16(t0, t1, 0x30);
    let mx2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(2, 3, 0, 1));

    let t0 = _mm_unpacklo_epi64(m2, m1);
    let t1 = _mm_shuffle_epi32(m3, _MM_SHUFFLE!(2, 0, 1, 0));
    let t2 = _mm_srli_si128(t0, 4);
    let my2 = _mm_blend_epi16(t1, t2, 0x33);
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);

    // Round-7
    let t0 = _mm_slli_si128(m1, 12);
    let t1 = _mm_blend_epi16(m0, m3, 0x33);
    let mx1 = _mm_blend_epi16(t1, t0, 0xC0);

    let t0 = _mm_blend_epi16(m3, m2, 0x30);
    let t1 = _mm_srli_si128(m1, 4);
    let t2 = _mm_blend_epi16(t0, t1, 0x03);
    let my1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(2, 1, 3, 0));

    let t0 = _mm_unpacklo_epi64(m0, m2);
    let t1 = _mm_srli_si128(m1, 4);
    let mx2 = _mm_shuffle_epi32(_mm_blend_epi16(t0, t1, 0x0C), _MM_SHUFFLE!(3, 1, 0, 2));

    let t0 = _mm_unpackhi_epi32(m1, m2);
    let t1 = _mm_unpackhi_epi64(m0, t0);
    let my2 = _mm_shuffle_epi32(t1, _MM_SHUFFLE!(0, 1, 2, 3));
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);

    // Round-8
    let t0 = _mm_unpackhi_epi32(m0, m1);
    let t1 = _mm_blend_epi16(t0, m3, 0x0F);
    let mx1 = _mm_shuffle_epi32(t1, _MM_SHUFFLE!(2, 0, 3, 1));

    let t0 = _mm_blend_epi16(m2, m3, 0x30);
    let t1 = _mm_srli_si128(m0, 4);
    let t2 = _mm_blend_epi16(t0, t1, 0x03);
    let my1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(1, 0, 2, 3));

    let t0 = _mm_unpackhi_epi64(m0, m3);
    let t1 = _mm_unpacklo_epi64(m1, m2);
    let t2 = _mm_blend_epi16(t0, t1, 0x3C);
    let mx2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(2, 3, 1, 0));

    let t0 = _mm_unpacklo_epi32(m0, m1);
    let t1 = _mm_unpackhi_epi32(m1, m2);
    let t2 = _mm_unpacklo_epi64(t0, t1);
    let my2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(2, 1, 0, 3));
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);

    // Round-9
    let t0 = _mm_unpackhi_epi32(m1, m3);
    let t1 = _mm_unpacklo_epi64(t0, m0);
    let t2 = _mm_blend_epi16(t1, m2, 0xC0);
    let mx1 = _mm_shufflehi_epi16(t2, _MM_SHUFFLE!(1, 0, 3, 2));

    let t0 = _mm_unpackhi_epi32(m0, m3);
    let t1 = _mm_blend_epi16(m2, t0, 0xF0);
    let my1 = _mm_shuffle_epi32(t1, _MM_SHUFFLE!(0, 2, 1, 3));

    let t0 = _mm_unpacklo_epi64(m0, m3);
    let t1 = _mm_srli_si128(m2, 8);
    let t2 = _mm_blend_epi16(t0, t1, 0x03);
    let mx2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(1, 3, 2, 0));

    let t0 = _mm_blend_epi16(m1, m0, 0x30);
    let my2 = _mm_shuffle_epi32(t0, _MM_SHUFFLE!(0, 3, 2, 1));
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);

    // Round-10
    let t0 = _mm_blend_epi16(m0, m2, 0x03);
    let t1 = _mm_blend_epi16(m1, m2, 0x30);
    let t2 = _mm_blend_epi16(t1, t0, 0x0F);
    let mx1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(1, 3, 0, 2));

    let t0 = _mm_slli_si128(m0, 4);
    let t1 = _mm_blend_epi16(m1, t0, 0xC0);
    let my1 = _mm_shuffle_epi32(t1, _MM_SHUFFLE!(1, 2, 0, 3));
    
    let t0 = _mm_unpackhi_epi32(m0, m3);
    let t1 = _mm_unpacklo_epi32(m2, m3);
    let t2 = _mm_unpackhi_epi64(t0, t1);
    let mx2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(0, 2, 1, 3));

    let t0 = _mm_blend_epi16(m3, m2, 0xC0);
    let t1 = _mm_unpacklo_epi32(m0, m3);
    let t2 = _mm_blend_epi16(t0, t1, 0x0F);
    let my2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE!(1, 2, 3, 0));
    ROUND!(va, vb, vc, vd, mx1, mx2, my1, my2);

    state[0] = _mm_xor_si128(_mm_xor_si128(state[0], va), vc);
    state[1] = _mm_xor_si128(_mm_xor_si128(state[1], vb), vd);
}