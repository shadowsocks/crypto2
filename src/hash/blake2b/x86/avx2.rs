#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::Blake2b;

macro_rules! VG {
    ($va:expr, $vb:expr, $vc:expr, $vd:expr, $vmx:expr, $vmy:expr) => {
        // NOTE: _mm_rol_epi32 和 _mm_ror_epi32 需要 avx512f, avx512vl X86 target feature.
        //       因此我们使用模拟。
        $va = _mm256_add_epi64(_mm256_add_epi64($va, $vb), $vmx);
        $vd = _mm256_xor_si256($vd, $va);
        $vd = _mm256_or_si256(_mm256_srli_epi64::<32>($vd), _mm256_slli_epi64::<32>($vd)); // rotate_right(32)

        $vc = _mm256_add_epi64($vc, $vd);
        $vb = _mm256_xor_si256($vb, $vc);
        $vb = _mm256_or_si256(_mm256_srli_epi64::<24>($vb), _mm256_slli_epi64::<40>($vb)); // rotate_right(24)

        $va = _mm256_add_epi64(_mm256_add_epi64($va, $vb), $vmy);
        $vd = _mm256_xor_si256($vd, $va);
        $vd = _mm256_or_si256(_mm256_srli_epi64::<16>($vd), _mm256_slli_epi64::<48>($vd));  // rotate_right(16)

        $vc = _mm256_add_epi64($vc, $vd);
        $vb = _mm256_xor_si256($vb, $vc);
        $vb = _mm256_or_si256(_mm256_srli_epi64::<63>($vb), _mm256_slli_epi64::<1>($vb));   // rotate_right(63)
    }
}

#[cfg(all(not(target_feature = "sse4.1"), target_feature = "avx2"))]
#[inline]
pub unsafe fn transform(state: &mut [__m256i; 4], block: &[u8], counter: u128, flags: u128) {
    debug_assert_eq!(state.len(), 4);
    debug_assert_eq!(block.len(), Blake2b::BLOCK_LEN);

    let t1 = (counter >> 64) as u64;
    let t0 = counter as u64;
    let f1 = (flags >> 64) as u64;
    let f0 = flags as u64;

    let mut va = state[0];
    let mut vb = state[1];
    let mut vc = state[2];
    let mut vd = state[3];

    vd = _mm256_xor_si256(
        vd,
        _mm256_setr_epi64x(t0 as i64, t1 as i64, f0 as i64, f1 as i64),
    );

    _mm_prefetch::<_MM_HINT_T0>(block.as_ptr().add(0) as *const i8);
    _mm_prefetch::<_MM_HINT_T0>(block.as_ptr().add(64) as *const i8);

    let m: &[u64] = core::slice::from_raw_parts(block.as_ptr() as *const u64, 16);

    macro_rules! ROUND {
        ($va:expr, $vb:expr, $vc:expr, $vd:expr, $x1:expr, $x2:expr, $x3:expr, $x4:expr, $x5:expr, $x6:expr, $x7:expr, $x8:expr, $y1:expr, $y2:expr, $y3:expr, $y4:expr, $y5:expr, $y6:expr, $y7:expr, $y8:expr) => {
            VG!(
                $va,
                $vb,
                $vc,
                $vd,
                _mm256_setr_epi64x($x1 as i64, $x2 as i64, $x3 as i64, $x4 as i64),
                _mm256_setr_epi64x($y1 as i64, $y2 as i64, $y3 as i64, $y4 as i64)
            );
            // $va = _mm256_permute4x64_epi64($va, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
            // $vd = _mm256_permute4x64_epi64($vd, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
            // $vc = _mm256_permute4x64_epi64($vc, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)

            $vb = _mm256_permute4x64_epi64($vb, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
            $vc = _mm256_permute4x64_epi64($vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
            $vd = _mm256_permute4x64_epi64($vd, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)

            VG!(
                $va,
                $vb,
                $vc,
                $vd,
                _mm256_setr_epi64x($x5 as i64, $x6 as i64, $x7 as i64, $x8 as i64),
                _mm256_setr_epi64x($y5 as i64, $y6 as i64, $y7 as i64, $y8 as i64)
            );
            // $va = _mm256_permute4x64_epi64($va, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
            // $vd = _mm256_permute4x64_epi64($vd, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
            // $vc = _mm256_permute4x64_epi64($vc, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)

            $vb = _mm256_permute4x64_epi64($vb, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
            $vc = _mm256_permute4x64_epi64($vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
            $vd = _mm256_permute4x64_epi64($vd, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
        };
    }

    // 12 Rounds
    ROUND!(
        va, vb, vc, vd, m[0], m[2], m[4], m[6], m[8], m[10], m[12], m[14], m[1], m[3], m[5], m[7],
        m[9], m[11], m[13], m[15]
    );
    ROUND!(
        va, vb, vc, vd, m[14], m[4], m[9], m[13], m[1], m[0], m[11], m[5], m[10], m[8], m[15],
        m[6], m[12], m[2], m[7], m[3]
    );
    ROUND!(
        va, vb, vc, vd, m[11], m[12], m[5], m[15], m[10], m[3], m[7], m[9], m[8], m[0], m[2],
        m[13], m[14], m[6], m[1], m[4]
    );
    ROUND!(
        va, vb, vc, vd, m[7], m[3], m[13], m[11], m[2], m[5], m[4], m[15], m[9], m[1], m[12],
        m[14], m[6], m[10], m[0], m[8]
    );
    ROUND!(
        va, vb, vc, vd, m[9], m[5], m[2], m[10], m[14], m[11], m[6], m[3], m[0], m[7], m[4], m[15],
        m[1], m[12], m[8], m[13]
    );
    ROUND!(
        va, vb, vc, vd, m[2], m[6], m[0], m[8], m[4], m[7], m[15], m[1], m[12], m[10], m[11], m[3],
        m[13], m[5], m[14], m[9]
    );
    ROUND!(
        va, vb, vc, vd, m[12], m[1], m[14], m[4], m[0], m[6], m[9], m[8], m[5], m[15], m[13],
        m[10], m[7], m[3], m[2], m[11]
    );
    ROUND!(
        va, vb, vc, vd, m[13], m[7], m[12], m[3], m[5], m[15], m[8], m[2], m[11], m[14], m[1],
        m[9], m[0], m[4], m[6], m[10]
    );
    ROUND!(
        va, vb, vc, vd, m[6], m[14], m[11], m[0], m[12], m[13], m[1], m[10], m[15], m[9], m[3],
        m[8], m[2], m[7], m[4], m[5]
    );
    ROUND!(
        va, vb, vc, vd, m[10], m[8], m[7], m[1], m[15], m[9], m[3], m[13], m[2], m[4], m[6], m[5],
        m[11], m[14], m[12], m[0]
    );

    ROUND!(
        va, vb, vc, vd, m[0], m[2], m[4], m[6], m[8], m[10], m[12], m[14], m[1], m[3], m[5], m[7],
        m[9], m[11], m[13], m[15]
    );
    ROUND!(
        va, vb, vc, vd, m[14], m[4], m[9], m[13], m[1], m[0], m[11], m[5], m[10], m[8], m[15],
        m[6], m[12], m[2], m[7], m[3]
    );

    state[0] = _mm256_xor_si256(_mm256_xor_si256(state[0], va), vc);
    state[1] = _mm256_xor_si256(_mm256_xor_si256(state[1], vb), vd);
}

#[cfg(all(target_feature = "sse4.1", target_feature = "avx2"))]
#[inline]
pub unsafe fn transform(state: &mut [__m256i; 4], block: &[u8], counter: u128, flags: u128) {
    debug_assert_eq!(state.len(), 4);
    debug_assert_eq!(block.len(), Blake2b::BLOCK_LEN);

    let t1 = (counter >> 64) as u64;
    let t0 = counter as u64;
    let f1 = (flags >> 64) as u64;
    let f0 = flags as u64;

    let mut va = state[0];
    let mut vb = state[1];
    let mut vc = state[2];
    let mut vd = state[3];

    vd = _mm256_xor_si256(
        vd,
        _mm256_setr_epi64x(t0 as i64, t1 as i64, f0 as i64, f1 as i64),
    );

    macro_rules! ROUND {
        ($va:expr, $vb:expr, $vc:expr, $vd:expr, $vmx1:expr, $vmy1:expr, $vmx2:expr, $vmy2:expr) => {
            VG!($va, $vb, $vc, $vd, $vmx1, $vmy1);
            $va = _mm256_permute4x64_epi64($va, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
            $vd = _mm256_permute4x64_epi64($vd, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
            $vc = _mm256_permute4x64_epi64($vc, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)

            VG!($va, $vb, $vc, $vd, $vmx2, $vmy2);
            $va = _mm256_permute4x64_epi64($va, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
            $vd = _mm256_permute4x64_epi64($vd, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
            $vc = _mm256_permute4x64_epi64($vc, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
        };
    }

    macro_rules! _MM_SHUFFLE {
        ($z:expr, $y:expr, $x:expr, $w:expr) => {
            ($z << 6) | ($y << 4) | ($x << 2) | $w
        };
    }

    let m0 = _mm256_broadcastsi128_si256(_mm_loadu_si128(block.as_ptr().add(0) as *const __m128i));
    let m1 = _mm256_broadcastsi128_si256(_mm_loadu_si128(block.as_ptr().add(16) as *const __m128i));
    let m2 = _mm256_broadcastsi128_si256(_mm_loadu_si128(block.as_ptr().add(32) as *const __m128i));
    let m3 = _mm256_broadcastsi128_si256(_mm_loadu_si128(block.as_ptr().add(48) as *const __m128i));
    let m4 = _mm256_broadcastsi128_si256(_mm_loadu_si128(block.as_ptr().add(64) as *const __m128i));
    let m5 = _mm256_broadcastsi128_si256(_mm_loadu_si128(block.as_ptr().add(80) as *const __m128i));
    let m6 = _mm256_broadcastsi128_si256(_mm_loadu_si128(block.as_ptr().add(96) as *const __m128i));
    let m7 =
        _mm256_broadcastsi128_si256(_mm_loadu_si128(block.as_ptr().add(112) as *const __m128i));

    // 12 Rounds

    let mut t0;
    let mut t1;

    let mut vmx1;
    let mut vmy1;

    let mut vmx2;
    let mut vmy2;

    // Round 1
    t0 = _mm256_unpacklo_epi64(m0, m1);
    t1 = _mm256_unpacklo_epi64(m2, m3);
    vmx1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpackhi_epi64(m0, m1);
    t1 = _mm256_unpackhi_epi64(m2, m3);
    vmy1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpacklo_epi64(m7, m4);
    t1 = _mm256_unpacklo_epi64(m5, m6);
    vmx2 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpackhi_epi64(m7, m4);
    t1 = _mm256_unpackhi_epi64(m5, m6);
    vmy2 = _mm256_blend_epi32(t0, t1, 0xF0);
    ROUND!(va, vb, vc, vd, vmx1, vmy1, vmx2, vmy2);

    // Round 2
    t0 = _mm256_unpacklo_epi64(m7, m2);
    t1 = _mm256_unpackhi_epi64(m4, m6);
    vmx1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpacklo_epi64(m5, m4);
    t1 = _mm256_alignr_epi8(m3, m7, 8);
    vmy1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpackhi_epi64(m2, m0);
    t1 = _mm256_blend_epi32(m5, m0, 0x33);
    vmx2 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_alignr_epi8(m6, m1, 8);
    t1 = _mm256_blend_epi32(m3, m1, 0x33);
    vmy2 = _mm256_blend_epi32(t0, t1, 0xF0);
    ROUND!(va, vb, vc, vd, vmx1, vmy1, vmx2, vmy2);

    // Round 3
    t0 = _mm256_alignr_epi8(m6, m5, 8);
    t1 = _mm256_unpackhi_epi64(m2, m7);
    vmx1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpacklo_epi64(m4, m0);
    t1 = _mm256_blend_epi32(m6, m1, 0x33);
    vmy1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_alignr_epi8(m5, m4, 8);
    t1 = _mm256_unpackhi_epi64(m1, m3);
    vmx2 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpacklo_epi64(m2, m7);
    t1 = _mm256_blend_epi32(m0, m3, 0x33);
    vmy2 = _mm256_blend_epi32(t0, t1, 0xF0);
    ROUND!(va, vb, vc, vd, vmx1, vmy1, vmx2, vmy2);

    // Round 4
    t0 = _mm256_unpackhi_epi64(m3, m1);
    t1 = _mm256_unpackhi_epi64(m6, m5);
    vmx1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpackhi_epi64(m4, m0);
    t1 = _mm256_unpacklo_epi64(m6, m7);
    vmy1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_alignr_epi8(m1, m7, 8);
    t1 = _mm256_shuffle_epi32(m2, _MM_SHUFFLE!(1, 0, 3, 2));
    vmx2 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpacklo_epi64(m4, m3);
    t1 = _mm256_unpacklo_epi64(m5, m0);
    vmy2 = _mm256_blend_epi32(t0, t1, 0xF0);
    ROUND!(va, vb, vc, vd, vmx1, vmy1, vmx2, vmy2);

    // Round 5
    t0 = _mm256_unpackhi_epi64(m4, m2);
    t1 = _mm256_unpacklo_epi64(m1, m5);
    vmx1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_blend_epi32(m3, m0, 0x33);
    t1 = _mm256_blend_epi32(m7, m2, 0x33);
    vmy1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_alignr_epi8(m7, m1, 8);
    t1 = _mm256_alignr_epi8(m3, m5, 8);
    vmx2 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpackhi_epi64(m6, m0);
    t1 = _mm256_unpacklo_epi64(m6, m4);
    vmy2 = _mm256_blend_epi32(t0, t1, 0xF0);
    ROUND!(va, vb, vc, vd, vmx1, vmy1, vmx2, vmy2);

    // Round 6
    t0 = _mm256_unpacklo_epi64(m1, m3);
    t1 = _mm256_unpacklo_epi64(m0, m4);
    vmx1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpacklo_epi64(m6, m5);
    t1 = _mm256_unpackhi_epi64(m5, m1);
    vmy1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_alignr_epi8(m2, m0, 8);
    t1 = _mm256_unpackhi_epi64(m3, m7);
    vmx2 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpackhi_epi64(m4, m6);
    t1 = _mm256_alignr_epi8(m7, m2, 8);
    vmy2 = _mm256_blend_epi32(t0, t1, 0xF0);
    ROUND!(va, vb, vc, vd, vmx1, vmy1, vmx2, vmy2);

    // Round 7
    t0 = _mm256_blend_epi32(m0, m6, 0x33);
    t1 = _mm256_unpacklo_epi64(m7, m2);
    vmx1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpackhi_epi64(m2, m7);
    t1 = _mm256_alignr_epi8(m5, m6, 8);
    vmy1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpacklo_epi64(m4, m0);
    t1 = _mm256_blend_epi32(m4, m3, 0x33);
    vmx2 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpackhi_epi64(m5, m3);
    t1 = _mm256_shuffle_epi32(m1, _MM_SHUFFLE!(1, 0, 3, 2));
    vmy2 = _mm256_blend_epi32(t0, t1, 0xF0);
    ROUND!(va, vb, vc, vd, vmx1, vmy1, vmx2, vmy2);

    // Round 8
    t0 = _mm256_unpackhi_epi64(m6, m3);
    t1 = _mm256_blend_epi32(m1, m6, 0x33);
    vmx1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_alignr_epi8(m7, m5, 8);
    t1 = _mm256_unpackhi_epi64(m0, m4);
    vmy1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_blend_epi32(m2, m1, 0x33);
    t1 = _mm256_alignr_epi8(m4, m7, 8);
    vmx2 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpacklo_epi64(m5, m0);
    t1 = _mm256_unpacklo_epi64(m2, m3);
    vmy2 = _mm256_blend_epi32(t0, t1, 0xF0);
    ROUND!(va, vb, vc, vd, vmx1, vmy1, vmx2, vmy2);

    // Round 9
    t0 = _mm256_unpacklo_epi64(m3, m7);
    t1 = _mm256_alignr_epi8(m0, m5, 8);
    vmx1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpackhi_epi64(m7, m4);
    t1 = _mm256_alignr_epi8(m4, m1, 8);
    vmy1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpacklo_epi64(m5, m6);
    t1 = _mm256_unpackhi_epi64(m6, m0);
    vmx2 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_alignr_epi8(m1, m2, 8);
    t1 = _mm256_alignr_epi8(m2, m3, 8);
    vmy2 = _mm256_blend_epi32(t0, t1, 0xF0);
    ROUND!(va, vb, vc, vd, vmx1, vmy1, vmx2, vmy2);

    // Round 10
    t0 = _mm256_unpacklo_epi64(m5, m4);
    t1 = _mm256_unpackhi_epi64(m3, m0);
    vmx1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpacklo_epi64(m1, m2);
    t1 = _mm256_blend_epi32(m2, m3, 0x33);
    vmy1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpackhi_epi64(m6, m7);
    t1 = _mm256_unpackhi_epi64(m4, m1);
    vmx2 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_blend_epi32(m5, m0, 0x33);
    t1 = _mm256_unpacklo_epi64(m7, m6);
    vmy2 = _mm256_blend_epi32(t0, t1, 0xF0);
    ROUND!(va, vb, vc, vd, vmx1, vmy1, vmx2, vmy2);

    // Round 11
    t0 = _mm256_unpacklo_epi64(m0, m1);
    t1 = _mm256_unpacklo_epi64(m2, m3);
    vmx1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpackhi_epi64(m0, m1);
    t1 = _mm256_unpackhi_epi64(m2, m3);
    vmy1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpacklo_epi64(m7, m4);
    t1 = _mm256_unpacklo_epi64(m5, m6);
    vmx2 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpackhi_epi64(m7, m4);
    t1 = _mm256_unpackhi_epi64(m5, m6);
    vmy2 = _mm256_blend_epi32(t0, t1, 0xF0);
    ROUND!(va, vb, vc, vd, vmx1, vmy1, vmx2, vmy2);

    // Round 12
    t0 = _mm256_unpacklo_epi64(m7, m2);
    t1 = _mm256_unpackhi_epi64(m4, m6);
    vmx1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpacklo_epi64(m5, m4);
    t1 = _mm256_alignr_epi8(m3, m7, 8);
    vmy1 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_unpackhi_epi64(m2, m0);
    t1 = _mm256_blend_epi32(m5, m0, 0x33);
    vmx2 = _mm256_blend_epi32(t0, t1, 0xF0);

    t0 = _mm256_alignr_epi8(m6, m1, 8);
    t1 = _mm256_blend_epi32(m3, m1, 0x33);
    vmy2 = _mm256_blend_epi32(t0, t1, 0xF0);
    ROUND!(va, vb, vc, vd, vmx1, vmy1, vmx2, vmy2);

    state[0] = _mm256_xor_si256(_mm256_xor_si256(state[0], va), vc);
    state[1] = _mm256_xor_si256(_mm256_xor_si256(state[1], vb), vd);
}
