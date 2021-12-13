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

macro_rules! ROUND {
    ($va:expr, $vb:expr, $vc:expr, $vd:expr, $x1:expr, $x2:expr, $x3:expr, $x4:expr, $x5:expr, $x6:expr, $x7:expr, $x8:expr, $y1:expr, $y2:expr, $y3:expr, $y4:expr, $y5:expr, $y6:expr, $y7:expr, $y8:expr) => {
        VG!(
            $va,
            $vb,
            $vc,
            $vd,
            _mm_setr_epi32($x1 as i32, $x2 as i32, $x3 as i32, $x4 as i32),
            _mm_setr_epi32($y1 as i32, $y2 as i32, $y3 as i32, $y4 as i32)
        );
        $vb = _mm_shuffle_epi32($vb, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
        $vc = _mm_shuffle_epi32($vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        $vd = _mm_shuffle_epi32($vd, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)

        VG!(
            $va,
            $vb,
            $vc,
            $vd,
            _mm_setr_epi32($x5 as i32, $x6 as i32, $x7 as i32, $x8 as i32),
            _mm_setr_epi32($y5 as i32, $y6 as i32, $y7 as i32, $y8 as i32)
        );
        $vb = _mm_shuffle_epi32($vb, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
        $vc = _mm_shuffle_epi32($vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        $vd = _mm_shuffle_epi32($vd, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    };
}

#[cfg(target_feature = "sse2")]
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

    vd = _mm_xor_si128(
        vd,
        _mm_setr_epi32(t0 as i32, t1 as i32, f0 as i32, f1 as i32),
    );

    _mm_prefetch::<_MM_HINT_T0>(block.as_ptr() as *const i8);

    let m: &[u32] = core::slice::from_raw_parts(block.as_ptr() as *const u32, 16);

    // 10 Rounds
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

    state[0] = _mm_xor_si128(_mm_xor_si128(state[0], va), vc);
    state[1] = _mm_xor_si128(_mm_xor_si128(state[1], vb), vd);
}
