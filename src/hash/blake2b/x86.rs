#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;


use super::BLAKE2B_IV;
use super::Blake2b;


macro_rules! VG {
    ($va:expr, $vb:expr, $vc:expr, $vd:expr, $vmx:expr, $vmy:expr) => {
        // NOTE: _mm_rol_epi32 和 _mm_ror_epi32 需要 avx512f, avx512vl X86 target feature.
        //       因此我们使用模拟。
        $va = _mm256_add_epi64(_mm256_add_epi64($va, $vb), $vmx);
        $vd = _mm256_xor_si256($vd, $va);
        $vd = _mm256_xor_si256(_mm256_srli_epi64::<32>($vd), _mm256_slli_epi64::<32>($vd)); // rotate_right(32)
        
        $vc = _mm256_add_epi64($vc, $vd);
        $vb = _mm256_xor_si256($vb, $vc);
        $vb = _mm256_xor_si256(_mm256_srli_epi64::<24>($vb), _mm256_slli_epi64::<40>($vb)); // rotate_right(24)
        
        $va = _mm256_add_epi64(_mm256_add_epi64($va, $vb), $vmy);
        $vd = _mm256_xor_si256($vd, $va);
        $vd = _mm256_xor_si256(_mm256_srli_epi64::<16>($vd), _mm256_slli_epi64::<48>($vd));  // rotate_right(16)
        
        $vc = _mm256_add_epi64($vc, $vd);
        $vb = _mm256_xor_si256($vb, $vc);
        $vb = _mm256_xor_si256(_mm256_srli_epi64::<63>($vb), _mm256_slli_epi64::<1>($vb));   // rotate_right(63)
    }
}

macro_rules! ROUND {
    ($va:expr, $vb:expr, $vc:expr, $vd:expr, 
        $x1:expr, $x2:expr, $x3:expr, $x4:expr, $x5:expr, $x6:expr, $x7:expr, $x8:expr,
        $y1:expr, $y2:expr, $y3:expr, $y4:expr, $y5:expr, $y6:expr, $y7:expr, $y8:expr
    ) => {
        VG!($va, $vb, $vc, $vd, _mm256_setr_epi64x($x1 as i64, $x2 as i64, $x3 as i64, $x4 as i64), _mm256_setr_epi64x($y1 as i64, $y2 as i64, $y3 as i64, $y4 as i64));
        $vb = _mm256_permute4x64_epi64($vb, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
        $vc = _mm256_permute4x64_epi64($vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        $vd = _mm256_permute4x64_epi64($vd, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)

        VG!($va, $vb, $vc, $vd, _mm256_setr_epi64x($x5 as i64, $x6 as i64, $x7 as i64, $x8 as i64), _mm256_setr_epi64x($y5 as i64, $y6 as i64, $y7 as i64, $y8 as i64));
        $vb = _mm256_permute4x64_epi64($vb, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
        $vc = _mm256_permute4x64_epi64($vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        $vd = _mm256_permute4x64_epi64($vd, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    }
}


#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2",
))]
#[inline]
pub fn transform(state: &mut [u64; 8], block: &[u8], block_counter: u128, flags: u128) {
    debug_assert_eq!(state.len(), 8);
    debug_assert_eq!(block.len(), Blake2b::BLOCK_LEN);
    unsafe {
        let m: &[u64] = core::slice::from_raw_parts(block.as_ptr() as *const u64, 16);

        let t1 = (block_counter >> 64) as u64;
        let t0 = block_counter as u64;
        let f1 = (flags >> 64) as u64;
        let f0 = flags as u64;

        // let n1 = BLAKE2B_IV[4] ^ t0;
        // let n2 = BLAKE2B_IV[5] ^ t1;
        // let n3 = BLAKE2B_IV[6] ^ f0;
        // let n4 = BLAKE2B_IV[7] ^ f1;

        let mut va = _mm256_setr_epi64x(state[0] as i64, state[1] as i64, state[2] as i64, state[3] as i64);
        let mut vb = _mm256_setr_epi64x(state[4] as i64, state[5] as i64, state[6] as i64, state[7] as i64);
        let mut vc = _mm256_setr_epi64x(BLAKE2B_IV[0] as i64, BLAKE2B_IV[1] as i64, BLAKE2B_IV[2] as i64, BLAKE2B_IV[3] as i64);
        // let mut vd = _mm256_setr_epi64x(n1 as i64, n2 as i64, n3 as i64, n4 as i64);
        let mut vd = _mm256_setr_epi64x(t0 as i64, t1 as i64, f0 as i64, f1 as i64);

        vd = _mm256_xor_si256(vd, _mm256_setr_epi64x(BLAKE2B_IV[4] as i64, BLAKE2B_IV[5] as i64, BLAKE2B_IV[6] as i64, BLAKE2B_IV[7] as i64));

        // 12 Rounds
        ROUND!(va, vb, vc, vd, m[00], m[02], m[04], m[06],   m[08], m[10], m[12], m[14],   m[01], m[03], m[05], m[07],   m[09], m[11], m[13], m[15]);
        ROUND!(va, vb, vc, vd, m[14], m[04], m[09], m[13],   m[01], m[00], m[11], m[05],   m[10], m[08], m[15], m[06],   m[12], m[02], m[07], m[03]);
        ROUND!(va, vb, vc, vd, m[11], m[12], m[05], m[15],   m[10], m[03], m[07], m[09],   m[08], m[00], m[02], m[13],   m[14], m[06], m[01], m[04]);
        ROUND!(va, vb, vc, vd, m[07], m[03], m[13], m[11],   m[02], m[05], m[04], m[15],   m[09], m[01], m[12], m[14],   m[06], m[10], m[00], m[08]);
        ROUND!(va, vb, vc, vd, m[09], m[05], m[02], m[10],   m[14], m[11], m[06], m[03],   m[00], m[07], m[04], m[15],   m[01], m[12], m[08], m[13]);
        ROUND!(va, vb, vc, vd, m[02], m[06], m[00], m[08],   m[04], m[07], m[15], m[01],   m[12], m[10], m[11], m[03],   m[13], m[05], m[14], m[09]);
        ROUND!(va, vb, vc, vd, m[12], m[01], m[14], m[04],   m[00], m[06], m[09], m[08],   m[05], m[15], m[13], m[10],   m[07], m[03], m[02], m[11]);
        ROUND!(va, vb, vc, vd, m[13], m[07], m[12], m[03],   m[05], m[15], m[08], m[02],   m[11], m[14], m[01], m[09],   m[00], m[04], m[06], m[10]);
        ROUND!(va, vb, vc, vd, m[06], m[14], m[11], m[00],   m[12], m[13], m[01], m[10],   m[15], m[09], m[03], m[08],   m[02], m[07], m[04], m[05]);
        ROUND!(va, vb, vc, vd, m[10], m[08], m[07], m[01],   m[15], m[09], m[03], m[13],   m[02], m[04], m[06], m[05],   m[11], m[14], m[12], m[00]);

        ROUND!(va, vb, vc, vd, m[00], m[02], m[04], m[06],   m[08], m[10], m[12], m[14],   m[01], m[03], m[05], m[07],   m[09], m[11], m[13], m[15]);
        ROUND!(va, vb, vc, vd, m[14], m[04], m[09], m[13],   m[01], m[00], m[11], m[05],   m[10], m[08], m[15], m[06],   m[12], m[02], m[07], m[03]);

        let mut s1 = _mm256_setr_epi64x(state[0] as i64, state[1] as i64, state[2] as i64, state[3] as i64);
        let mut s2 = _mm256_setr_epi64x(state[4] as i64, state[5] as i64, state[6] as i64, state[7] as i64);
        
        s1 = _mm256_xor_si256(_mm256_xor_si256(s1, va), vc);
        s2 = _mm256_xor_si256(_mm256_xor_si256(s2, vb), vd);

        _mm256_storeu_si256(state.as_mut_ptr() as *mut __m256i, s1);
        _mm256_storeu_si256(state.as_mut_ptr().add(4) as *mut __m256i, s2);
    }
}