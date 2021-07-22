#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;


use super::BLAKE2S_IV;
use super::Blake2s;


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
        $vd = _mm_xor_si128(_mm_srli_epi32::<8>($vd), _mm_slli_epi32::<24>($vd));  // rotate_right(8)
        
        $vc = _mm_add_epi32($vc, $vd);
        $vb = _mm_xor_si128($vb, $vc);
        $vb = _mm_xor_si128(_mm_srli_epi32::<7>($vb), _mm_slli_epi32::<25>($vb));  // rotate_right(7)
    }
}

macro_rules! ROUND {
    ($va:expr, $vb:expr, $vc:expr, $vd:expr, 
        $x1:expr, $x2:expr, $x3:expr, $x4:expr, $x5:expr, $x6:expr, $x7:expr, $x8:expr,
        $y1:expr, $y2:expr, $y3:expr, $y4:expr, $y5:expr, $y6:expr, $y7:expr, $y8:expr
    ) => {
        VG!($va, $vb, $vc, $vd, _mm_setr_epi32($x1 as i32, $x2 as i32, $x3 as i32, $x4 as i32), _mm_setr_epi32($y1 as i32, $y2 as i32, $y3 as i32, $y4 as i32));
        $vb = _mm_shuffle_epi32($vb, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
        $vc = _mm_shuffle_epi32($vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        $vd = _mm_shuffle_epi32($vd, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)

        VG!($va, $vb, $vc, $vd, _mm_setr_epi32($x5 as i32, $x6 as i32, $x7 as i32, $x8 as i32), _mm_setr_epi32($y5 as i32, $y6 as i32, $y7 as i32, $y8 as i32));
        $vb = _mm_shuffle_epi32($vb, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
        $vc = _mm_shuffle_epi32($vc, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        $vd = _mm_shuffle_epi32($vd, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    }
}


#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2",
))]
#[inline]
pub fn transform(state: &mut [u32; 8], block: &[u8], block_counter: u64, flags: u64) {
    debug_assert_eq!(state.len(), 8);
    debug_assert_eq!(block.len(), Blake2s::BLOCK_LEN);
    unsafe {
        let m: &[u32] = core::slice::from_raw_parts(block.as_ptr() as *const u32, 16);

        let t1 = (block_counter >> 32) as u32;
        let t0 = block_counter as u32;
        let f1 = (flags >> 32) as u32;
        let f0 = flags as u32;

        // let n1 = BLAKE2S_IV[4] ^ t0;
        // let n2 = BLAKE2S_IV[5] ^ t1;
        // let n3 = BLAKE2S_IV[6] ^ f0;
        // let n4 = BLAKE2S_IV[7] ^ f1;

        let mut va = _mm_setr_epi32(state[0] as i32, state[1] as i32, state[2] as i32, state[3] as i32);
        let mut vb = _mm_setr_epi32(state[4] as i32, state[5] as i32, state[6] as i32, state[7] as i32);
        let mut vc = _mm_setr_epi32(BLAKE2S_IV[0] as i32, BLAKE2S_IV[1] as i32, BLAKE2S_IV[2] as i32, BLAKE2S_IV[3] as i32);
        // let mut vd = _mm_setr_epi32(n1 as i32, n2 as i32, n3 as i32, n4 as i32);
        let mut vd = _mm_setr_epi32(t0 as i32, t1 as i32, f0 as i32, f1 as i32);

        vd = _mm_xor_si128(vd, _mm_setr_epi32(BLAKE2S_IV[4] as i32, BLAKE2S_IV[5] as i32, BLAKE2S_IV[6] as i32, BLAKE2S_IV[7] as i32));

        // 10 Rounds
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

        let mut s1 = _mm_setr_epi32(state[0] as i32, state[1] as i32, state[2] as i32, state[3] as i32);
        let mut s2 = _mm_setr_epi32(state[4] as i32, state[5] as i32, state[6] as i32, state[7] as i32);
        
        s1 = _mm_xor_si128(_mm_xor_si128(s1, va), vc);
        s2 = _mm_xor_si128(_mm_xor_si128(s2, vb), vd);

        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, s1);
        _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, s2);
    }
}


#[cfg(test)]
#[bench]
fn bench_blake2s_transform(b: &mut test::Bencher) {
    let mut state = test::black_box([u32::MAX; 8]);
    let block = test::black_box([3u8; 64]);

    b.iter(|| {
        transform(&mut state, &block, 1, 0)
    })
}
