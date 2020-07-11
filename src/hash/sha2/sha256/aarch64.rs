use super::K32;
use super::Sha256;


use core::arch::aarch64::*;


#[inline]
pub fn transform(state: &mut [u32; 8], block: &[u8]) {
    // Process a block with the SHA-256 algorithm.
    // https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-arm.c
    debug_assert_eq!(state.len(), 8);
    debug_assert_eq!(block.len(), Sha256::BLOCK_LEN);

    // vld1q_u32
    fn uint32x4_t_new(a: u32, b: u32, c: u32, d: u32) -> uint32x4_t {
        let array = [ a, b, c, d ];
        union U {
            array: [u32; 4],
            vec: uint32x4_t,
        }
        unsafe { U { array }.vec }
    }

    fn uint32x4_t_from_be_bytes(data: &[u8]) -> uint32x4_t {
        let a = u32::from_be_bytes([data[ 0], data[ 1], data[ 2], data[ 3]]);
        let b = u32::from_be_bytes([data[ 4], data[ 5], data[ 6], data[ 7]]);
        let c = u32::from_be_bytes([data[ 8], data[ 9], data[10], data[11]]);
        let d = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        uint32x4_t_new(a, b, c, d)
    }

    unsafe {
        // Load state
        let mut state0: uint32x4_t = uint32x4_t_new(state[0], state[1], state[2], state[3]);
        let mut state1: uint32x4_t = uint32x4_t_new(state[4], state[5], state[6], state[7]);
        
        // Save state
        let abef_save: uint32x4_t = state0;
        let cdgh_save: uint32x4_t = state1;

        let mut msg0: uint32x4_t = uint32x4_t_from_be_bytes(&block[ 0..16]);
        let mut msg1: uint32x4_t = uint32x4_t_from_be_bytes(&block[16..32]);
        let mut msg2: uint32x4_t = uint32x4_t_from_be_bytes(&block[32..48]);
        let mut msg3: uint32x4_t = uint32x4_t_from_be_bytes(&block[48..64]);

        let mut tmp0: uint32x4_t;
        let mut tmp1: uint32x4_t;
        let mut tmp2: uint32x4_t;

        tmp0 = vaddq_u32(msg0, uint32x4_t_new(K32[0], K32[1], K32[2], K32[3]));

        // Rounds 0-3
        msg0 = vsha256su0q_u32(msg0, msg1);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, uint32x4_t_new(K32[4], K32[5], K32[6], K32[7]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);

        // Rounds 4-7
        msg1 = vsha256su0q_u32(msg1, msg2);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, uint32x4_t_new(K32[8], K32[9], K32[10], K32[11]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);

        // Rounds 8-11
        msg2 = vsha256su0q_u32(msg2, msg3);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, uint32x4_t_new(K32[12], K32[13], K32[14], K32[15]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);

        // Rounds 12-15
        msg3 = vsha256su0q_u32(msg3, msg0);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg0, uint32x4_t_new(K32[16], K32[17], K32[18], K32[19]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);

        // Rounds 16-19
        msg0 = vsha256su0q_u32(msg0, msg1);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, uint32x4_t_new(K32[20], K32[21], K32[22], K32[23]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);

        // Rounds 20-23
        msg1 = vsha256su0q_u32(msg1, msg2);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, uint32x4_t_new(K32[24], K32[25], K32[26], K32[27]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);

        // Rounds 24-27
        msg2 = vsha256su0q_u32(msg2, msg3);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, uint32x4_t_new(K32[28], K32[29], K32[30], K32[31]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);

        // Rounds 28-31
        msg3 = vsha256su0q_u32(msg3, msg0);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg0, uint32x4_t_new(K32[32], K32[33], K32[34], K32[35]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);

        // Rounds 32-35
        msg0 = vsha256su0q_u32(msg0, msg1);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, uint32x4_t_new(K32[36], K32[37], K32[38], K32[39]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);

        // Rounds 36-39
        msg1 = vsha256su0q_u32(msg1, msg2);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, uint32x4_t_new(K32[40], K32[41], K32[42], K32[43]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);

        // Rounds 40-43
        msg2 = vsha256su0q_u32(msg2, msg3);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, uint32x4_t_new(K32[44], K32[45], K32[46], K32[47]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);

        // Rounds 44-47
        msg3 = vsha256su0q_u32(msg3, msg0);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg0, uint32x4_t_new(K32[48], K32[49], K32[50], K32[51]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);

        // Rounds 48-51
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, uint32x4_t_new(K32[52], K32[53], K32[54], K32[55]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);

        // Rounds 52-55
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, uint32x4_t_new(K32[56], K32[57], K32[58], K32[59]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);

        // Rounds 56-59
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, uint32x4_t_new(K32[60], K32[61], K32[62], K32[63]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);

        // Rounds 60-63
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);

        // Combine state
        state0 = vaddq_u32(state0, abef_save);
        state1 = vaddq_u32(state1, cdgh_save);
        
        // vst1q_u32
        #[inline]
        fn save_state(state: &mut [u32], vec: uint32x4_t) {
            union U {
                array: [u32; 4],
                vec: uint32x4_t,
            }
            let array = unsafe { U { vec }.array };
            state[0] = array[0];
            state[1] = array[1];
            state[2] = array[2];
            state[3] = array[3];
        }

        // Save state
        save_state(&mut state[0..4], state0);
        save_state(&mut state[4..8], state1);
    }
}
