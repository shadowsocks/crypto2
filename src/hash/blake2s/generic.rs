use super::BLAKE2S_IV;
use super::BLAKE2S_224_IV;
use super::BLAKE2S_256_IV;


const SIGMA: [[u8; 16]; 12] = [
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
    [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
    [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
    [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
    [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
    [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
    [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
    [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
    [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 ],
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
];


macro_rules! G {
    ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {
        $a = $a.wrapping_add($b).wrapping_add($mx);
        $d = ($d ^ $a).rotate_right(16); // R1

        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_right(12); // R2

        $a = $a.wrapping_add($b).wrapping_add($my);
        $d = ($d ^ $a).rotate_right( 8); // R3

        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_right( 7); // R4
    }
}

macro_rules! ROUND {
    ($state:expr, $m:expr, $sigma:expr) => {
        G!($state[ 0], $state[ 4], $state[ 8], $state[12],  $m[$sigma[ 0] as usize], $m[$sigma[ 1] as usize]);
        G!($state[ 1], $state[ 5], $state[ 9], $state[13],  $m[$sigma[ 2] as usize], $m[$sigma[ 3] as usize]);
        G!($state[ 2], $state[ 6], $state[10], $state[14],  $m[$sigma[ 4] as usize], $m[$sigma[ 5] as usize]);
        G!($state[ 3], $state[ 7], $state[11], $state[15],  $m[$sigma[ 6] as usize], $m[$sigma[ 7] as usize]);
        
        G!($state[ 0], $state[ 5], $state[10], $state[15],  $m[$sigma[ 8] as usize], $m[$sigma[ 9] as usize]);
        G!($state[ 1], $state[ 6], $state[11], $state[12],  $m[$sigma[10] as usize], $m[$sigma[11] as usize]);
        G!($state[ 2], $state[ 7], $state[ 8], $state[13],  $m[$sigma[12] as usize], $m[$sigma[13] as usize]);
        G!($state[ 3], $state[ 4], $state[ 9], $state[14],  $m[$sigma[14] as usize], $m[$sigma[15] as usize]);
    }
}

#[inline]
fn transform(state: &mut [u32; 8], block: &[u8], counter: u64, flags: u64) {
    debug_assert_eq!(state.len(), 8);
    debug_assert_eq!(block.len(), Blake2s::BLOCK_LEN);

    let mut m = [0u32; 16];
    let mut v = [0u32; 16];

    for i in 0usize..16 {
        let pos = i * 4;
        m[i] = u32::from_le_bytes([
            block[pos + 0],
            block[pos + 1], 
            block[pos + 2], 
            block[pos + 3], 
        ]);
    }

    let t1 = (counter >> 32) as u32;
    let t0 = counter as u32;
    let f1 = (flags >> 32) as u32;
    let f0 = flags as u32;

    v[..8].copy_from_slice(&state[..]);

    v[ 8] = BLAKE2S_IV[0];
    v[ 9] = BLAKE2S_IV[1];
    v[10] = BLAKE2S_IV[2];
    v[11] = BLAKE2S_IV[3];
    v[12] = BLAKE2S_IV[4] ^ t0;
    v[13] = BLAKE2S_IV[5] ^ t1;
    v[14] = BLAKE2S_IV[6] ^ f0;
    v[15] = BLAKE2S_IV[7] ^ f1;

    // 10 Rounds
    ROUND!(v, m, SIGMA[0]);
    ROUND!(v, m, SIGMA[1]);
    ROUND!(v, m, SIGMA[2]);
    ROUND!(v, m, SIGMA[3]);
    ROUND!(v, m, SIGMA[4]);
    ROUND!(v, m, SIGMA[5]);
    ROUND!(v, m, SIGMA[6]);
    ROUND!(v, m, SIGMA[7]);
    ROUND!(v, m, SIGMA[8]);
    ROUND!(v, m, SIGMA[9]);

    state[0] = state[0] ^ v[0] ^ v[ 8];
    state[1] = state[1] ^ v[1] ^ v[ 9];
    state[2] = state[2] ^ v[2] ^ v[10];
    state[3] = state[3] ^ v[3] ^ v[11];
    state[4] = state[4] ^ v[4] ^ v[12];
    state[5] = state[5] ^ v[5] ^ v[13];
    state[6] = state[6] ^ v[6] ^ v[14];
    state[7] = state[7] ^ v[7] ^ v[15];
}


#[derive(Clone)]
pub struct Blake2s {
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
    state: [u32; 8],
    counter: u64, // T0, T1
    hlen: usize,
}

impl Blake2s {
    pub const BLOCK_LEN: usize  = 64;
    
    pub const H_MIN: usize =  1;
    pub const H_MAX: usize = 32;
    
    pub const K_MIN: usize =  0;
    pub const K_MAX: usize = 32;

    pub const M_MIN: u64 = 0;
    pub const M_MAX: u64 = u64::MAX;

    pub const ROUNDS: usize = 10; // Rounds in F


    #[inline]
    pub fn new(key: &[u8], hlen: usize) -> Self {
        let klen = key.len();

        assert!(hlen >= Self::H_MIN && hlen <= Self::H_MAX);
        assert!(klen >= Self::K_MIN && klen <= Self::K_MAX);

        // parameter block
        // digest_length, key_length, fanout, depth
        let p1 = u32::from_le_bytes([ hlen as u8, klen as u8, 1, 1]);

        // IV XOR ParamBlock
        let s1 = BLAKE2S_IV[0] ^ p1;
        let state: [u32; 8] = [
            // H
            s1,          BLAKE2S_IV[1], 
            BLAKE2S_IV[2], BLAKE2S_IV[3],
            BLAKE2S_IV[4], BLAKE2S_IV[5], 
            BLAKE2S_IV[6], BLAKE2S_IV[7],
        ];

        let mut hasher = Self {
            buffer: [0u8; Self::BLOCK_LEN],
            offset: 0,
            state,
            counter: 0,
            hlen,
        };

        if klen > 0 {
            let mut block = [0u8; Self::BLOCK_LEN];
            block[..klen].copy_from_slice(&key);

            hasher.update(&block);
        }

        hasher
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;
        while i < data.len() {
            if self.offset == Self::BLOCK_LEN {
                self.counter = self.counter.wrapping_add(Self::BLOCK_LEN as u64);
                
                transform(&mut self.state, &self.buffer, self.counter, 0);
                self.offset = 0;
            }

            if self.offset < Self::BLOCK_LEN {
                self.buffer[self.offset] = data[i];
                self.offset += 1;
                i += 1;
            }
        }
    }

    #[inline]
    pub fn finalize(mut self) -> [u8; Self::H_MAX] {
        assert_eq!(out.len(), self.hlen);

        self.counter = self.counter.wrapping_add(self.offset as u64);

        // Padding
        while self.offset < Self::BLOCK_LEN {
            self.buffer[self.offset] = 0;
            self.offset += 1;
        }

        transform(&mut self.state, &self.buffer, self.counter, u32::MAX as u64);

        let mut hash = [0u8; Self::H_MAX]; // 32
        hash[ 0.. 4].copy_from_slice(&self.state[0].to_le_bytes());
        hash[ 4.. 8].copy_from_slice(&self.state[1].to_le_bytes());
        hash[ 8..12].copy_from_slice(&self.state[2].to_le_bytes());
        hash[12..16].copy_from_slice(&self.state[3].to_le_bytes());
        hash[16..20].copy_from_slice(&self.state[4].to_le_bytes());
        hash[20..24].copy_from_slice(&self.state[5].to_le_bytes());
        hash[24..28].copy_from_slice(&self.state[6].to_le_bytes());
        hash[28..32].copy_from_slice(&self.state[7].to_le_bytes());

        hash
    }

    #[inline]
    pub fn oneshot_hash<T: AsRef<[u8]>>(iv: [u32; 8], data: T) -> [u8; Self::H_MAX] {
        Self::oneshot(iv, b"", data)
    }

    #[inline]
    pub fn oneshot<T: AsRef<[u8]>>(iv: [u32; 8], key: &[u8], data: T) -> [u8; Self::H_MAX] {
        let mut h = Self::new(iv, key);
        h.update(data.as_ref());
        h.finalize()
    }
}


#[cfg(test)]
#[bench]
fn bench_blake2s_transform(b: &mut test::Bencher) {
    let mut state = test::black_box([u32::MAX; 8]);
    let block = test::black_box([3u8; 64]);

    b.iter(|| {
        transform(&mut state, &block, Blake2s::BLOCK_LEN as u64, 0)
    })
}


