use super::generic;
use super::platform;

#[derive(Clone)]
pub enum GHash {
    Generic(generic::GHash),
    Platform(platform::GHash),
}

impl GHash {
    pub const KEY_LEN: usize = generic::GHash::KEY_LEN;
    pub const BLOCK_LEN: usize = generic::GHash::BLOCK_LEN;
    pub const TAG_LEN: usize = generic::GHash::TAG_LEN;

    pub fn new(h: &[u8; Self::BLOCK_LEN]) -> Self {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if std::is_x86_feature_detected!("sse2") && std::is_x86_feature_detected!("pclmulqdq") {
            return GHash::Platform(platform::GHash::new(h));
        }

        #[cfg(target_arch = "aarch64")]
        if std::is_aarch64_feature_detected!("pmull") {
            return GHash::Platform(platform::GHash::new(h));
        }

        GHash::Generic(generic::GHash::new(h))
    }

    pub fn update(&mut self, m: &[u8]) {
        match *self {
            GHash::Generic(ref mut g) => g.update(m),
            GHash::Platform(ref mut g) => g.update(m),
        }
    }

    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        match self {
            GHash::Generic(g) => g.finalize(),
            GHash::Platform(g) => g.finalize(),
        }
    }
}
