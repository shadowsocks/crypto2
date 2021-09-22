use super::generic;
use super::platform;

pub enum Polyval {
    Generic(generic::Polyval),
    Platform(platform::Polyval),
}

impl Polyval {
    pub const KEY_LEN: usize = generic::Polyval::KEY_LEN;
    pub const BLOCK_LEN: usize = generic::Polyval::BLOCK_LEN;
    pub const TAG_LEN: usize = generic::Polyval::TAG_LEN;

    pub fn new(k: &[u8]) -> Self {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if std::is_x86_feature_detected!("sse2") && std::is_x86_feature_detected!("pclmulqdq") {
            return Polyval::Platform(platform::Polyval::new(k));
        }

        #[cfg(target_arch = "aarch64")]
        if std::is_aarch64_feature_detected!("pmull") {
            return Polyval::Platform(platform::Polyval::new(k));
        }

        Polyval::Generic(generic::Polyval::new(k))
    }

    pub fn update(&mut self, m: &[u8]) {
        match *self {
            Polyval::Generic(ref mut g) => g.update(m),
            Polyval::Platform(ref mut g) => g.update(m),
        }
    }

    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        match self {
            Polyval::Generic(g) => g.finalize(),
            Polyval::Platform(g) => g.finalize(),
        }
    }
}
