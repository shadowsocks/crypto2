pub mod test {
    use rand::{thread_rng, Rng, RngCore};
    use super::super::{md2::Md2, md4::Md4, md5::Md5, sha1::Sha1, sm3::Sm3};
    use crate::hash::{Sha256, Sha512};

    macro_rules! random_split_test {
    ($x:ident) => {
        for stream_size in 2..1024 {
            let mut buffer = vec![0u8; stream_size];
            thread_rng().fill_bytes(&mut buffer);

            let h1 = $x::oneshot(&buffer);

            let break_size = thread_rng().gen_range(1..stream_size);
            let left = &buffer[..break_size];
            let right = &buffer[break_size..];

            let mut ctx = $x::new();
            ctx.update(left);
            ctx.update(right);
            let h2 = ctx.finalize();

            debug_assert_eq!(
                h1,
                h2,
                "expect same result when a stream with size {:} is broken into {:} and {:}",
                stream_size,
                break_size,
                stream_size - break_size
            );
        }
    };
}

    #[test]
    fn random_split_test_md2() {
        random_split_test!(Md2);
    }

    #[test]
    fn random_split_test_md4() {
        random_split_test!(Md4);
    }

    #[test]
    fn random_split_test_md5() {
        random_split_test!(Md5);
    }

    #[test]
    fn random_split_test_sha1() {
        random_split_test!(Sha1);
    }

    #[test]
    fn random_split_test_sm3() {
        random_split_test!(Sm3);
    }

    #[test]
    fn random_split_test_sha256() {
        random_split_test!(Sha256);
    }

    #[test]
    fn random_split_test_sha512() {
        random_split_test!(Sha512);
    }
}
