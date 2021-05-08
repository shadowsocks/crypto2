
use crypto2::encoding::percent;
use crypto2::encoding::base64;



fn main() {
    println!("{:?}", percent::encode("abc==\x7f") );
    println!("{:?}", percent::decode(percent::encode("abc==\x7f")) );

    println!("{:?}",  base64::encode("foobar"));
    println!("{:?}",  base64::encode("foob"));

    println!("{:?}", base64::forgiving_decode("Zm9vYg==").map(String::from_utf8) );
}