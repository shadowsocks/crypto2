
use crypto2::encoding::percent;


fn main() {
    println!("{:?}", percent::encode("abc==\x7f") );
    println!("{:?}", percent::decode(percent::encode("abc==\x7f")) );
}