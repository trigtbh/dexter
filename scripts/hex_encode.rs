use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("failed to read stdin");
    let hex: String = input.bytes().map(|b| format!("{:02x}", b)).collect();
    print!("{}", hex);
}
