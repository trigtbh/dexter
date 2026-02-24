use std::env;
use std::io::{self, Read};

fn rot13_char(c: char) -> char {
    match c {
        'a'..='m' | 'A'..='M' => ((c as u8) + 13) as char,
        'n'..='z' | 'N'..='Z' => ((c as u8) - 13) as char,
        _ => c,
    }
}

fn rot13(s: &str) -> String {
    s.chars().map(rot13_char).collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let input = if args.len() > 1 {
        args[1..].join(" ")
    } else {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).expect("failed to read stdin");
        buf
    };

    let out = rot13(&input);
    print!("{}", out);
}
