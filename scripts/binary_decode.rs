use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("failed to read stdin");

    let groups: Vec<&str> = input.split_whitespace().collect();
    let mut result = String::new();

    for group in &groups {
        if group.len() != 8 || !group.chars().all(|c| c == '0' || c == '1') {
            eprintln!("Invalid binary group: '{}' — expected 8 bits of 0s and 1s", group);
            std::process::exit(1);
        }
        let byte = u8::from_str_radix(group, 2).unwrap();
        result.push(byte as char);
    }

    print!("{}", result);
}
