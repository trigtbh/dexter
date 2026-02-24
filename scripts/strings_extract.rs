use std::io::{self, Read};

const MIN_LEN: usize = 4;

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("failed to read stdin");
    let input = input.trim();

    // If it looks like a hex dump, decode it first
    let cleaned: String = input.replace("0x", "").chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let raw: Vec<u8> = if cleaned.len() > 8 && cleaned.len() % 2 == 0 && cleaned.len() == input.replace(' ', "").replace("0x", "").len() {
        (0..cleaned.len()).step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i+2], 16).unwrap_or(0))
            .collect()
    } else {
        input.as_bytes().to_vec()
    };

    let mut found: Vec<String> = Vec::new();
    let mut current: Vec<u8> = Vec::new();

    for &byte in &raw {
        if byte >= 0x20 && byte < 0x7f {
            current.push(byte);
        } else {
            if current.len() >= MIN_LEN {
                found.push(String::from_utf8_lossy(&current).to_string());
            }
            current.clear();
        }
    }
    if current.len() >= MIN_LEN {
        found.push(String::from_utf8_lossy(&current).to_string());
    }

    if found.is_empty() {
        println!("No printable strings found (minimum length {})", MIN_LEN);
    } else {
        println!("Found {} strings:\n", found.len());
        for s in &found {
            println!("{}", s);
        }
    }
}
