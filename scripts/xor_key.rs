use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("failed to read stdin");
    let input = input.trim();

    // Expected format: <hex_ciphertext>::<hex_key>
    let parts: Vec<&str> = input.splitn(2, "::").collect();
    if parts.len() != 2 {
        eprintln!("Format: <hex ciphertext>::<hex key>  e.g.  1b3a45::2f1a");
        std::process::exit(1);
    }

    let ct_hex: String = parts[0].trim().replace("0x", "").chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let key_hex: String = parts[1].trim().replace("0x", "").chars().filter(|c| c.is_ascii_hexdigit()).collect();

    if ct_hex.len() % 2 != 0 {
        eprintln!("Ciphertext hex has odd length");
        std::process::exit(1);
    }
    if key_hex.len() % 2 != 0 {
        eprintln!("Key hex has odd length");
        std::process::exit(1);
    }
    if key_hex.is_empty() {
        eprintln!("Key cannot be empty");
        std::process::exit(1);
    }

    let ct: Vec<u8> = (0..ct_hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&ct_hex[i..i+2], 16).unwrap())
        .collect();
    let key: Vec<u8> = (0..key_hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&key_hex[i..i+2], 16).unwrap())
        .collect();

    let result: Vec<u8> = ct.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect();

    match String::from_utf8(result.clone()) {
        Ok(s) => print!("{}", s),
        Err(_) => print!("{}", result.iter().map(|b| format!("{:02x}", b)).collect::<String>()),
    }
}
