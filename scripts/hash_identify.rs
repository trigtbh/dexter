use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("failed to read stdin");
    let h = input.trim();

    let is_hex = h.chars().all(|c| c.is_ascii_hexdigit());
    let len = h.len();

    let mut matched = false;

    // Hex-length based
    if is_hex {
        let name = match len {
            8   => Some("CRC32 / Adler-32"),
            16  => Some("MySQL 3.x / half-hash"),
            32  => Some("MD5 / NTLM / MD4"),
            40  => Some("SHA1 / MySQL5 / Git object SHA"),
            48  => Some("Tiger-192 / SHA1(SHA1)"),
            56  => Some("SHA224 / SHA3-224"),
            64  => Some("SHA256 / SHA3-256 / BLAKE2s-256"),
            96  => Some("SHA384 / SHA3-384"),
            128 => Some("SHA512 / SHA3-512 / BLAKE2b-512 / Whirlpool"),
            _   => None,
        };
        if let Some(n) = name {
            println!("✓  {} (hex, {} chars)", n, len);
            matched = true;
        }
    }

    // Prefixed formats
    if h.starts_with("$2a$") || h.starts_with("$2b$") || h.starts_with("$2y$") {
        println!("✓  bcrypt");
        matched = true;
    }
    if h.starts_with("$1$") { println!("✓  MD5-crypt (Linux shadow $1$)"); matched = true; }
    if h.starts_with("$5$") { println!("✓  SHA256-crypt (Linux shadow $5$)"); matched = true; }
    if h.starts_with("$6$") { println!("✓  SHA512-crypt (Linux shadow $6$)"); matched = true; }
    if h.starts_with("$argon2") { println!("✓  Argon2"); matched = true; }
    if h.starts_with("$pbkdf2") { println!("✓  PBKDF2"); matched = true; }
    if h.starts_with('*') && h.len() == 41 && h[1..].chars().all(|c| c.is_ascii_hexdigit()) {
        println!("✓  MySQL 4.1+ (*HASH)");
        matched = true;
    }

    if !matched {
        println!("No known hash format matched.");
        println!("Length: {}  Hex-only: {}", len, is_hex);
        println!("\nTip: make sure you paste just the hash with no extra whitespace.");
    }
}
