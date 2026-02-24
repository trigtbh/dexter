use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("failed to read stdin");

    let cleaned: String = input.trim()
        .replace("0x", "")
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if cleaned.len() % 2 != 0 {
        eprintln!("Odd-length hex string");
        std::process::exit(1);
    }

    let data: Vec<u8> = (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i+2], 16).unwrap())
        .collect();

    let mut scored: Vec<(f64, u8, String)> = (0u8..=255)
        .filter_map(|key| {
            let decrypted: Vec<u8> = data.iter().map(|b| b ^ key).collect();
            let text = String::from_utf8_lossy(&decrypted).to_string();
            let score = english_score(&text);
            if score > 0.0 { Some((score, key, text)) } else { None }
        })
        .collect();

    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());

    println!("=== Top single-byte XOR candidates ===\n");
    for (score, key, text) in scored.iter().take(10) {
        let preview: String = text.chars().take(120).collect();
        println!("Key 0x{:02x} ({:3}) score {:.2}: {}", key, key, score, preview);
    }
}

fn english_score(text: &str) -> f64 {
    let freq = [
        ('e', 12.7f64), ('t', 9.1), ('a', 8.2), ('o', 7.5), ('i', 7.0),
        ('n', 6.7), ('s', 6.3), ('h', 6.1), ('r', 6.0), ('d', 4.3),
        ('l', 4.0), ('c', 2.8), ('u', 2.8), ('m', 2.4), ('w', 2.4),
        ('f', 2.2), ('g', 2.0), ('y', 2.0), ('p', 1.9), ('b', 1.5),
        ('v', 1.0), ('k', 0.8), ('j', 0.2), ('x', 0.2), ('q', 0.1), ('z', 0.1),
    ];
    // Penalise non-printable bytes heavily
    if text.bytes().any(|b| b < 32 && b != b'\n' && b != b'\r' && b != b'\t') {
        return 0.0;
    }
    let total = text.chars().filter(|c| c.is_alphabetic()).count();
    if total == 0 { return 0.0; }
    text.chars()
        .filter_map(|c| freq.iter().find(|(l, _)| *l == c.to_ascii_lowercase()).map(|(_, s)| *s))
        .sum::<f64>() / total as f64
}
