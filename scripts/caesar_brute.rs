use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("failed to read stdin");
    let input = input.trim();

    let mut scored: Vec<(f64, usize, String)> = (1..26)
        .map(|shift| {
            let decrypted = caesar_shift(input, shift);
            let score = english_score(&decrypted);
            (score, shift, decrypted)
        })
        .collect();

    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());

    println!("=== Top candidates (by English frequency score) ===\n");
    for (score, shift, text) in scored.iter().take(5) {
        println!("Shift {:2} (score {:.2}): {}", shift, score, text);
    }

    println!("\n=== All shifts ===");
    for shift in 1..26usize {
        println!("Shift {:2}: {}", shift, caesar_shift(input, shift));
    }
}

fn caesar_shift(text: &str, shift: usize) -> String {
    text.chars().map(|c| {
        if c.is_ascii_uppercase() {
            (b'A' + (c as u8 - b'A' + shift as u8) % 26) as char
        } else if c.is_ascii_lowercase() {
            (b'a' + (c as u8 - b'a' + shift as u8) % 26) as char
        } else {
            c
        }
    }).collect()
}

fn english_score(text: &str) -> f64 {
    let freq = [
        ('e', 12.7), ('t', 9.1), ('a', 8.2), ('o', 7.5), ('i', 7.0),
        ('n', 6.7), ('s', 6.3), ('h', 6.1), ('r', 6.0), ('d', 4.3),
        ('l', 4.0), ('c', 2.8), ('u', 2.8), ('m', 2.4), ('w', 2.4),
        ('f', 2.2), ('g', 2.0), ('y', 2.0), ('p', 1.9), ('b', 1.5),
        ('v', 1.0), ('k', 0.8), ('j', 0.2), ('x', 0.2), ('q', 0.1), ('z', 0.1),
    ];
    let total = text.chars().filter(|c| c.is_alphabetic()).count();
    if total == 0 { return 0.0; }
    let score: f64 = text.chars()
        .filter_map(|c| freq.iter().find(|(l, _)| *l == c.to_ascii_lowercase()).map(|(_, s)| s))
        .sum();
    score / total as f64
}
