use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("failed to read stdin");

    // Strip common separators and prefixes
    let cleaned: String = input
        .trim()
        .replace("0x", "")
        .replace("0X", "")
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if cleaned.len() % 2 != 0 {
        eprintln!("Hex string has odd length — maybe a leading 0 is missing?");
        std::process::exit(1);
    }

    let bytes: Result<Vec<u8>, _> = (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i+2], 16))
        .collect();

    match bytes {
        Ok(b) => match String::from_utf8(b.clone()) {
            Ok(s) => print!("{}", s),
            Err(_) => {
                let printable: String = b.iter()
                    .map(|&byte| if byte >= 32 && byte < 127 { byte as char } else { '.' })
                    .collect();
                println!("(non-UTF8 output — printable chars)");
                print!("{}", printable);
            }
        },
        Err(e) => {
            eprintln!("Invalid hex: {}", e);
            std::process::exit(1);
        }
    }
}
