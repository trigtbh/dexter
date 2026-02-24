use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("failed to read stdin");
    let input = input.trim();

    match url_decode(input) {
        Ok(decoded) => {
            // Try double-decode to catch double-encoded inputs
            if let Ok(double) = url_decode(&decoded) {
                if double != decoded {
                    println!("Single decode: {}", decoded);
                    print!("Double decode: {}", double);
                    return;
                }
            }
            print!("{}", decoded);
        }
        Err(e) => {
            eprintln!("URL decode failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn url_decode(input: &str) -> Result<String, String> {
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &input[i+1..i+3];
            match u8::from_str_radix(hex, 16) {
                Ok(b) => { out.push(b); i += 3; }
                Err(_) => { out.push(bytes[i]); i += 1; }
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|e| e.to_string())
}
