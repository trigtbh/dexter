use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("failed to read stdin");
    let input = input.trim().replace([' ', '\n', '\r'], "");

    // Add padding if needed
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };

    match base64_decode(&padded) {
        Ok(bytes) => match String::from_utf8(bytes.clone()) {
            Ok(s) => print!("{}", s),
            Err(_) => print!("{}", hex_encode(&bytes)),
        },
        Err(e) => {
            eprintln!("Base64 decode failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [0u8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        table[c as usize] = i as u8;
    }

    let input = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 < input.len() {
        if input[i] == b'=' { break; }
        let a = table[input[i] as usize] as u32;
        let b = table[input[i+1] as usize] as u32;
        let c = if input[i+2] == b'=' { 0 } else { table[input[i+2] as usize] as u32 };
        let d = if i+3 >= input.len() || input[i+3] == b'=' { 0 } else { table[input[i+3] as usize] as u32 };

        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((triple >> 16) & 0xFF) as u8);
        if input[i+2] != b'=' { out.push(((triple >> 8) & 0xFF) as u8); }
        if i+3 < input.len() && input[i+3] != b'=' { out.push((triple & 0xFF) as u8); }
        i += 4;
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
