use std::env;
use std::io::{self, Read};
use std::path::Path;
use std::process::Command;

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("failed to read stdin");
    let input = input.trim();

    // Resolve path — if not absolute, look in /workspace
    let path = if Path::new(input).is_absolute() {
        input.to_string()
    } else {
        format!("/workspace/{}", input)
    };

    if !Path::new(&path).exists() {
        eprintln!("File not found: {}\nDrop your file into the ./workspace/ folder first.", path);
        std::process::exit(1);
    }

    let ext = Path::new(&path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if !["png", "bmp", "tiff", "tif"].contains(&ext.as_str()) {
        eprintln!("zsteg supports PNG / BMP / TIFF only. Got: .{}", ext);
        std::process::exit(1);
    }

    let output = Command::new("zsteg")
        .args(["-a", &path])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            let combined = format!("{}{}", stdout, stderr).trim().to_string();
            if combined.is_empty() {
                println!("zsteg found nothing. Try steghide or manual bit-plane analysis.");
            } else {
                print!("{}", combined);
            }
        }
        Err(e) => {
            eprintln!("Failed to run zsteg: {}\nMake sure the Docker image is up to date.", e);
            std::process::exit(1);
        }
    }
}
