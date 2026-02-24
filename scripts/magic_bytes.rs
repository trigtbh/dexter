use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("failed to read stdin");

    let cleaned: String = input.trim()
        .replace("0x", "")
        .replace(" ", "")
        .replace(":", "")
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if cleaned.is_empty() {
        eprintln!("No hex input provided");
        std::process::exit(1);
    }

    let signatures: &[(&str, &str)] = &[
        ("ffd8ff",           "JPEG image"),
        ("89504e47",         "PNG image"),
        ("47494638",         "GIF image"),
        ("25504446",         "PDF document"),
        ("504b0304",         "ZIP archive (or .docx / .xlsx / .jar)"),
        ("504b0506",         "ZIP archive (empty)"),
        ("52617221",         "RAR archive"),
        ("377abcaf271c",     "7-Zip archive"),
        ("1f8b",             "Gzip compressed"),
        ("425a68",           "Bzip2 compressed"),
        ("fd377a585a00",     "XZ compressed"),
        ("7f454c46",         "ELF executable (Linux)"),
        ("4d5a",             "PE executable (Windows .exe / .dll)"),
        ("cafebabe",         "Java class file or Mach-O fat binary"),
        ("feedface",         "Mach-O 32-bit binary"),
        ("feedfacf",         "Mach-O 64-bit binary"),
        ("49443303",         "MP3 audio (ID3v2.3)"),
        ("49443304",         "MP3 audio (ID3v2.4)"),
        ("fffb",             "MP3 audio (no ID3)"),
        ("664c6143",         "FLAC audio"),
        ("4f676753",         "OGG container"),
        ("52494646",         "RIFF container (WAV / AVI)"),
        ("1a45dfa3",         "Matroska / WebM video"),
        ("d0cf11e0a1b11ae1", "Microsoft OLE2 / Office 97-2003 (.doc / .xls / .ppt)"),
        ("efbbbf",           "UTF-8 BOM"),
        ("fffe",             "UTF-16 LE BOM"),
        ("feff",             "UTF-16 BE BOM"),
        ("38425053",         "Photoshop PSD"),
        ("53514c69746520666f726d6174203300", "SQLite 3 database"),
        ("d4c3b2a1",         "pcap capture (little-endian)"),
        ("a1b2c3d4",         "pcap capture (big-endian)"),
        ("0a0d0d0a",         "pcapng capture"),
        ("4c000000",         "Windows shortcut (.lnk)"),
    ];

    let mut matched = false;
    for (sig, desc) in signatures {
        if cleaned.starts_with(sig) {
            println!("✓  {}  (magic: {})", desc, sig);
            matched = true;
        }
    }

    if !matched {
        let preview: String = (0..cleaned.len().min(32))
            .step_by(2)
            .map(|i| format!("{} ", &cleaned[i..i+2]))
            .collect();
        println!("No known signature matched.");
        println!("\nFirst bytes: {}", preview.trim());
        println!("\nTip: paste the very start of the file as hex.");
    }
}
