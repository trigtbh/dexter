# CTF Swiss Army Knife — Full Feature Specification

> A hybrid CyberChef + Metasploit for CTF competitors. Two top-level modes: **OPS** (entirely client-side, no external interaction) and **RECON** (requires network access to a target). All tools run inside a Docker image; a terminal frontend (TUI) interfaces with the container via a Unix socket or REST API.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [OPS Mode](#ops-mode)
   - [Encoding & Decoding](#encoding--decoding)
   - [Hashing](#hashing)
   - [Hash Cracking](#hash-cracking)
   - [Symmetric Cryptography](#cryptography--symmetric)
   - [Asymmetric Cryptography](#cryptography--asymmetric)
   - [Classical Ciphers](#cryptography--classical-ciphers)
   - [XOR Operations](#xor-operations)
   - [Binary & Bitwise Operations](#binary--bitwise-operations)
   - [Number Theory & Math](#number-theory--math)
   - [Forensics](#forensics)
   - [Reverse Engineering](#reverse-engineering)
   - [Pwn / Exploit Dev](#pwn--exploit-dev)
   - [Web (Client-Side Analysis)](#web-client-side-analysis)
   - [Password & Wordlist Tools](#password--wordlist-tools)
   - [Miscellaneous OPS](#miscellaneous-ops)
3. [RECON Mode](#recon-mode)
   - [Network Scanning](#network-scanning)
   - [DNS](#dns)
   - [HTTP / Web Reconnaissance](#http--web-reconnaissance)
   - [OSINT](#osint)
   - [SSL/TLS](#ssltls)
   - [Active Exploitation Helpers](#active-exploitation-helpers)
   - [Service-Specific Attacks](#service-specific-attacks)
   - [Wireless](#wireless)
   - [Infrastructure & Cloud](#infrastructure--cloud)
   - [Callback / Out-of-Band](#callback--out-of-band)
   - [Proxy & Traffic Manipulation](#proxy--traffic-manipulation)
4. [TUI Frontend Features](#tui-frontend-features)
5. [Docker Tool Inventory](#docker-tool-inventory)

---

## Architecture Overview

The Docker image hosts all tools and exposes a Unix socket or local REST API. The TUI (built in Rust or Go using Ratatui/Bubbletea) sends commands, streams stdout/stderr back in real time, and renders results inline. Two top-level modes — **OPS** and **RECON** — are selectable at launch or via a hotkey.

Key architectural principles:
- **OPS mode** is fully air-gapped. No DNS, no outbound connections. Safe on locked-down networks.
- **RECON mode** has full network access. Includes an embedded callback server for OOB interactions.
- A **pipeline system** allows the output of any tool to be piped directly into the input of another via a visual builder.
- A **workspace/project layer** persists loot, notes, flags, and action history per CTF challenge.

---

## OPS Mode

### Encoding & Decoding

| Feature | Details |
|---|---|
| Base families | Base64, Base32, Base58, Base85, Base91 |
| Hex | Encode/decode with optional byte spacing and endian swap |
| URL encoding | Full, partial, and double-encoding; decode all variants |
| HTML entities | Named and numeric (`&amp;`, `&#38;`, `&#x26;`) encode/decode |
| Numeral systems | Binary, octal, decimal, hex conversions for arbitrary integers |
| ROT variants | ROT-N (all N, 0–25), ROT47 |
| Morse code | Encode/decode, configurable separator |
| NATO phonetic | Alphabet encode/decode |
| Bacon cipher | Standard and modified variants |
| Braille | Grade 1 encode/decode |
| Unicode escapes | `\uXXXX`, `\UXXXXXXXX`, `&#xXXXX;`, `%uXXXX` encode/decode |
| MIME | Quoted-printable encode/decode |
| UUEncode / XXEncode | Full encode/decode |
| Punycode | IDN (internationalized domain name) encode/decode |
| JWT | Decode header/payload, pretty-print claims (no signature verification required) |
| Protobuf | Schema-less best-effort decode, field type guesser |
| ASN.1 / DER | Decode and pretty-print (certificate extensions, OID resolution) |
| Msgpack | Decode to JSON-like display |
| CBOR | Decode to annotated display |

---

### Hashing

**Supported algorithms:**
- MD4, MD5
- SHA1, SHA224, SHA256, SHA384, SHA512
- SHA3-224, SHA3-256, SHA3-384, SHA3-512
- Keccak (non-standard pre-NIST padding: 224/256/384/512)
- BLAKE2b, BLAKE2s, BLAKE3
- RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320
- Whirlpool, Tiger, Streebog (GOST R 34.11-2012)
- CRC8, CRC16, CRC32, CRC64 (all common polynomials selectable)
- Adler-32
- FNV-1 / FNV-1a (32/64/128-bit)
- MurmurHash2 / MurmurHash3
- xxHash (32/64/128-bit)
- Poly1305 MAC
- HMAC wrappers for all above
- NTLM, LM hash generation
- MySQL 4.1+ (`*HASH`), PostgreSQL MD5 (`md5` + user prefix), crypt(3) variants (`$1$`, `$5$`, `$6$`)
- PBKDF2, scrypt, bcrypt, Argon2i/d/id (test hash generation)

**Additional features:**
- Hash identification (hashid / haiti integration — returns ranked list of likely algorithms)
- Hash comparison and equality check (constant-time)
- Batch hash (hash a file per line, hash a list of files)
- Hash of hash (iterated hashing, configurable rounds)

---

### Hash Cracking

**Attack modes:**
- **Dictionary attack** — wordlist selector (bundled: rockyou, darkweb21m, SecLists; custom upload)
- **Rule-based attack** — hashcat rule selector (d3ad0ne, best64, OneRuleToRuleThemAll, dive, custom)
- **Brute-force** — charset builder (lower, upper, digits, symbols, custom) + min/max length
- **Mask attack** — hashcat-style masks (`?l`, `?u`, `?d`, `?s`, `?a`, custom sets)
- **Combinator attack** — two wordlists combined with optional separator
- **Prince attack** — PACK/PRINCE integration
- **Markov chain attack** — stat file selection, threshold
- **Toggle-case and leet-speak mutation** — applied as pre-processing pass
- **Hybrid attack** — wordlist + mask append/prepend

**Backends:** hashcat (GPU-accelerated), john (CPU fallback). Auto-detects hash type and suggests correct mode/format.

**UI features:**
- Real-time progress bar with speed (H/s, kH/s, MH/s, GH/s), ETA, and found count
- Live cracked hash panel with plaintext reveal
- Session save/restore (resume interrupted crack)
- GPU vs CPU toggle; OpenCL / CUDA device selector

---

### Cryptography — Symmetric

**Ciphers and modes:**

| Cipher | Modes Supported |
|---|---|
| AES | ECB, CBC, CFB, OFB, CTR, GCM, CCM, SIV, XTS |
| DES / 3DES | ECB, CBC, CFB, OFB |
| Blowfish, Twofish, Threefish | ECB, CBC, CTR |
| Camellia, CAST-128/256 | ECB, CBC, CTR |
| ChaCha20, XChaCha20 | Stream (nonce + counter) |
| Salsa20 | Stream |
| RC2, RC4, RC5, RC6 | As applicable |
| IDEA, SEED, Aria | ECB, CBC |
| GOST 28147-89 | ECB, CFB |

**Analysis and attack tools:**
- AES key schedule viewer (expanded round keys displayed)
- IV/nonce manipulation workbench
- ECB block detection — identical block highlighter on ciphertext input
- **Padding oracle attack assistant** — semi-automated; tracks block queries, suggests next byte, visualizes progress
- **Bit-flipping attack workbench (CBC)** — target byte selector, XOR delta calculator, auto-applies to ciphertext
- Key wrap/unwrap (AES-KW, RFC 3394)
- Automatic input format detection: hex, base64, raw binary

---

### Cryptography — Asymmetric

**RSA:**
- Key generation (512–8192 bits), PKCS#1 and PKCS#8 output
- Encrypt/decrypt: PKCS#1 v1.5, OAEP (SHA-1, SHA-256 MGF)
- Sign/verify: PKCS#1 v1.5, PSS

**RSA attack toolkit** (all via SageMath/Python subprocess):

| Attack | Condition |
|---|---|
| Fermat factorization | p and q are close together |
| Wiener attack | Small private exponent (d < N^0.25) |
| Hastad broadcast attack | Small e, same message encrypted with multiple keys |
| Common modulus attack | Same message, different keys, same modulus |
| Franklin-Reiter related message attack | Two related plaintexts, same key |
| Boneh-Durfee attack | Weak private exponent (extended Wiener) |
| ROCA vulnerability check | Infineon key fingerprint detection |
| Coppersmith's theorem | Small message / partial key recovery |
| Pollard p-1 | Smooth p-1 |
| Pollard p+1 | Smooth p+1 |
| ECM factorization | General purpose via sympy/PARI |
| Batch GCD | Weak key detection across multiple moduli |

**DSA / ECDSA:**
- Nonce reuse attack (k-reuse → private key recovery)
- Weak nonce detection (bias analysis across signature set)
- Key recovery from repeated nonce (lattice-based)

**ECC:**
- Curve parameter display and validation (named curves + custom Weierstrass/Montgomery/Edwards)
- Point addition / scalar multiplication interactive workbench
- Invalid curve attack assistant
- MOV attack check (embedding degree analysis)
- ECDLP brute-force (small-order curves)
- Pohlig-Hellman for smooth-order groups

**Other:**
- ElGamal encrypt/decrypt/attack helpers
- Diffie-Hellman and ECDH key exchange simulator (step-by-step)
- PEM / DER / PFX / JWK format conversion (bidirectional)
- x509 certificate inspector (all extensions, SANs, key usage, EKU, CT poison)
- Certificate chain validator
- Private key extraction from PEM bundles
- OpenSSH key format conversion (OpenSSH ↔ PEM ↔ PPK)

---

### Cryptography — Classical Ciphers

**Substitution ciphers:**
Caesar, Vigenère, Beaufort, Affine, Atbash, Playfair, Polybius square, Porta, Gronsfeld, Autokey, Running Key, Trithemius

**Transposition ciphers:**
Rail Fence, Columnar transposition, Route cipher, Scytale

**Machine ciphers:**
- Enigma machine simulator (all historical rotors I–VIII, reflectors A/B/C, plugboard, Uhr box)
- Lorenz/Tunny (basic implementation)

**Polygraphic:**
- Hill cipher (2×2 and 3×3 matrix, mod 26 key input, inverse key calculator)
- ADFGVX / ADFGX

**Attack tools:**
- Index of Coincidence calculator
- Friedman test (Vigenère key length estimator)
- Kasiski examination (key length from repeated trigrams)
- Chi-squared fitness scorer (against multiple languages)
- Automated substitution cipher solver (simulated annealing + bigram/trigram scoring)
- Drag-and-drop letter assignment interface for manual solving
- One-Time Pad XOR workbench with known-plaintext assist

---

### XOR Operations

- Single-byte XOR brute-force with English scoring (IC, bigram frequency, ETAOIN model)
- Multi-byte XOR — key length guesser (normalized Hamming distance + Kasiski), then per-column single-byte solve
- XOR two hex strings / byte arrays
- XOR file against repeating key
- Visual XOR diff (byte-level side-by-side highlighting)
- XOR key recovery given plaintext + ciphertext
- Many-time-pad analyzer (multiple ciphertexts XOR'd together with visual alignment tool)

---

### Binary & Bitwise Operations

- Bitwise AND, OR, XOR, NOT between two arbitrary-length inputs
- Bit rotation left/right (configurable width: 8/16/32/64/custom)
- Byte reversal / endian swap (16/32/64-bit, full buffer)
- Bit extraction / bit-field slicer (offset + length)
- Integer overflow / underflow simulator (signed/unsigned, width selector, wrap vs trap)
- Two's complement / one's complement / sign-magnitude display with conversion
- IEEE 754 floating point inspector (single/double, hex ↔ float, NaN/Inf/denormal highlighting)
- Popcount, parity, count trailing zeros, count leading zeros
- Gray code encode/decode
- Hamming distance calculator

---

### Number Theory & Math

- Modular arithmetic: mod, modpow, modinv, gcd, lcm, extended Euclidean algorithm
- Primality test: Miller-Rabin (configurable rounds), trial division, BPSW
- Integer factorization: trial, Pollard rho, Pollard p-1, ECM (via sympy / PARI / SageMath)
- CRT (Chinese Remainder Theorem) solver (arbitrary number of congruences)
- Discrete logarithm: baby-step giant-step, Pohlig-Hellman (smooth order groups)
- Jacobi / Legendre symbol calculator
- Quadratic residue checker and square root finder (Tonelli-Shanks)
- Lattice reduction (LLL algorithm via SageMath)
- Polynomial arithmetic over GF(2^n) and GF(p)
- Matrix operations over finite fields (det, inv, row reduce)

**PRNG analysis:**
- PHP `mt_rand` state predictor (from observed outputs)
- Java `Random` state recovery
- Python `random` (Mersenne Twister state reconstruction from 624 consecutive 32-bit outputs)
- LFSR analyzer (polynomial recovery from output stream)

---

### Forensics

#### File Analysis
- File signature identification (magic bytes, 500+ types via `file` / libmagic)
- Embedded hex editor with: jump to offset, byte search, bookmarks, struct annotations, compare two files
- String extraction: ASCII, UTF-8, UTF-16LE/BE, configurable minimum length, regex filter
- Metadata extraction (exiftool — EXIF, XMP, IPTC, ICC, PDF metadata, Office document properties)
- Shannon entropy calculator with per-block visual entropy heatmap
- File carving: foremost / scalpel integration with carve type selector

#### Steganography
**Images:**
- LSB analysis (PNG, BMP, GIF, TIFF) — visual bit-plane viewer (bits 0–7, per channel)
- LSB extraction with row/column/channel order selector
- LSB injection with custom payload
- zsteg (automated multi-channel PNG/BMP analysis)
- steghide embed/extract (passphrase brute-force via stegseek + wordlist)
- OpenStego embed/extract
- Chi-squared randomness test (detect LSB modification)
- DCT coefficient analysis for JPEG (detect JSteg / F5 / OutGuess)
- Color plane viewer (R, G, B, A isolated display)
- StegSolve-style filter suite (invert, enhance, XOR channels, combine planes)
- Pixel diff between two images (highlight changed pixels)
- Image histogram viewer

**Audio:**
- Spectrogram viewer (FFT-based, linear/log frequency scale)
- LSB extraction from WAV samples
- MP3Stego detection and extract
- DeepSound extract
- Phase coding detection

**Video:**
- Frame extractor (ffmpeg wrapper)
- Per-frame steg analysis pipeline

**Documents:**
- Zero-width character detection and extraction (ZWSP, ZWJ, ZWNJ, U+200B–200F, etc.)
- Whitespace steganography detection (trailing spaces, tab/space encoding)
- Homoglyph substitution detection (Cyrillic/Latin lookalike swap)
- Font steganography detection (minor glyph variation patterns)

#### Archives
- Encrypted ZIP brute-force (fcrackzip / john / hashcat)
- Known-plaintext ZIP attack (pkcrack)
- ZIP comment extraction
- Hidden file detection in archives (extra bytes after EOCD, etc.)
- Archive-in-archive / polyglot file detection
- RAR / 7z / tar.gz / bzip2 password brute-force

#### PDF Analysis
- PDF object tree browser (pdfid / pdf-parser integration)
- Embedded file and stream extraction
- JavaScript extraction and deobfuscation
- Hidden text / invisible layer detection
- Incremental update and shadow attack analysis

#### PCAP Analysis
- Packet summary / flow reconstruction (tshark / scapy)
- HTTP stream extraction (credentials, uploaded files, cookies, auth headers)
- DNS query/response log
- Credential harvesting (FTP, HTTP Basic/Digest, Telnet, SMTP AUTH, POP3, IMAP)
- TLS decryption (given SSLKEYLOGFILE or session keys)
- USB HID packet decode (keyboard input reconstruction, mouse trajectory)
- Bluetooth HCI packet decode
- ICMP covert channel detection
- File reassembly from TCP streams

#### Memory Forensics (Volatility 2 & 3)
- Profile / OS auto-detection
- Process list, process tree, DLL list, handle list
- Network connections (netstat, netscan)
- Registry hive dump and query
- Clipboard contents
- Browser history and credential extraction
- AES key scanning (AESKeyFinder), bulk_extractor integration
- Shellcode detection and extraction (malfind)
- Dump specific process memory (procdump, memdump)
- Loaded kernel modules list

#### Disk Image Analysis (The Sleuth Kit)
- Partition table viewer (MBR, GPT, APM)
- File system walk: NTFS, FAT12/16/32/exFAT, ext2/3/4, HFS+, APFS, UFS
- Deleted file recovery
- MFT / $MFT parser (NTFS metadata, timestamps, attribute list)
- NTFS Alternate Data Stream detection and extraction
- Slack space analysis
- Timeline generation (mactime format, visual)
- Inode / block inspection

---

### Reverse Engineering

**Disassembly & Decompilation:**
- Ghidra headless (decompile functions, P-Code display, symbol rename)
- radare2 (full integration: disassemble, analyze, patch, ESIL emulation)
- RetDec (standalone decompiler for x86/x64/ARM/MIPS/PPC)
- jadx (Android APK / DEX decompiler with GUI tunnel)
- Capstone disassembly engine (direct; all architectures)

**Binary Formats:**
- **ELF:** headers, section headers, program headers, symbol table (.symtab/.dynsym), dynamic segment, GOT/PLT, DWARF debug info, TLS
- **PE:** DOS/NT headers, sections, import/export tables, resources (icon, manifest, version info, strings), Rich header, debug directory; flag display: ASLR, NX/DEP, SafeSEH, CFG, Authenticode
- **Mach-O:** load commands, segments/sections, imports, code signature, fat binary slices
- **.NET:** dnSpy CLI / ILSpy CLI decompile; assembly manifest, resource extraction
- **Python bytecode:** uncompyle6 / decompile3; `.pyc` header parser (magic → Python version)
- **Java `.class`:** javap disassembly; constant pool inspector
- **WebAssembly:** wasm2wat, wabt validation, wasm-decompile

**Android / iOS:**
- APK: jadx decompile, AndroidManifest parse, smali view, certificate extract, intent/permission analysis, resource decode (aapt2)
- IPA: class-dump, binary analysis, entitlements extract

**Anti-Analysis Detection:**
- Packer detection (DetectItEasy / die CLI)
- VM check pattern scanner (CPUID, RDTSC, VMware I/O ports, registry keys)
- Anti-debug pattern scanner (IsDebuggerPresent, NtQueryInformationProcess, timing checks)
- Obfuscation type guesser

**Dynamic Analysis:**
- strace / ltrace wrapper with call filter
- Frida script injection (hook by function name, address, or export)
- Unicorn Engine emulator (inline shellcode / snippet emulation, register/memory state display)
- GDB launcher with auto-load of GEF or PWNDBG config

**Patching:**
- Hex patch by offset
- NOP sled insertion (x86/x64/ARM)
- Byte search and replace across binary
- Patch and re-sign (Mach-O ad-hoc, PE checksum recalculation)

**Other:**
- Binary diff (radiff2 / BinDiff integration)
- String xref finder
- Function call graph (dot/graphviz export)
- Symbol recovery (rizzo-style FLIRT sig matching, stripped binary function classifier)

---

### Pwn / Exploit Dev

- **pwntools** interactive Python shell with pre-loaded context, ELF, ROP, cyclic, asm/disasm
- **checksec** — display all binary mitigations (NX, ASLR, PIE, Full/Partial RELRO, stack canary, Fortify, RUNPATH)
- Cyclic De Bruijn pattern generator and offset finder (pwntools `cyclic` / `cyclic_find`)
- Stack frame visualizer (argument layout, saved registers, return address position)

**Shellcode library:** x86, x86-64, ARM (32/64), MIPS, PowerPC — categories: exec shell, read flag (arbitrary path), staged loader, reverse shell, bind shell, `execve` with arbitrary args, `mprotect` + second stage

**Shellcode encoders:**
- Bad-byte avoider (configurable avoid list)
- Alphanumeric encoder (x86-64)
- Printable shellcode encoder
- Polymorphic encoder

**Exploit building:**
- Format string payload builder: offset finder (via automated test input), arbitrary read (%n$s), arbitrary write (%n$n), GOT overwrite calculator, stack/libc address leak parser
- Return-to-libc / ROP chain builder (given libc base + gadget list)
- FSOP (FILE structure oriented programming) payload builder (vtable overwrite, `_IO_str_overflow`)
- SROP (Sigreturn-Oriented Programming) frame builder

**Heap exploitation templates** (annotated Python scaffolding):
- fastbin dup (pre-2.27)
- tcache poisoning (2.27+)
- unsorted bin attack
- House of Force
- House of Orange
- House of Einherjar
- Largebin attack

**Gadget finding:**
- ROPgadget (all gadgets, JOP, COP, quality filter)
- Ropper (stack pivot, syscall gadgets, register control chains)
- one_gadget (magic one-gadget exec finder)

**libc tools:**
- libc-database: version identification from leaked function addresses
- ASLR entropy calculator (by OS/arch)

**GDB wrapper:**
- Auto-attach to process by name or PID
- GEF / PWNDBG pre-configured (heap visualization, canary display, vmmap, search, telescope)
- Breakpoint manager UI
- Memory snapshot diff

**Templates:**
- Remote exploit scaffold generator (pwntools boilerplate: connect, send, recv, interactive)
- Local exploit scaffold (subprocess, pty)
- Kernel exploit scaffold (modprobe_path, seq_operations, tty_struct, FUSE templates)

---

### Web (Client-Side Analysis)

**JWT toolkit:**
- Decode header + payload (no key required)
- Forge with `alg: none` (strip signature)
- Algorithm confusion attack (RS256 → HS256 with public key as HMAC secret)
- Secret brute-force (dictionary attack against HMAC-signed JWTs)
- Key ID (`kid`) injection payload builder
- `jwk` header injection (embed attacker's public key)
- Token expiry manipulation

**Session/cookie decoders:**
- Flask signed session (decode, forge with known secret)
- Django signed cookies
- Rails `secret_key_base` signed/encrypted session decode and forge
- Express `cookie-session` / `cookie-parser` signed cookie
- URL-encoded / base64 cookie display
- Rack session decoder

**Serialization attack payloads:**
- Java: ysoserial gadget chain selector (CommonsCollections 1–7, Spring, Hibernate, etc.) → base64/hex output
- PHP: phpggc gadget chain selector (Laravel, Symfony, Monolog, etc.)
- Python pickle: arbitrary RCE payload generator
- Ruby Marshal: gadget chain generator
- .NET: ysoserial.net (LosFormatter, BinaryFormatter, TypeConfuseDelegate)
- Node.js: `node-serialize` / `serialize-javascript` gadget

**Hash length extension:** sha1, sha256, md5 (hlextend integration) — append arbitrary data and produce valid MAC

**Other web tools:**
- SAML assertion decoder and forge (XML signature wrapping attack builder)
- OAuth flow analyzer (state param check, PKCE verifier, implicit flow risks)
- GraphQL introspection query generator and schema visualizer
- CORS misconfiguration tester (request builder with Origin variations)
- CSP analyzer and bypass suggester (unsafe-inline paths, JSONP endpoints, Angular/Vue gadgets)
- SSRF payload generator (cloud metadata, internal ranges, URL bypass techniques: IPv6, decimal, octal, URL encoding, `0.0.0.0`, Rebind DNS)
- XXE payload generator (file read, SSRF, blind OOB via DNS/HTTP, parameter entity, UTF-16/UTF-7 encoding bypass)
- SSTI payload wordlist with template engine auto-detection heuristics (Jinja2, Twig, Freemarker, Velocity, Mako, Pebble, Smarty, Handlebars)
- Request/response diff tool (headers + body, word-level)
- WebSocket frame encoder/decoder
- Prototype pollution payload generator (constructor chain, `__proto__`, `Object.prototype`)
- HTTP request smuggler (CL.TE / TE.CL / H2 desync payload builder)

---

### Password & Wordlist Tools

- **CUPP** — personal info-based wordlist generator (name, DOB, pet, company, keywords)
- **Crunch** — pattern-based wordlist generator (min/max length, charset, custom patterns)
- **Mentalist** — rule-based wordlist builder (base words + transformations)
- **PRINCE** — PCFG-style wordlist from base words
- Rule application: apply hashcat / john rules offline to any wordlist
- Password strength analyzer (entropy, pattern matching, crack-time estimator)
- Common password pattern highlighter (keyboard walks, dates, l33t speak)
- Wordlist statistics: entropy distribution, length histogram, charset distribution
- Wordlist operations: merge, sort, dedup, filter by length / charset / regex
- Mask generator from known partial pattern (e.g., `Pass????!` → `Pass?l?l?l?l!`)

---

### Miscellaneous OPS

- **QR code:** encode (with error correction level selector), decode, damaged QR repair (Reed-Solomon assisted)
- **Barcodes:** decode all major symbologies (EAN, UPC, Code128, Code39, ITF, QR, DataMatrix, Aztec, PDF417)
- **Color codes:** HEX ↔ RGB ↔ HSL ↔ HSV ↔ CMYK conversion
- **Timestamps:** Unix timestamp ↔ human-readable date (all IANA timezones, ms/µs/ns variants), Windows FILETIME, Mac HFS+ time, NTP timestamp
- **UUID/GUID parser:** version detection, node (v1 MAC address extraction), timestamp (v1), namespace (v3/v5)
- **Luhn algorithm:** validate and generate (credit card, IMEI)
- **BIN lookup** (offline DB): card brand, bank, country, card type
- **ISBN:** validate (ISBN-10 / ISBN-13), convert between formats, group decode
- **IBAN / BIC:** validate, parse country/bank/account structure
- **IP tools (offline):** subnet calculator, CIDR expansion, IP → integer, IP → binary display, IPv4 ↔ IPv6 mapping, private range detection
- **MAC address OUI lookup** (offline DB): vendor identification
- **Regex tester:** multiline, all flags, capture group display, named groups, step-through match debugger
- **Text diff:** unified diff and side-by-side (character + word + line level)
- **Binary diff:** visual byte-level diff with offset sync
- **Language detection:** character n-gram model, confidence scores
- **Frequency analysis:** letter, bigram, trigram, word frequency tables; IC, chi-squared, entropy output
- **Morse / Semaphore / flag signal decoder**
- **Tap code / Polybius square workbench**
- **Braille decode**
- **Wingdings / Webdings / Symbol font decoder**
- **Zero-width character inspector** (shows invisible characters explicitly)
- **Homoglyph detector** (Cyrillic/Greek/Latin lookalike character highlighter)
- **Phone number parser** (libphonenumber: region, type, format variants)
- **Color-based cipher helper** (hex color → ASCII, RGB values as char codes)

---

## RECON Mode

### Network Scanning

- **Nmap** — full integration: SYN scan, UDP scan, version detection (`-sV`), OS detection (`-O`), aggressive scan (`-A`), output all formats
- **Nmap NSE browser** — searchable script list with description, category, args display; one-click run against target
- **Masscan** — high-speed port scan with configurable rate limiting (PPS), banner grab
- **Zmap** — single-port internet-scale scan (for lab/CTF ranges)
- Service fingerprinting and banner grab (netcat / custom TCP/UDP probe)
- Traceroute: TCP, UDP, and ICMP modes; per-hop ASN and geolocation lookup
- Ping sweep / host discovery: ARP (LAN), ICMP echo, TCP SYN to common ports
- IPv6 scanning: neighbor discovery (NDP), ICMPv6 ping, link-local range sweep
- Network topology mapper (visual graph from nmap scan results, dot/graphviz/D3 export)
- Firewall and WAF detection heuristics (nmap `--badsum`, TTL analysis, response fingerprinting)

---

### DNS

- Full record type lookup: A, AAAA, MX, NS, TXT, SOA, PTR, SRV, CAA, DNSKEY, DS, NSEC, NSEC3, TLSA, NAPTR, HINFO, LOC, CERT
- Reverse DNS (PTR lookup, subnet sweep)
- Zone transfer: AXFR, IXFR (per-nameserver targeting)
- DNS brute-force: dnsx, massdns, dnsrecon, fierce with configurable wordlists (small/medium/large)
- Subdomain enumeration: passive (Certificate Transparency, SecurityTrails API, FOFA, VirusTotal) + active brute-force combined
- DNS history (passive DNS lookup: SecurityTrails, RiskIQ, DNSDB API)
- DNSSEC chain validation (trust anchor to record)
- DNS-over-HTTPS (Cloudflare, Google, custom resolver)
- DNS-over-TLS (configurable upstream)
- Wildcard detection (randomized subdomain testing)
- DNS cache poisoning check (Kaminsky-style, transaction ID randomness)
- DNS rebinding checker (short TTL + A record to private IP detection)
- MX security analysis: SPF parse/validate, DKIM record lookup, DMARC policy display, BIMI check

---

### HTTP / Web Reconnaissance

- **HTTP request builder:** method, headers, body, auth (Basic, Bearer, NTLM, Digest), proxy, follow-redirects toggle, TLS SNI override, IPv6 force
- **Directory/file brute-force:** feroxbuster / gobuster / dirsearch — configurable wordlist, extensions, status filter, recursion, rate limit, output diff
- **Virtual host brute-force:** ffuf vhost mode, Host header fuzzing
- **Parameter discovery:** ffuf GET/POST parameter fuzzing, arjun integration
- **Technology fingerprinting:** whatweb, wappalyzer CLI — version detection, CMS, frameworks, libraries
- **CMS scanners:** WPScan (WordPress), droopescan (Drupal/Silverstripe/Moodle), CMSeeK, joomscan
  - WordPress: user enumeration, plugin/theme version check, vuln DB lookup, XML-RPC check
- **JavaScript analysis:** linkfinder (endpoints), secretfinder (secrets/keys), JSParser, js-beautify; auto-extract all `<script src>` URLs and fetch
- **Historical URL mining:** Wayback Machine (CDX API), CommonCrawl, OTX URLscan — bulk URL dump, filter by content-type, diff snapshots
- **Secret scanning in JS/HTML:** gitleaks pattern set (AWS keys, GCP, GitHub tokens, generic API keys, JWTs, private keys)
- robots.txt / sitemap.xml / `.well-known/` fetcher and recursive parser
- HTTP security header analyzer (HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, rating)
- Cookie security flag display (Secure, HttpOnly, SameSite, domain scope)
- Full recursive crawler: katana / gospider / hakrawler — scope control, JS rendering mode, out-of-scope link logging
- Screenshot capture: gowitness / aquatone — bulk screenshot and HTML report
- API endpoint discovery: kiterunner against API wordlists (swagger, Assetnote mega-list)
- GraphQL: endpoint detection (`/graphql`, `/api/graphql`, etc.), introspection dump, schema visualizer, query fuzzer
- WebSocket endpoint detection and probe
- Open redirect tester (parametric and path-based)
- Clickjacking check (X-Frame-Options + CSP `frame-ancestors`)
- Certificate transparency search: crt.sh, certspotter, Entrust CT logs

---

### OSINT

- **WHOIS:** current query (all TLDs) + historical (SecurityTrails)
- **IP geolocation:** MaxMind GeoIP2 (bundled DB) + fallback APIs (ip-api.com, ipinfo.io)
- **ASN lookup:** full prefix list, peer ASes, upstream providers, BGP route history (bgpview.io API)
- **Shodan** search + host lookup (API key managed in config)
- **Censys** search + certificate/host lookup (API key)
- **FOFA** search (API key)
- **Hunter.io** email finder (API key)
- **Dehashed** / **HaveIBeenPwned** breach check (API key)
- **GitHub dorking:** code search, commit search, issue/PR search — secret patterns (token, API key, password, private key)
- **GitLab / Bitbucket** public repo search
- **Pastebin** search (Google dork via SerpAPI or direct scrape)
- **Google dork templates:** `filetype`, `site`, `inurl`, `intitle`, `intext` combos — prebuilt for common CTF scenarios
- **Sherlock** — username search across 400+ social platforms
- **Email tools:** format guesser (first.last, flast, f.last permutations), MX validation, disposable email detection
- **LinkedIn enumeration** (Google dork + theHarvester)
- **theHarvester** — email, name, subdomain, IP harvest from public sources
- **Recon-ng** workspace integration — module browser, data export
- **Phone number OSINT:** numverify API (carrier, region, line type)
- **BGP route history** (RIPE RIS, RouteViews)

---

### SSL/TLS

- **testssl.sh** full integration — cipher suite enumeration, protocol support, certificate details, vulnerability checks
- **Certificate transparency monitoring** — crt.sh watch for new certs on domain
- Cipher suite rating (A–F grade, SSL Labs methodology)
- Certificate chain download, parse, and display (all certs, validity windows, signature algorithms)
- **Vulnerability checks:**
  - Heartbleed (CVE-2014-0160)
  - POODLE (SSLv3 CBC padding)
  - BEAST (TLS 1.0 CBC)
  - CRIME / BREACH (compression oracle)
  - FREAK (export cipher downgrade)
  - Logjam (DHE export downgrade)
  - DROWN (SSLv2 cross-protocol)
  - ROBOT (RSA PKCS#1 v1.5 Bleichenbacher)
  - LUCKY13
  - Ticketbleed (TLS session ticket)
  - Sweet32 (64-bit block cipher birthday)
  - RC4 usage detection
- Certificate pinning detection (HPKP header, HTTP/2 preload)
- HSTS header check and preload list lookup
- Key exchange group enumeration (ECDH named curves, DHE parameter sizes)
- Session resumption support check (session ID, session ticket)

---

### Active Exploitation Helpers

> **For use in legal CTF environments only. Always obtain authorization.**

| Category | Tools / Features |
|---|---|
| **SQLi** | sqlmap full integration — GET/POST/cookie/header injection, DBMS auto-detect, tamper script selector, `--os-shell`, dump mode |
| **XSS** | XSStrike, dalfox — DOM/stored/reflected detection, polyglot payloads, WAF bypass wordlist, filter evasion options |
| **LFI** | wfuzz/ffuf LFI wordlist runner, PHP filter chain generator (arbitrary file read via PHP wrapper chains), log poisoning helper, `/proc/self/` exploration |
| **RFI** | Payload generator with automatic listener setup |
| **SSTI** | tplmap integration, manual payload injection with engine selector |
| **Command injection** | commix integration, manual payload builder, semicolon/pipe/backtick/`$()` variants, blind (sleep/DNS/HTTP OOB) |
| **File upload bypass** | Magic byte manipulation, MIME type bypass, double extension, null byte injection, case variation, content-type spoof, SVG/XML upload |
| **IDOR** | Sequential ID fuzzer, hash-based ID fuzzer (MD5/SHA1 of sequential integers) |
| **CSRF** | CSRF PoC HTML generator, token bypass heuristics, SameSite analysis |
| **Race condition** | Concurrent HTTP request sender (configurable concurrency, turbo-intruder style) |
| **Path traversal** | Fuzzer with OS-specific payloads and encoding bypasses (URL, double URL, UTF-8, 16-bit Unicode) |
| **SSRF** | Cloud metadata payloads (AWS IMDSv1/v2, GCP, Azure, DigitalOcean, Oracle Cloud), bypass list |
| **HTTP smuggling** | CL.TE / TE.CL / H2 desync payload builder and tester |
| **Prototype pollution** | `__proto__`, `constructor.prototype`, `Object.prototype` payload chain generator |
| **Open redirect** | Payload list with schema bypass (`javascript:`, `//`, `////`, `\/\/`, unicode) |

---

### Service-Specific Attacks

#### Authentication Services
- **FTP:** anonymous login test, brute-force (hydra), recursive download (wget mirror), hidden file check
- **SSH:** banner grab, brute-force (hydra/medusa), user enumeration (CVE-2018-15473 timing), accepted key algorithm check, `authorized_keys` path testing
- **Telnet:** connect + brute-force, banner harvest
- **RDP:** brute-force (crowbar/hydra), BlueKeep (CVE-2019-0708) check, NLA detection, drive/clipboard mount
- **VNC:** brute-force, authentication-none check, screenshotter

#### Email
- **SMTP:** open relay test, user enumeration (VRFY, EXPN, RCPT TO harvesting), send test email (with attachment), STARTTLS support check
- **POP3 / IMAP:** brute-force, full mailbox dump (login required)

#### File Sharing
- **SMB:** share enumeration (smbmap, smbclient), null session test, user enumeration, relay detection, EternalBlue (MS17-010) check (nmap NSE), BlueKeep adjacent MS19-0708 check, pass-the-hash (impacket psexec/smbexec)
- **NFS:** showmount, mount and browse, no_root_squash detection

#### Databases
- **MySQL:** brute-force (hydra), schema dump (mysqldump), `LOAD_FILE()` test, UDF command execution check
- **PostgreSQL:** brute-force, schema dump, `COPY TO/FROM PROGRAM` check, `lo_read` file read
- **MSSQL:** brute-force, `xp_cmdshell` enable/exec check, linked server enumeration, `OPENROWSET` file read
- **Oracle:** SID brute-force (odat), TNS listener check, `UTL_FILE` read, Java stored proc exec
- **Redis:** unauthenticated access check, keyspace dump (`SCAN` + type resolver), config read/write, cron/authorized_keys write exploit path
- **MongoDB:** unauthenticated access check, collection dump, `$where` injection
- **Elasticsearch:** unauthenticated check, index enumeration, full document dump
- **Memcached:** stats dump, key scan (`lru_crawler`)
- **CouchDB:** unauthenticated check, `/_users` read, admin party detection, CVE-2017-12635 check

#### Directory Services
- **SNMP:** community string brute-force (onesixtyone), MIB walk (snmpwalk), v1/v2c/v3 support, OID dump
- **LDAP:** anonymous bind check, object dump (ldapsearch), user enumeration, password spray
- **Kerberos** (impacket-based): AS-REP roasting (`GetNPUsers.py`), kerberoasting (`GetUserSPNs.py`), pass-the-ticket, golden ticket forge, silver ticket forge, MS14-068 check, DCSync simulation
- **WinRM:** authentication check, evil-winrm launcher with upload/download
- **MSRPC:** endpoint mapper query, interface enumeration (rpcclient)
- **IPMI:** cipher 0 authentication bypass test, RAKP hash capture

#### DevOps / Cloud APIs
- **Docker daemon:** unauthenticated API check, container list, image list, escape path indicator (privileged container, host volume mounts)
- **Kubernetes API server:** anonymous auth check, pod enumeration, secret dump, `kubectl` proxy launcher
- **etcd:** unauthenticated check, key enumeration and dump (service account token harvest)
- **Consul:** unauthenticated check, service/node dump, KV store read
- **Zookeeper:** unauthenticated check, node tree dump

---

### Wireless

> Requires compatible hardware (monitor mode capable adapter or USB passthrough to container)

- **WiFi scan:** airodump-ng capture, channel hopper, client list display
- **WPA2 handshake capture:** aireplay-ng deauthentication + airodump-ng capture, 4-way handshake detector
- **PMKID attack:** hcxdumptool capture, hcxtools convert to hashcat format 22000
- **WPA handshake crack:** aircrack-ng (CPU) / hashcat mode 22000 (GPU)
- **WPS PIN brute-force:** reaver / bully, pixie-dust attack
- **Evil twin AP:** hostapd-wpe (credentials capture), captive portal template
- **Bluetooth:** hcitool scan, bluetoothctl device enumerate, L2CAP ping, SDP browse
- **BLE:** advertisement scanner, GATT service/characteristic enumerate (gatttool / bluetoothctl)
- **Zigbee / Z-Wave:** sniff and decode (KillerBee / Z-Wave sniffer if hardware present)

---

### Infrastructure & Cloud

- AWS IMDSv1 (`169.254.169.254`) and IMDSv2 (token-based) metadata endpoint check
- **S3 bucket testing:** name brute-force, ACL check (public read/write/list), object enumeration, policy read
- GCP metadata endpoint (`metadata.google.internal`) check + token/attribute dump
- Azure IMDS endpoint check + managed identity token fetch
- CloudFront / Cloudflare / Fastly origin IP discovery (historical DNS, timing, direct probing)
- Container registry enumeration (Docker Hub, GitHub Container Registry, ECR — public image list)
- Serverless function endpoint fingerprinting (Lambda URL patterns, Cloud Function URL)

---

### Callback / Out-of-Band

The built-in interaction server runs inside the Docker container with configurable port forwarding. A unique subdomain/token is generated per probe.

| Listener | Protocol | Features |
|---|---|---|
| HTTP/HTTPS server | TCP 80/443 | Log all requests (headers, body, source IP, timestamp), configurable response |
| DNS server | UDP 53 | Log all queries, wildcard `*.token.yourdomain.com` response, A/AAAA/MX/TXT support |
| SMTP listener | TCP 25 | Log EHLO, RCPT, DATA — capture XXE/SSRF triggered mail |
| FTP listener | TCP 21 | Log USER/PASS, capture XXE FTP OOB |
| LDAP listener | TCP 389 | Log bind DN/password, JNDI/Log4Shell OOB capture |
| Generic TCP | Any port | Raw byte capture, hex display |

- Interaction log viewer: real-time stream with timestamp, source IP, protocol, decoded payload
- Unique token generator (UUID-based, per-probe tracking)
- One-click copy of payload strings containing callback URL/domain

---

### Proxy & Traffic Manipulation

- **mitmproxy** embedded integration (intercept mode, scripted mode)
- Upstream proxy support (route tool traffic through Burp Suite, ZAP, custom proxy)
- Intercept rules: URL regex match, header match, method filter
- Request replay with inline modification (headers, body, method)
- Request history browser (search by URL, status code, content-type, response time)
- Response modification rules (header injection, body search-and-replace)
- Traffic capture: tcpdump wrapper (filter expression builder, PCAP save, live hex stream)
- WebSocket intercept and replay (frame-level modification)

---

## TUI Frontend Features

### Layout

- **Multi-pane layout:** tool selector tree (left sidebar), input pane (center-top), output pane (center-bottom), context/info pane (right sidebar — shows tool docs, last result summary, loot snippets)
- Tab system for multiple simultaneous tool sessions
- Split-pane mode (run two tools side-by-side)
- Fullscreen output mode (maximize output pane, toggle back)

### Navigation & Usability

- Keyboard-first: vim-style navigation (`h/j/k/l`, `/` for search, `q` to close)
- Fuzzy tool search (fzf-style, searches name + description + tags)
- Command palette (`Ctrl+P`) — jump to any tool, action, or workspace item
- Persistent session history — replay or re-run any previous command
- Copy output to clipboard (entire pane, selection, or just last result)
- Export: raw text, JSON, annotated HTML report
- **Pipeline builder:** visually chain tools (output of tool A → input of tool B), save and re-run pipelines
- Drag-and-drop file input (drop file onto TUI window)
- Configurable color scheme (dark terminal-native, ANSI 256-color, true color; base16 theme support)
- Progress bars, spinners, and ETAs for long-running operations

### Project / Workspace

- **CTF project workspace:** named per-challenge, stores target metadata, notes, discovered assets
- **Loot database:** found credentials, hashes, tokens, cookies, API keys, flags — searchable, taggable, exportable
- **Note pad** per challenge (Markdown, rendered inline)
- Flag submission tracker (found / submitted / verified status)
- Action timeline (chronological log of every tool invocation and result)
- Export workspace to full Markdown pentest report (template-based, customizable)
- Import workspace from previous session or share with teammate (encrypted zip)

### Docker Management

- Container health indicator (status, uptime)
- Tool inventory display with installed versions
- Update mechanism: pull latest image, diff tool versions
- Resource monitor: container CPU, memory, disk I/O
- Background service log viewer: callback server, proxy, listeners
- Port forwarding manager (add/remove container ↔ host port mappings)

---

## Docker Tool Inventory

The image is based on Ubuntu 22.04/24.04 LTS and bundles (among others):

**Scanning & Enumeration:** nmap, masscan, zmap, ncrack, hydra, medusa, netcat, socat, curl, wget, httpx, nuclei, nikto, whatweb, wpscan, droopescan, cmseek, joomscan, amass, subfinder, assetfinder, dnsx, massdns, dnsrecon, fierce, dig, nslookup, whois

**Web Attack:** sqlmap, ffuf, gobuster, feroxbuster, dirsearch, dalfox, XSStrike, commix, tplmap, kiterunner, arjun, katana, gospider, hakrawler, linkfinder, secretfinder, gowitness, gitleaks

**Password & Hash:** hashcat, john (jumbo), fcrackzip, pkcrack, stegseek, hcxtools, hcxdumptool, onesixtyone, hydra, medusa, crowbar

**Exploitation:** metasploit framework, impacket suite, evil-winrm, crackmapexec, bloodhound-python, kerbrute, responder, bettercap, ysoserial (Java), phpggc, pwntools, ROPgadget, ropper, one_gadget, pwndbg, GEF

**Reverse Engineering / Forensics:** ghidra (headless), radare2, retdec, jadx, apktool, cfr, dnspy CLI, ilspy CLI, wasm-tools, frida-tools, unicorn engine, capstone, binwalk, foremost, scalpel, volatility3, sleuthkit (TSK), bulk_extractor, exiftool, steghide, zsteg, stegsolve (headless), outguess, pdfid, pdf-parser, ffmpeg, imagemagick, wireshark/tshark, tcpdump, mitmproxy, scapy

**Crypto & Math:** openssl, age, gpg, SageMath, python3 (pwntools, cryptography, PyCryptodome, gmpy2, sympy, angr, z3-solver), hashid, haiti

**Utilities:** gdb, ltrace, strace, objdump, readelf, checksec, file, xxd, hexdump, strings, binutils, upx, qrencode, zbar, poppler-utils, pandoc, jq, yq, xmllint, python3, ruby, perl, go toolchain, nodejs, php CLI, java 17+, rustc

---

*Document version: 1.0 — Generated as full CTF Swiss Army Knife specification*
