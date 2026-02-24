use std::io::{self, Read};
use num_bigint::{BigInt, BigUint};
use num_traits::{Zero, One, Signed};

fn n_to_bytes(n: BigUint) -> Vec<u8> {
    n.to_bytes_be()
}

fn is_perfect_square(n: &BigInt) -> Option<BigInt> {
    if n.is_negative() { return None; }
    if n.is_zero() { return Some(BigInt::zero()); }
    let s = n.sqrt();
    if (&s * &s) == *n {
        Some(s)
    } else {
        None
    }
}

fn factor_fermat(n: &BigInt) -> Option<(BigInt, BigInt)> {
    let mut a = n.sqrt();
    if (&a * &a) < *n {
        a += BigInt::one();
    }
    let mut b2 = &a * &a - n;
    let max_iterations = 1000000;
    for _ in 0..max_iterations {
        if let Some(b) = is_perfect_square(&b2) {
            return Some((&a - &b, &a + &b));
        }
        a += BigInt::one();
        b2 = &a * &a - n;
    }
    None
}

fn parse_value(s: &str) -> Option<BigInt> {
    let s = s.trim().to_lowercase();
    if s.starts_with("0x") {
        BigInt::parse_bytes(s[2..].as_bytes(), 16)
    } else {
        s.parse::<BigInt>().ok()
    }
}

fn mod_inverse(e: &BigInt, phi: &BigInt) -> Option<BigInt> {
    let (g, x, _) = egcd(e, phi);
    if g != BigInt::one() {
        None
    } else {
        Some((x % phi + phi) % phi)
    }
}

fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if *a == BigInt::zero() {
        (b.clone(), BigInt::zero(), BigInt::one())
    } else {
        let (g, x, y) = egcd(&(b % a), a);
        (g, y - (b / a) * &x, x)
    }
}

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("failed to read stdin");
    let input = input.trim();
    if input.is_empty() { return; }

    let parts: Vec<&str> = input.split("::").collect();
    if parts.len() < 3 {
        println!("Format Error: modulus::exponent::ciphertext");
        return;
    }

    let n = match parse_value(parts[0]) {
        Some(v) => v,
        None => { println!("Parse Error: Invalid N"); return; }
    };
    let e = match parse_value(parts[1]) {
        Some(v) => v,
        None => { println!("Parse Error: Invalid E"); return; }
    };
    let c = match parse_value(parts[2]) {
        Some(v) => v,
        None => { println!("Parse Error: Invalid C"); return; }
    };

    let mut p_found: Option<BigInt> = None;
    let mut q_found: Option<BigInt> = None;

    if &n % 2i32 == BigInt::zero() {
        p_found = Some(2i32.into());
        q_found = Some(&n / 2i32);
    } else {
        for i in (3..1000000).step_by(2) {
            let bi = BigInt::from(i);
            if &n % &bi == BigInt::zero() {
                p_found = Some(bi);
                q_found = Some(&n / BigInt::from(i));
                break;
            }
        }
        if p_found.is_none() {
            if let Some((p, q)) = factor_fermat(&n) {
                p_found = Some(p);
                q_found = Some(q);
            }
        }
    }

    if let (Some(p), Some(q)) = (p_found, q_found) {
        let phi = (&p - BigInt::one()) * (&q - BigInt::one());
        if let Some(d) = mod_inverse(&e, &phi) {
            let m = c.modpow(&d, &n);
            let m_bytes = m.to_biguint().unwrap();
            let bytes = n_to_bytes(m_bytes);
            match String::from_utf8(bytes.clone()) {
                Ok(s) => {
                    println!("Decrypted (p={}, q={}):\n{}", p, q, s);
                }
                Err(_) => {
                    println!("Decrypted hex (p={}, q={}):\n0x{:x}", p, q, m);
                }
            }
        } else {
            println!("Math Error: E and phi(N) are not coprime.");
        }
    } else {
        println!("Could not factor N. Try using an external factorizer (like factordb).");
    }
}