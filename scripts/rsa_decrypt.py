#!/usr/bin/env python3
import sys

def n_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def isqrt(n):
    if n < 0: return -1
    if n == 0: return 0
    x, y = (n + 1) // 2, n
    while x < y:
        y, x = x, (x + n // x) // 2
    return y

def factor_fermat(n):
    a = isqrt(n)
    if a * a < n: a += 1
    b2 = a * a - n
    while True:
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
        b2 = a * a - n
        if a > (n + 1) // 2: break
    return None

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def inverse(e, phi):
    d, x1, x2, y1, y2 = 0, 0, 1, 1, 0
    temp_phi = phi
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2
        x = x2 - temp1 * x1
        y = y2 - temp1 * y1
        x2 = x1
        x1 = x
        y2 = y
        y1 = y
    if x2 < 0:
        x2 += phi
    return x2

def solve():
    raw = sys.stdin.read().strip()
    if not raw: return
    parts = raw.split("::")
    if len(parts) < 3:
        print("Format Error: modulus::exponent::ciphertext")
        return

    def parse(s):
        s = s.strip().lower()
        if s.startswith("0x"): return int(s, 16)
        try: return int(s)
        except: return int(s, 16)

    try:
        n = parse(parts[0])
        e = parse(parts[1])
        c = parse(parts[2])
    except Exception as ex:
        print(f"Parse Error: {ex}")
        return

    # Try simple factoring
    p, q = None, None
    if n % 2 == 0:
        p, q = 2, n // 2
    else:
        # Pollard's rho or Fermat? Let's just try small factors first
        for i in range(3, 1000000, 2):
            if n % i == 0:
                p, q = i, n // i
                break
        
        # If not found, try Fermat (for p/q close together)
        if not p:
            # Only try Fermat if N isn't too huge, just for 1s
            res = factor_fermat(n)
            if res: p, q = res

    if p and q:
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
            m = pow(c, d, n)
            try:
                msg = n_to_bytes(m).decode()
                print(f"Decrypted (p={p}, q={q}):\n{msg}")
            except:
                print(f"Decrypted hex (p={p}, q={q}):\n{hex(m)}")
        except Exception as ex:
            print(f"Math Error: {ex}")
    else:
        print("Could not factor N. Try using an external factorizer (like factordb).")

if __name__ == "__main__":
    solve()
