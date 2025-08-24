#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# offline-keykit :: evm_tool.py  (air-gapped)
# Generates a 32-byte EVM private key and the EIP-55 checksummed address (Ethereum/Base).
# - No third-party libs. Pure-Python secp256k1 + Keccak-256.
# - NEVER bring the PRIVATE KEY online. Write on paper. Bring back ONLY the address.
#
# Usage (offline):
#   python3 evm_tool.py
#
# Entropy:
#   1) Dice: roll a fair 6-sided die >= 100 times; type a continuous string of digits 1..6.
#   2) System: os.urandom(32) (works on Live Ubuntu, still offline).
#
# Output:
#   - PRIVATE KEY (64-hex)  -> write on paper (two copies)
#   - Address (0x...)       -> you can bring this online
#
# ------------------------------------------------------------------------------

import os
import sys

# ======= secp256k1 parameters (Ethereum/Base) =======
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A  = 0
B  = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G  = (Gx, Gy)

def inv_mod(x, p=P):
    return pow(x % p, p - 2, p)

def ec_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    (x1, y1) = p1
    (x2, y2) = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if x1 == x2 and y1 == y2:
        # tangent
        m = (3 * x1 * x1 + A) * inv_mod(2 * y1, P) % P
    else:
        # chord
        m = (y2 - y1) * inv_mod((x2 - x1) % P, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y2) % P
    return (x3, y3)

def scalar_mult(k, point=G):
    if k % N == 0 or point is None:
        return None
    k = k % N
    result = None
    addend = point
    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result

# ======= Keccak-256 (Ethereum) =======
# Pure-Python Keccak-f[1600] with pad10*1, rate=1088 bits (136 bytes), output 32 bytes.

ROT = [
    [0,  36, 3,  41, 18],
    [1,  44, 10, 45, 2 ],
    [62, 6,  43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8,  14],
]
RC = [
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
]

def rol64(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

def keccak_f(a):
    # a is 5x5 of 64-bit ints
    for rnd in range(24):
        # Theta
        C = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rol64(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= D[x]
        # Rho + Pi
        B = [[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2*x + 3*y) % 5] = rol64(a[x][y], ROT[x][y])
        # Chi
        for x in range(5):
            for y in range(5):
                a[x][y] = B[x][y] ^ ((~B[(x+1)%5][y]) & B[(x+2)%5][y])
        # Iota
        a[0][0] ^= RC[rnd]
    return a

def keccak_256(msg: bytes) -> bytes:
    rate = 136  # bytes
    # init state 5x5 of 64-bit
    A = [[0]*5 for _ in range(5)]
    # pad10*1
    padlen = rate - ((len(msg) + 1) % rate)
    padded = msg + b'\x01' + b'\x00' * padlen
    padded = bytearray(padded)
    padded[-1] ^= 0x80
    # absorb
    for off in range(0, len(padded), rate):
        block = padded[off:off+rate]
        # XOR block into lanes (little-endian)
        for i in range(rate // 8):  # 17 lanes
            lane = int.from_bytes(block[i*8:(i+1)*8], 'little')
            x = i % 5
            y = i // 5
            A[x][y] ^= lane
        keccak_f(A)
    # squeeze
    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            x = i % 5
            y = i // 5
            out += A[x][y].to_bytes(8, 'little')
        if len(out) >= 32:
            break
        keccak_f(A)
    return bytes(out[:32])

# ======= Address helpers =======

def privkey_from_dice(digits: str) -> bytes:
    # validate
    if not digits or any(ch not in "123456" for ch in digits):
        raise ValueError("Dice input must be digits 1..6 only.")
    if len(digits) < 100:
        raise ValueError("Need >=100 rolls (digits 1..6).")
    # Convert base-6 string to big integer, then hash to 32 bytes (uniform)
    n = 0
    for ch in digits:
        n = n * 6 + (ord(ch) - 48)  # '1'..'6' -> 1..6
    be = n.to_bytes((n.bit_length() + 7)//8 or 1, 'big')
    return keccak_256(be)

def ensure_range_1n(priv: bytes) -> int:
    k = int.from_bytes(priv, 'big')
    k = (k % (N - 1)) + 1
    return k

def pubkey_uncompressed(k_int: int) -> bytes:
    Pxy = scalar_mult(k_int, G)
    if Pxy is None:
        raise ValueError("Invalid private key.")
    x, y = Pxy
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

def eth_address_from_pub(u_pub: bytes) -> str:
    # address = last 20 bytes of keccak256(uncompressed_pub[1:])
    h = keccak_256(u_pub[1:])
    raw = h[-20:]
    return to_checksum_address(raw)

def to_checksum_address(raw20: bytes) -> str:
    hx = raw20.hex()
    hh = keccak_256(hx.encode('ascii')).hex()
    out = ['0', 'x']
    for c, h in zip(hx, hh):
        if c.isdigit():
            out.append(c)
        else:
            out.append(c.upper() if int(h, 16) >= 8 else c.lower())
    return ''.join(out)

def print_box(title, value):
    print("\n" + "="*70)
    print(title)
    print("-"*70)
    print(value)
    print("="*70 + "\n")

def main():
    print("== offline-keykit :: evm_tool (air-gapped) ==")
    print("Generates a 32-byte private key and the EIP-55 checksummed address (Ethereum/Base).")
    print("Write the PRIVATE KEY on PAPER. Bring back online ONLY the address.\n")

    print("Entropy source: 1) Dice  2) System")
    choice = input("[1/2]: ").strip()

    if choice == "1":
        print("\n[ Dice mode ] Roll a fair 6-sided die.")
        print("Enter a continuous string of >=100 rolls (digits 1..6, no spaces).")
        print("Example: 362514... (keep going until you have at least 100 digits)")
        digits = input("Enter rolls: ").strip()
        try:
            seed = privkey_from_dice(digits)
        except Exception as e:
            print(f"[fatal] {e}")
            sys.exit(1)
    elif choice == "2":
        seed = os.urandom(32)
    else:
        print("[fatal] Choose 1 or 2.")
        sys.exit(1)

    k_int = ensure_range_1n(seed)
    priv_hex = k_int.to_bytes(32, 'big').hex()
    u_pub = pubkey_uncompressed(k_int)
    addr = eth_address_from_pub(u_pub)

    print_box("PRIVATE KEY (64-hex)  -> WRITE ON PAPER; NEVER BRING ONLINE", priv_hex)
    print_box("Address (EIP-55)      -> you may bring this online", addr)

if __name__ == "__main__":
    main()
