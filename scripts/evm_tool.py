#!/usr/bin/env python3
# offline-keykit: evm_tool.py
#
# Air-gapped EVM key tool:
#  - Generates a 32-byte private key (dice or system entropy)
#  - Derives Ethereum/Base address via pure-Python secp256k1 + Keccak-256 (Ethereum variant)
#  - Prints hex private key and EIP-55 checksummed address
#
# 100% offline, single-file, pure Python. No third-party libs.
#
# USAGE (offline):
#   python3 evm_tool.py
#
# SECURITY:
#   * Never run on an internet-connected OS.
#   * Write the private key on paper ONLY (two copies, separate locations).
#   * Bring back online ONLY the address (public).
#
# NOTE:
#   This script includes a compact Keccak-256 (Ethereum) implementation,
#   not hashlib.sha3_256 (NIST SHA3) — Ethereum uses the pre-NIST Keccak.
#
# References (conceptual):
#   - secp256k1 params (SEC)
#   - EIP-55 checksum
#   - Keccak-f[1600] 24-round permutation

import os, sys, hashlib

def die(msg): print(f"[fatal] {msg}"); sys.exit(1)
def ask(p):
    try: return input(p)
    except KeyboardInterrupt:
        print("\n[aborted]"); sys.exit(1)

# ---------- secp256k1 ----------
# Curve: y^2 = x^3 + 7 over Fp
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424

def inv(n): return pow(n, P-2, P)

def _pt_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1,y1 = P1; x2,y2 = P2
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if x1 == x2 and y1 == y2:
        lam = (3*x1*x1) * inv(2*y1) % P
    else:
        lam = (y2 - y1) * inv((x2 - x1) % P) % P
    x3 = (lam*lam - x1 - x2) % P
    y3 = (lam*(x1 - x3) - y1) % P
    return (x3, y3)

def _pt_mul(k, P0=(Gx, Gy)):
    if k % N == 0 or k <= 0: raise ValueError("bad priv")
    Q = None; add = P0
    while k:
        if k & 1: Q = _pt_add(Q, add)
        add = _pt_add(add, add)
        k >>= 1
    return Q

def priv_to_pub_uncompressed(priv: int) -> bytes:
    x, y = _pt_mul(priv)
    return b'\x04' + x.to_bytes(32,'big') + y.to_bytes(32,'big')

# ---------- Keccak-256 (Ethereum) ----------
# Compact, pure-Python Keccak-f[1600] permutation + sponge for Keccak-256
# Based on the Keccak specification. Slow but fine for offline single-use.

def _rot(x, n): return ((x << n) | (x >> (64 - n))) & ((1<<64)-1)

RC = [
  0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
  0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
  0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
  0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
  0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
  0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008
]
RHO = [
  [0,36,3,41,18],
  [1,44,10,45,2],
  [62,6,43,15,61],
  [28,55,25,21,56],
  [27,20,39,8,14],
]

def _keccak_f(a):
    # a is 5x5 matrix of 64-bit ints
    for rnd in range(24):
        # Theta
        C = [a[x][0]^a[x][1]^a[x][2]^a[x][3]^a[x][4] for x in range(5)]
        D = [C[(x-1)%5] ^ _rot(C[(x+1)%5],1) for x in range(5)]
        for x in range(5):
            for y in range(5): a[x][y] ^= D[x]
        # Rho + Pi
        B = [[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2*x+3*y)%5] = _rot(a[x][y], RHO[x][y])
        # Chi
        for x in range(5):
            for y in range(5):
                a[x][y] = B[x][y] ^ ((~B[(x+1)%5][y]) & B[(x+2)%5][y])
        # Iota
        a[0][0] ^= RC[rnd]
    return a

def keccak_256(data: bytes) -> bytes:
    # Keccak-256: rate=1088 bits (136 bytes), capacity=512, output=256 bits
    rate = 136
    # initialize state
    a = [[0]*5 for _ in range(5)]
    # absorb
    i = 0
    while i < len(data):
        block = data[i:i+rate]
        for j in range(len(block)):
            x = j // 8
            y = (j % 8)
            # map into lanes: we fold block into a in little-endian per lane
            a[x][y] ^= block[j] << (8 * (j % 8))
        i += rate
        if len(block) == rate:
            a = _keccak_f(a)
    # pad: multi-rate padding 0x01 ... 0x80
    padlen = rate - (len(data) % rate)
    pad = bytearray([0]*padlen)
    pad[0] = 0x01
    pad[-1] |= 0x80
    j = 0
    for b in pad:
        x = j // 8
        y = (j % 8)
        a[x][y] ^= b << (8 * (j % 8))
        j += 1
    a = _keccak_f(a)
    # squeeze 32 bytes
    out = bytearray()
    while len(out) < 32:
        for y in range(5):
            for x in range(5):
                if (8*(5*y + x)) >= rate*8: continue
                lane = a[x][y]
                out += lane.to_bytes(8,'little')
                if len(out) >= 32: return bytes(out[:32])
        a = _keccak_f(a)
    return bytes(out[:32])

# ---------- EIP-55 checksum ----------
def to_checksum_address(addr20: bytes) -> str:
    hex_addr = addr20.hex()
    hashed = keccak_256(hex_addr.encode()).hex()
    out = "0x"
    for c,h in zip(hex_addr, hashed):
        out += c.upper() if int(h,16) >= 8 else c
    return out

# ---------- entropy sources ----------
def _entropy_from_dice():
    print("\n[ Dice mode ] Roll a fair 6-sided die; enter a string like 326154... ")
    s = ask("Enter >=100 rolls (digits 1..6, no spaces): ").strip()
    if len(s) < 100 or any(ch not in "123456" for ch in s):
        die("Need >=100 rolls, digits 1..6 only.")
    # Mix via SHA-512 -> SHA-256 (32 bytes)
    h = hashlib.sha512(s.encode()).digest()
    ent = hashlib.sha256(h).digest()
    return ent

def _entropy_from_system():
    return os.urandom(32)

# ---------- main ----------
def main():
    print("=== offline-keykit :: evm_tool (air-gapped) ===")
    print("Generates a 32-byte private key and the EIP-55 checksummed address (Ethereum/Base).")
    print("Write the PRIVATE KEY on PAPER. Bring back online ONLY the address.\n")

    choice = ask("Entropy source: 1) Dice  2) System   [1/2]: ").strip()
    ent = _entropy_from_dice() if choice == "1" else _entropy_from_system()

    # map 32 bytes to [1..N-1]
    k = (int.from_bytes(ent, 'big') % (N-1)) + 1
    if k == 0 or k >= N: die("entropy mapping failed, try again")

    pk_hex = k.to_bytes(32,'big').hex()
    pub = priv_to_pub_uncompressed(k)  # 0x04 || X(32) || Y(32)
    pub_xy = pub[1:]                   # 64 bytes
    addr20 = keccak_256(pub_xy)[-20:]
    csum = to_checksum_address(addr20)

    print("\n--- YOUR EVM KEY ---")
    print("Private key (hex, 64 chars):")
    print(pk_hex)
    print("[Write on paper. DO NOT PHOTOGRAPH.]\n")

    print("Address (EIP-55 checksummed):")
    print(csum)
    print("\nDone. Bring ONLY the address online. Keep the private key on PAPER.\n")

if __name__ == "__main__":
    main()
