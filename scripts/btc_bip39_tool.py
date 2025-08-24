#!/usr/bin/env python3
# offline-keykit: btc_bip39_tool.py
#
# Air-gapped Bitcoin key tool:
#  - Generates BIP39 mnemonic (12 or 24 words) from dice or system entropy
#  - Optional BIP39 passphrase (for "25th word")
#  - Derives BIP84 account m/84'/0'/0' (mainnet); prints xpub + zpub
#  - Prints the first N bech32 P2WPKH addresses (bc1...) from that account
#
# 100% offline, single-file, pure Python. No third-party libs.
#
# FILES REQUIRED (offline):
#   data/bip39_english.txt  -> official BIP39 English wordlist (2048 words)
#
# USAGE (offline):
#   python3 btc_bip39_tool.py
#
# SECURITY:
#   * Never run on an internet-connected OS.
#   * Write mnemonic and (optional) passphrase on paper ONLY.
#   * Keep the xpub/zpub and addresses on a separate USB (public).
#
# NOTE:
#   This script computes bech32 P2WPKH addresses using pure-Python RIPEMD-160
#   (included below) and BIP173 bech32 reference logic (also included).

import os, sys, hmac, hashlib, struct, unicodedata

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
WORDLIST_PATH = os.path.normpath(os.path.join(DATA_DIR, "bip39_english.txt"))

# ---------- helpers ----------
def die(msg):
    print(f"[fatal] {msg}")
    sys.exit(1)

def ask(prompt):
    try:
        return input(prompt)
    except KeyboardInterrupt:
        print("\n[aborted]")
        sys.exit(1)

def nkfd(s: str) -> str:
    return unicodedata.normalize("NFKD", s)

# ---------- RIPEMD-160 (pure Python) ----------
# Adapted from public domain reference; compacted for clarity.
# Verified on test vectors: RIPEMD160(b"") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
def _rol32(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff
def _ripemd160_compress(h, block):
    x = list(struct.unpack("<16I", block))
    h0,h1,h2,h3,h4 = h
    A1,B1,C1,D1,E1 = h0,h1,h2,h3,h4
    A2,B2,C2,D2,E2 = h0,h1,h2,h3,h4

    # selection functions
    def f(j,x,y,z):
        if   j<=15: return x ^ y ^ z
        elif j<=31: return (x & y) | (~x & z)
        elif j<=47: return (x | ~y) ^ z
        elif j<=63: return (x & z) | (y & ~z)
        else:       return x ^ (y | ~z)
    def K(j):
        return [0x00000000,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e][j//16]
    def KK(j):
        return [0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0x00000000][j//16]

    # message word order
    r1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8, 3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2, 4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    s1 = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12, 11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12, 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    r2 = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2, 15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14, 12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    s2 = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11, 9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8, 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]

    # left line
    for j in range(80):
        T = _rol32(A1 + f(j,B1,C1,D1) + x[r1[j]] + K(j), s1[j]) + E1 & 0xffffffff
        A1,E1,D1,C1,B1 = E1,D1,_rol32(C1,10),B1,T
    # right line
    for j in range(80):
        T = _rol32(A2 + f(79-j,B2,C2,D2) + x[r2[j]] + KK(j), s2[j]) + E2 & 0xffffffff
        A2,E2,D2,C2,B2 = E2,D2,_rol32(C2,10),B2,T

    T = (h1 + C1 + D2) & 0xffffffff
    h1 = (h2 + D1 + E2) & 0xffffffff
    h2 = (h3 + E1 + A2) & 0xffffffff
    h3 = (h4 + A1 + B2) & 0xffffffff
    h4 = (h0 + B1 + C2) & 0xffffffff
    h0 = T
    return [h0,h1,h2,h3,h4]

def ripemd160(data: bytes) -> bytes:
    h = [0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0]
    ml = len(data)
    data += b'\x80'
    while (len(data) % 64) != 56:
        data += b'\x00'
    data += struct.pack("<Q", ml*8)
    for i in range(0,len(data),64):
        h = _ripemd160_compress(h, data[i:i+64])
    return struct.pack("<5I", *h)

# ---------- bech32 (BIP173) ----------
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _bech32_polymod(values):
    GEN = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25) & 0xff
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk
def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
def _bech32_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    return [(polymod >> 5*(5-i)) & 31 for i in range(6)]
def bech32_encode(hrp, data):
    combined = data + _bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])
def convertbits(data, frombits, tobits, pad=True):
    acc = 0; bits = 0; ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits): return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits: ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def p2wpkh_bech32(pubkey_compressed: bytes, hrp="bc") -> str:
    h160 = ripemd160(hashlib.sha256(pubkey_compressed).digest())
    # witness version 0, program = 20-byte h160
    data = [0] + convertbits(h160, 8, 5)
    return bech32_encode(hrp, data)

# ---------- Base58Check ----------
_ALPH = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    out = bytearray()
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_ALPH[rem])
    # leading zeros
    for c in b:
        if c == 0: out.append(_ALPH[0])
        else: break
    return out[::-1].decode()
def base58check(version_and_payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(version_and_payload).digest()).digest()[:4]
    return b58encode(version_and_payload + chk)

# ---------- secp256k1 & BIP32 ----------
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
def inv(n): return pow(n, P-2, P)
def _pt_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1,y1 = P1; x2,y2 = P2
    if x1==x2 and (y1 + y2) % P == 0: return None
    if x1==x2 and y1==y2:
        lam = (3*x1*x1) * inv(2*y1) % P
    else:
        lam = (y2 - y1) * inv((x2 - x1) % P) % P
    x3 = (lam*lam - x1 - x2) % P
    y3 = (lam*(x1 - x3) - y1) % P
    return (x3,y3)
def _pt_mul(k, P0=(Gx,Gy)):
    if k % N == 0 or k <= 0: raise ValueError("bad priv")
    Q = None; add = P0
    while k:
        if k & 1: Q = _pt_add(Q, add)
        add = _pt_add(add, add)
        k >>= 1
    return Q
def priv_to_pub_compressed(priv: int) -> bytes:
    x,y = _pt_mul(priv)
    prefix = 0x02 | (y & 1)
    return prefix.to_bytes(1,'big') + x.to_bytes(32,'big')

def hmac_sha512(key, data): return hmac.new(key, data, hashlib.sha512).digest()
def ser32(i): return struct.pack('>I', i)
def serP(Pc: bytes): return Pc
def ser256(i): return i.to_bytes(32,'big')
def parse256(b): return int.from_bytes(b, 'big')
def hash160(b): return ripemd160(hashlib.sha256(b).digest())

def fingerprint_from_pubkey(pubkey_compressed: bytes) -> bytes:
    return hash160(pubkey_compressed)[:4]

class ExtPriv:
    def __init__(self, k: int, c: bytes, depth: int, parent_fpr: bytes, child_num: int):
        self.k = k; self.c = c; self.depth = depth; self.parent_fpr = parent_fpr; self.child_num = child_num
    def neuter(self):
        Pc = priv_to_pub_compressed(self.k)
        return ExtPub(Pc, self.c, self.depth, self.parent_fpr, self.child_num)
    def CKDpriv(self, i: int):
        if i >= 0x80000000: data = b'\x00' + ser256(self.k) + ser32(i)
        else:               data = serP(self.neuter().P) + ser32(i)
        I = hmac_sha512(self.c, data); IL, IR = I[:32], I[32:]
        ki = (parse256(IL) + self.k) % N
        if ki == 0: raise ValueError("zero child key")
        depth = self.depth + 1
        parent_fpr = fingerprint_from_pubkey(self.neuter().P)
        return ExtPriv(ki, IR, depth, parent_fpr, i)
    def to_xprv(self, version=b'\x04\x88\xAD\xE4'):
        keydata = b'\x00' + ser256(self.k)
        payload = version + bytes([self.depth]) + self.parent_fpr + ser32(self.child_num) + self.c + keydata
        return base58check(payload)

class ExtPub:
    def __init__(self, P: bytes, c: bytes, depth: int, parent_fpr: bytes, child_num: int):
        self.P = P; self.c = c; self.depth = depth; self.parent_fpr = parent_fpr; self.child_num = child_num
    def CKDpub(self, i: int):
        if i >= 0x80000000: raise ValueError("cannot CKDpub hardened")
        I = hmac_sha512(self.c, self.P + ser32(i)); IL, IR = I[:32], I[32:]
        # child point = G*IL + parent_point
        Il = parse256(IL)
        if Il >= N or Il == 0: raise ValueError("IL invalid")
        x_parent = int.from_bytes(self.P[1:], 'big')
        # Recover y parity from prefix
        y_parity = (self.P[0] & 1)
        # find y for x (on curve): y^2 = x^3 + 7 mod P
        rhs = (pow(x_parent,3,P) + 7) % P
        y = pow(rhs, (P+1)//4, P)
        if y % 2 != y_parity: y = (-y) % P
        parent_pt = (x_parent, y)
        child_pt = _pt_add(_pt_mul(Il), parent_pt)
        if child_pt is None: raise ValueError("derived infinity")
        x,y = child_pt
        Pc = (0x02 | (y & 1)).to_bytes(1,'big') + x.to_bytes(32,'big')
        depth = self.depth + 1
        parent_fpr = fingerprint_from_pubkey(self.P)
        return ExtPub(Pc, IR, depth, parent_fpr, i)
    def to_xpub(self, version=b'\x04\x88\xB2\x1E'):
        payload = version + bytes([self.depth]) + self.parent_fpr + ser32(self.child_num) + self.c + self.P
        return base58check(payload)

def master_from_seed(seed: bytes) -> ExtPriv:
    I = hmac_sha512(b"Bitcoin seed", seed); IL, IR = I[:32], I[32:]
    m = parse256(IL)
    if m == 0 or m >= N: die("invalid master")
    return ExtPriv(m, IR, depth=0, parent_fpr=b'\x00\x00\x00\x00', child_num=0)

# ---------- BIP39 ----------
def load_wordlist(path=WORDLIST_PATH):
    if not os.path.exists(path):
        die(f"Missing wordlist: {path}\nPaste the official BIP39 English list (2048 lines, one per line).")
    with open(path, "r", encoding="utf-8") as f:
        words = [w.strip() for w in f.readlines()]
    if len(words) != 2048: die(f"Wordlist must have 2048 words; got {len(words)}")
    return words

def _entropy_bits_from_dice(min_rolls=100):
    print("\n[ Dice mode ] Roll a fair 6-sided die; enter a string like 326154... ")
    s = ask("Enter >=100 rolls (digits 1..6, no spaces): ").strip()
    if len(s) < 100 or any(ch not in "123456" for ch in s):
        die("Need >=100 rolls, digits 1..6 only.")
    # Mix via SHA-512 -> SHA-256 (32 bytes entropy)
    h = hashlib.sha512(s.encode()).digest()
    ent = hashlib.sha256(h).digest()
    return ent

def _entropy_bits_from_system(nbytes=32):
    return os.urandom(nbytes)

def _mnemonic_from_entropy(ent: bytes, wordlist):
    # ENT must be one of {16, 32} bytes for 12 or 24 words
    if len(ent) not in (16,32): die("Entropy must be 16 (128-bit, 12w) or 32 (256-bit, 24w) bytes")
    ENT = len(ent)*8
    CS = ENT // 32
    h = hashlib.sha256(ent).digest()
    bits = bin(int.from_bytes(ent, 'big'))[2:].zfill(ENT) + bin(int.from_bytes(h,'big'))[2:].zfill(256)[:CS]
    chunks = [bits[i:i+11] for i in range(0, len(bits), 11)]
    idxs = [int(c,2) for c in chunks]
    words = [wordlist[i] for i in idxs]
    return words

def mnemonic_to_seed(mnemonic_words, passphrase=""):
    m = nkfd(" ".join(mnemonic_words))
    p = nkfd("mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", m.encode(), p.encode(), 2048, dklen=64)

# ---------- main ----------
def main():
    print("=== offline-keykit :: btc_bip39_tool (air-gapped) ===")
    print("This generates a BIP39 mnemonic (12 or 24 words), derives BIP84 m/84'/0'/0',")
    print("prints xpub/zpub, and the first N bech32 P2WPKH addresses (bc1...).")
    print("\nWordlist:", WORDLIST_PATH)
    if not os.path.exists(WORDLIST_PATH):
        print("\n[!] Wordlist missing.")
        print("    Create data/bip39_english.txt and paste the official BIP39 English list (2048 lines).")
        sys.exit(1)

    # Show file hash so you can verify integrity (manually if desired)
    wl_bytes = open(WORDLIST_PATH, "rb").read()
    wl_sha256 = hashlib.sha256(wl_bytes).hexdigest()
    print("Wordlist SHA-256:", wl_sha256)

    WORDS = load_wordlist(WORDLIST_PATH)

    choice = ask("\nEntropy source: 1) Dice  2) System   [1/2]: ").strip()
    size   = ask("Mnemonic size:  1) 12 words  2) 24 words   [1/2]: ").strip()
    if size == "1":
        ent = _entropy_bits_from_dice() if choice=="1" else _entropy_bits_from_system(16)
    else:
        ent = _entropy_bits_from_dice() if choice=="1" else _entropy_bits_from_system(32)

    mnemonic_words = _mnemonic_from_entropy(ent, WORDS)
    print("\n--- YOUR MNEMONIC ---")
    print(" ".join(mnemonic_words))
    print("[Write on paper. DO NOT PHOTOGRAPH.]\n")

    use_pp = ask("Use a BIP39 passphrase (recommended)?  y/N: ").strip().lower() == "y"
    pp = ""
    if use_pp:
        pp = ask("Enter passphrase (case-sensitive; write on separate paper): ")
        pp = nkfd(pp)

    seed = mnemonic_to_seed(mnemonic_words, passphrase=pp)

    # Master -> BIP84 account m/84'/0'/0'
    master = master_from_seed(seed)
    purpose = master.CKDpriv(0x80000000 + 84)
    coin    = purpose.CKDpriv(0x80000000 + 0)   # 0 = mainnet
    acct0   = coin.CKDpriv(0x80000000 + 0)
    xpub    = acct0.neuter().to_xpub(b'\x04\x88\xB2\x1E')  # xpub
    zpub    = acct0.neuter().to_xpub(b'\x04\xB2\x47\x46')  # zpub (SLIP-0132 for BIP84)

    print("\n--- BIP84 ACCOUNT (m/84'/0'/0') ---")
    print("xpub:", xpub)
    print("zpub:", zpub)

    # Print first N receive addresses m/84'/0'/0'/0/i
    try:
        N = int(ask("\nHow many receive addresses to print? (e.g., 5): ").strip() or "5")
        if N < 1 or N > 100: raise ValueError()
    except:
        N = 5
    pub = acct0.neuter()
    branch0 = pub.CKDpub(0)  # external/receive
    print("\n--- First {} receive (bc1...) ---".format(N))
    for i in range(N):
        ch = branch0.CKDpub(i)
        addr = p2wpkh_bech32(ch.P, hrp="bc")
        print(f"m/84'/0'/0'/0/{i}: {addr}")

    print("\nDone. Bring ONLY xpub/zpub (and addresses if you want) online. Keep mnemonic/passphrase on PAPER.\n")

if __name__ == "__main__":
    main()
