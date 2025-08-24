#!/usr/bin/env python3
# offline-keykit: btc_bip39_tool.py
#
# Air-gapped Bitcoin key tool:
#  - Generates or accepts a 12/24-word BIP39 mnemonic (+ optional passphrase)
#  - Derives BIP84 (P2WPKH) account xpub/zpub at m/84'/0'/0'
#  - Prints the first N bech32 receive addresses (m/84'/0'/0'/0/i)
#
# 100% offline, single-file, standard-library only. NO network, NO third-party libs.
#
# USAGE (offline):
#   python3 btc_bip39_tool.py
#
# SECURITY:
#   * Run on an offline OS.
#   * Write mnemonic & passphrase on PAPER only (two copies, separate safes).
#   * Bring back online ONLY the xpub/zpub and addresses (public).
#
# NOTES:
#   * You must also provide the BIP39 English wordlist file (see README).
#   * This script uses PBKDF2-HMAC-SHA512 (BIP39) and HMAC-SHA512/BIP32
#     with secp256k1 for derivation. Hashes via hashlib; RIPEMD-160 via hashlib.new('ripemd160').
#   * Very small, not optimized for speed — fine for single-run offline use.

import os, sys, json, hmac, hashlib, binascii

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "bip39_english.txt")
COIN = 0  # 0=Bitcoin mainnet
PURPOSE = 84  # BIP84 (P2WPKH)
ACCOUNT = 0
CHANGE = 0  # external (receive)
DEFAULT_ADDR_COUNT = 10

def die(m): print(f"[fatal] {m}"); sys.exit(1)
def ask(p):
    try: return input(p)
    except KeyboardInterrupt:
        print("\n[aborted]"); sys.exit(1)

# ---- utils ----
def sha256(b): return hashlib.sha256(b).digest()
def ripemd160(b): return hashlib.new('ripemd160', b).digest()
def h160(b): return ripemd160(sha256(b))
def hmac_sha512(key, data): return hmac.new(key, data, hashlib.sha512).digest()

# ---- BIP39 ----
def load_wordlist():
    if not os.path.exists(WORDLIST_PATH):
        die(f"Missing wordlist at {WORDLIST_PATH}. Copy english.txt into data/bip39_english.txt")
    with open(WORDLIST_PATH, "r", encoding="utf-8") as f:
        words = [w.strip() for w in f.readlines() if w.strip()]
    if len(words) != 2048: die("wordlist must have 2048 words")
    return words

def entropy_to_mnemonic(entropy: bytes, words):
    ENT = len(entropy)*8
    if ENT not in (128,160,192,224,256): die("entropy must be 128..256 bits / 16..32 bytes")
    cs = sha256(entropy)[0]
    cs_bits = ENT//32
    data = int.from_bytes(entropy, 'big')
    data = (data << cs_bits) | (cs >> (8 - cs_bits))
    nwords = (ENT + cs_bits)//11
    out = []
    for i in range(nwords):
        idx = (data >> (11*(nwords-1-i))) & 0x7FF
        out.append(words[idx])
    return " ".join(out)

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    salt = ("mnemonic" + passphrase).encode()
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), salt, 2048, dklen=64)

# ---- BIP32/84 ----
# secp256k1
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

def ser32(i): return i.to_bytes(4, 'big')
def ser256(i): return i.to_bytes(32, 'big')
def parse256(b): return int.from_bytes(b, 'big')

# BIP32 serialization
VERSION_XPRV = 0x0488ADE4
VERSION_XPUB = 0x0488B21E

def CKD_priv(kpar, cpar, i):
    if i >= 0x80000000:  # hardened
        data = b'\x00' + ser256(kpar) + ser32(i)
    else:
        x, y = _pt_mul(kpar)
        Kpar = b'\x04' + ser256(x) + ser256(y)
        data = Kpar + ser32(i)
    I = hmac_sha512(cpar, data)
    Il, Ir = I[:32], I[32:]
    ki = (parse256(Il) + kpar) % N
    if ki == 0: return CKD_priv(kpar, cpar, i+1)
    return ki, Ir

def master_from_seed(seed):
    I = hmac_sha512(b"Bitcoin seed", seed)
    Il, Ir = I[:32], I[32:]
    k = parse256(Il)
    if k == 0 or k >= N: die("invalid master key")
    return k, Ir

def base58check(b: bytes) -> str:
    # Base58Check
    ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    chk = sha256(sha256(b))[:4]
    x = int.from_bytes(b+chk, 'big')
    s = ""
    while x > 0:
        x, r = divmod(x, 58)
        s = ALPH[r] + s
    # leading zeros
    pad = 0
    for c in (b+chk):
        if c == 0: pad += 1
        else: break
    return "1"*pad + s

def ser_pub_compressed(k):
    x, y = _pt_mul(k)
    prefix = 0x02 | (y & 1)
    return bytes([prefix]) + ser256(x)

def xpub_from_priv(k, c, depth, fingerprint, childnum, version=VERSION_XPUB):
    pub = ser_pub_compressed(k)
    data = (version.to_bytes(4,'big') +
            bytes([depth]) +
            fingerprint +
            ser32(childnum) +
            c +
            pub)
    return base58check(data)

def fingerprint_from_pub(pubkey_compressed):
    # parent fingerprint = first 4 bytes of HASH160(compressed pubkey)
    return h160(pubkey_compressed)[:4]

# bech32 address
BECH32_ALPH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_polymod(values):
    GEN = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25) & 0xff
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    return [(polymod >> 5*(5-i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([BECH32_ALPH[d] for d in combined])

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
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv): return None
    return ret

def p2wpkh_bech32(pubkey_compressed, hrp="bc"):
    # HASH160(compressed pubkey)
    vh160 = h160(pubkey_compressed)
    # witness version 0 + program (20 bytes)
    data = [0] + convertbits(list(vh160), 8, 5)
    return bech32_encode(hrp, data)

def derive_account_xpub_zpub(seed, account=0, purpose=84, coin=0):
    # m → m/84' → m/84'/0' → m/84'/0'/0'
    k, c = master_from_seed(seed)
    # depth=0
    parent_pub = ser_pub_compressed(k)
    parent_fpr = fingerprint_from_pub(parent_pub)
    depth = 0; childnum = 0

    def derive_hardened(k,c, idx, depth, parent_pub):
        I = hmac_sha512(c, b'\x00' + ser256(k) + ser32(idx | 0x80000000))
        Il, Ir = I[:32], I[32:]
        ki = (parse256(Il) + k) % N
        if ki == 0: return derive_hardened(k, c, idx+1, depth, parent_pub)
        depth += 1
        fpr = fingerprint_from_pub(ser_pub_compressed(k))
        return ki, Ir, depth, fpr, idx | 0x80000000

    # m/84'
    k,c,depth,parent_fpr,childnum = derive_hardened(k,c,purpose,depth,parent_pub)
    # m/84'/0'
    k,c,depth,parent_fpr,childnum = derive_hardened(k,c,coin,depth,parent_pub)
    # m/84'/0'/0'
    k,c,depth,parent_fpr,childnum = derive_hardened(k,c,0,depth,parent_pub)

    # xpub serialization for account (depth 3)
    pub = ser_pub_compressed(k)
    acc_fpr = fingerprint_from_pub(pub)  # parent fingerprint for next level
    xpub = xpub_from_priv(k, c, depth, parent_fpr, childnum, VERSION_XPUB)

    # zpub (BIP84): same payload as xpub but with version bytes 0x04b24746
    VERSION_ZPUB = 0x04B24746
    zpub = base58check(VERSION_ZPUB.to_bytes(4,'big') + xpub_decode_payload(xpub)[4:])
    return k, c, depth, parent_fpr, childnum, xpub, zpub

def xpub_decode_payload(xpub: str) -> bytes:
    # decode base58check to get raw payload
    ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    x = 0
    for ch in xpub:
        if ch not in ALPH: continue
        x = x*58 + ALPH.index(ch)
    raw = x.to_bytes((x.bit_length()+7)//8,'big')
    # re-add leading zeros
    pad = 0
    for ch in xpub:
        if ch == '1': pad += 1
        else: break
    raw = b'\x00'*pad + raw
    # strip checksum
    if len(raw) < 4: die("xpub too short")
    payload, chk = raw[:-4], raw[-4:]
    if sha256(sha256(payload))[:4] != chk: die("xpub checksum fail")
    return payload

def derive_receive_addresses(seed, count=10, hrp="bc"):
    # derive account node m/84'/0'/0' and then non-hardened child m/84'/0'/0'/0/i
    k, c = master_from_seed(seed)
    # m/84'
    k,c,_,_,_ = CKD_priv(k,c,PURPOSE | 0x80000000)
    # m/84'/0'
    k,c,_,_,_ = CKD_priv(k,c,COIN | 0x80000000)
    # m/84'/0'/0'
    k,c,_,_,_ = CKD_priv(k,c,0 | 0x80000000)
    # /0 external
    k0, c0 = CKD_priv(k,c,CHANGE)
    addrs = []
    for i in range(count):
        ki, ci = CKD_priv(k0,c0,i)
        pubc = ser_pub_compressed(ki)
        addr = p2wpkh_bech32(pubc, hrp=hrp)
        addrs.append(addr)
    return addrs

def main():
    print("=== offline-keykit :: btc_bip39_tool (air-gapped) ===")
    words = load_wordlist()

    print("\nChoose:")
    print("  1) Generate 24-word mnemonic (recommended)")
    print("  2) Generate 12-word mnemonic")
    print("  3) Enter existing mnemonic")
    choice = ask("Select [1/2/3]: ").strip()

    if choice == "3":
        mnemonic = ask("\nPaste mnemonic (space-separated words): ").strip()
    else:
        bits = 256 if choice == "1" else 128
        entropy = os.urandom(bits//8)
        mnemonic = entropy_to_mnemonic(entropy, words)

    use_pp = ask("\nAdd a BIP39 passphrase? Highly recommended. [y/N]: ").strip().lower() == "y"
    passphrase = ""
    if use_pp:
        passphrase = ask("Enter passphrase (case-sensitive; WRITE ON PAPER): ")

    seed = mnemonic_to_seed(mnemonic, passphrase)

    # xpub/zpub and first addresses
    _,_,depth, fpr, childnum, xpub, zpub = derive_account_xpub_zpub(seed, ACCOUNT, PURPOSE, COIN)
    addrs = derive_receive_addresses(seed, count=DEFAULT_ADDR_COUNT, hrp="bc")

    print("\n--- YOUR BTC SECRETS (WRITE ON PAPER) ---")
    print(mnemonic)
    if use_pp:
        print("\n[BIP39 passphrase: WRITE ON SEPARATE PAPER]")
    print("\n--- PUBLIC (BRING ONLINE) ---")
    print("Derivation: m/84'/0'/0'  (BIP84 P2WPKH)")
    print("xpub:", xpub)
    print("zpub:", zpub)
    print("\nFirst receive addresses (m/84'/0'/0'/0/i):")
    for i, a in enumerate(addrs):
        print(f"  {i}: {a}")
    print("\nDone. Bring ONLY xpub/zpub + addresses online. Keep mnemonic/passphrase PAPER-COLD.\n")

if __name__ == "__main__":
    main()
