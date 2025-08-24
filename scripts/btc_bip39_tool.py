#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Offline BTC BIP39/BIP32/BIP84 tool (mnemonic + passphrase + zpub + bech32 P2WPKH)
# Standard library only. No network. Pure-Python secp256k1 + bech32 + base58.
#
# Outputs (safe to take online):
#  - zpub (BIP84, account m/84'/0'/0')
#  - xpub (same node, legacy version bytes for compatibility)
#  - first N receive addresses (m/84'/0'/0'/0/i), bech32 (bc1…)
#
# Secrets (NEVER take online):
#  - 12/24-word mnemonic
#  - optional BIP39 passphrase
#
# Copyright (c) 2025 RAABX. Apache-2.0

import os, sys, hmac, hashlib, binascii, unicodedata, secrets, getpass, textwrap
from typing import Tuple, Optional, List

# --------- Utils ---------
def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def ripemd160(b: bytes) -> bytes:
    h = hashlib.new('ripemd160'); h.update(b); return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

def int_to_big_endian(i: int, length: int) -> bytes:
    return i.to_bytes(length, 'big')

def big_endian_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def ser32(i: int) -> bytes:
    return int_to_big_endian(i, 4)

def ser256(i: int) -> bytes:
    return int_to_big_endian(i, 32)

def parse256(b: bytes) -> int:
    return big_endian_to_int(b)

# --------- Base58Check (for xpub/zpub) ---------
_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58encode(b: bytes) -> bytes:
    n = int.from_bytes(b, 'big')
    out = bytearray()
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_ALPHABET[rem])
    # leading zeros
    for byte in b:
        if byte == 0:
            out.append(_ALPHABET[0])
        else:
            break
    return bytes(out[::-1])

def base58check(version: bytes, payload: bytes) -> str:
    data = version + payload
    checksum = sha256(sha256(data))[:4]
    return b58encode(data + checksum).decode()

# --------- Bech32 (BIP-173) ---------
# Minimal bech32 + segwit v0 encoder
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
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
    return hrp + '1' + ''.join([BECH32_CHARSET[d] for d in combined])

def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
    acc = 0; bits = 0; ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or value >> frombits:
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def encode_p2wpkh(pubkey_compressed: bytes, hrp='bc') -> str:
    # witness version 0 + program = HASH160(pubkey)
    prog = hash160(pubkey_compressed)
    five = convertbits(prog, 8, 5)
    data = [0] + five
    return bech32_encode(hrp, data)

# --------- secp256k1 (pure Python) ---------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx, Gy)

def inverse_mod(a: int, n: int = P) -> int:
    return pow(a, -1, n)

def is_on_curve(Pt: Optional[Tuple[int,int]]) -> bool:
    if Pt is None: return True
    x,y = Pt
    return (y*y - (x*x*x + A*x + B)) % P == 0

def point_add(Pt: Optional[Tuple[int,int]], Qt: Optional[Tuple[int,int]]) -> Optional[Tuple[int,int]]:
    if Pt is None: return Qt
    if Qt is None: return Pt
    x1,y1 = Pt; x2,y2 = Qt
    if x1 == x2 and y1 != y2: return None
    if Pt == Qt:
        m = (3*x1*x1) * inverse_mod(2*y1, P) % P
    else:
        m = (y2 - y1) * inverse_mod((x2 - x1) % P, P) % P
    x3 = (m*m - x1 - x2) % P
    y3 = (m*(x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k: int, Pt: Optional[Tuple[int,int]]) -> Optional[Tuple[int,int]]:
    if k % N == 0 or Pt is None: return None
    if k < 0: return scalar_mult(-k, (Pt[0], (-Pt[1]) % P))
    result = None
    addend = Pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def serP(Pt: Tuple[int,int], compressed=True) -> bytes:
    x,y = Pt
    if not compressed:
        return b'\x04' + ser256(x) + ser256(y)
    return (b'\x02' if (y % 2 == 0) else b'\x03') + ser256(x)

# --------- BIP39 ---------
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST_PATH = os.path.join(THIS_DIR, "..", "data", "bip39_english.txt")

def load_wordlist() -> List[str]:
    with open(WORDLIST_PATH, "r", encoding="utf-8") as f:
        words = [w.strip() for w in f.readlines()]
    if len(words) != 2048:
        raise RuntimeError("BIP39 wordlist must have 2048 words")
    return words

def entropy_to_mnemonic(entropy: bytes, words: List[str]) -> str:
    ENT = len(entropy) * 8
    CS = ENT // 32
    hash_ = sha256(entropy)
    checksum_bits = big_endian_to_int(hash_) >> (256 - CS)
    ent_int = big_endian_to_int(entropy)
    acc = (ent_int << CS) | checksum_bits
    num_words = (ENT + CS) // 11
    out = []
    for i in range(num_words):
        idx = (acc >> (11*(num_words-1-i))) & 0x7FF
        out.append(words[idx])
    return ' '.join(out)

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    mnemonic = unicodedata.normalize("NFKD", mnemonic.strip())
    salt = "mnemonic" + unicodedata.normalize("NFKD", passphrase)
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), salt.encode(), 2048)

# --------- BIP32 ---------
BIP32_HARDEN = 0x80000000

class Node:
    def __init__(self, k: int, c: bytes, depth: int, parent_fpr: bytes, child_num: int):
        self.k = k            # private key int
        self.c = c            # chain code 32 bytes
        self.depth = depth
        self.parent_fpr = parent_fpr  # 4 bytes
        self.child_num = child_num    # 4 bytes

    @property
    def P(self) -> Tuple[int,int]:
        return scalar_mult(self.k, G)

    @property
    def pubkey_compressed(self) -> bytes:
        return serP(self.P, compressed=True)

    @property
    def fingerprint(self) -> bytes:
        return hash160(self.pubkey_compressed)[:4]

def master_from_seed(seed: bytes) -> Node:
    I = hmac_sha512(b"Bitcoin seed", seed)
    k = parse256(I[:32]) % N
    if k == 0: raise RuntimeError("Invalid master key")
    c = I[32:]
    return Node(k, c, depth=0, parent_fpr=b"\x00\x00\x00\x00", child_num=0)

def CKD_priv(node: Node, index: int) -> Node:
    if index & BIP32_HARDEN:
        data = b"\x00" + ser256(node.k) + ser32(index)
    else:
        data = node.pubkey_compressed + ser32(index)
    I = hmac_sha512(node.c, data)
    IL, IR = I[:32], I[32:]
    ki = (parse256(IL) + node.k) % N
    if parse256(IL) >= N or ki == 0:
        # very unlikely, skip to next index (spec)
        return CKD_priv(node, index+1)
    return Node(ki, IR, depth=node.depth+1, parent_fpr=node.fingerprint, child_num=index)

def derive_path(node: Node, path: str) -> Node:
    """
    path like: m/84'/0'/0'/0/0
    """
    if not path.startswith("m/"): raise ValueError("Path must start with m/")
    cur = node
    for p in path.lstrip("m/").split("/"):
        if p == "": continue
        hard = p.endswith("'")
        idx = int(p[:-1]) if hard else int(p)
        if hard: idx |= BIP32_HARDEN
        cur = CKD_priv(cur, idx)
    return cur

# --------- SLIP-132 (zpub) + xpub serialization ---------
VER_XPUB = bytes.fromhex("0488B21E")   # xpub
VER_ZPUB = bytes.fromhex("04B24746")   # zpub (BIP84 mainnet)

def serialize_xpub(version: bytes, node: Node) -> str:
    depth = int_to_big_endian(node.depth, 1)
    child = ser32(node.child_num)
    data = (version + depth + node.parent_fpr + child + node.c + node.pubkey_compressed)
    return base58check(version, depth + node.parent_fpr + child + node.c + node.pubkey_compressed)

# --------- Main derivation helpers ---------
PURPOSE = 84
COIN_TYPE = 0           # 0 = mainnet
ACCOUNT = 0
CHANGE_EXTERNAL = 0     # receive chain

DEFAULT_ADDR_COUNT = 5

def make_account_node(master: Node) -> Node:
    # m / 84' / 0' / 0'
    return derive_path(master, f"m/{PURPOSE}'/{COIN_TYPE}'/{ACCOUNT}'")

def zpub_xpub_from_account(acc: Node) -> Tuple[str, str]:
    # acc.depth == 3; parent_fpr is fingerprint of m/84'/0'
    # serialize with zpub and xpub version bytes
    # (We reuse the same payload but swap version bytes for compatibility)
    depth = int_to_big_endian(acc.depth, 1)
    child = ser32(acc.child_num)
    payload = depth + acc.parent_fpr + child + acc.c + acc.pubkey_compressed
    zpub = base58check(VER_ZPUB, payload)
    xpub = base58check(VER_XPUB, payload)
    return zpub, xpub

def derive_receive_addresses(seed: bytes, count: int = DEFAULT_ADDR_COUNT, hrp: str = "bc") -> Tuple[str, str, List[str]]:
    master = master_from_seed(seed)
    acc = make_account_node(master)                     # m/84'/0'/0'
    zpub, xpub = zpub_xpub_from_account(acc)
    # external chain m/84'/0'/0'/0
    ext = CKD_priv(acc, CHANGE_EXTERNAL)
    addrs = []
    for i in range(count):
        ch = CKD_priv(ext, i)
        addr = encode_p2wpkh(ch.pubkey_compressed, hrp=hrp)
        addrs.append(addr)
    return zpub, xpub, addrs

# --------- Mnemonic generation ---------
def gen_entropy(bits: int) -> bytes:
    if bits not in (128, 256):
        raise ValueError("bits must be 128 or 256")
    return secrets.token_bytes(bits // 8)

def dice_entropy(num_rolls: int = 99) -> bytes:
    print("\nDice mode selected. Roll a six-sided die ~99 times.")
    print("Enter the sequence as digits 1-6 (spaces optional). Example: 163245... (press Enter when done)")
    s = input("Dice rolls: ").strip().replace(" ", "")
    if not s or any(ch not in "123456" for ch in s):
        raise ValueError("Invalid dice input")
    # Map 1..6 into bits (base-6 to bytes). Simpler: hash the raw string to 32 bytes.
    return sha256(s.encode())

def choose_mnemonic(words: List[str]) -> Tuple[str, str]:
    print("\nChoose:\n  1) Generate 24-word mnemonic (recommended)\n  2) Generate 12-word mnemonic\n  3) Enter existing mnemonic")
    sel = input("Select [1/2/3]: ").strip()
    if sel == "1":
        ent = gen_entropy(256)
        mnemonic = entropy_to_mnemonic(ent, words)
    elif sel == "2":
        ent = gen_entropy(128)
        mnemonic = entropy_to_mnemonic(ent, words)
    elif sel == "3":
        print("\nPaste your mnemonic (exact words, spaces between them):")
        mnemonic = input("> ").strip()
    else:
        print("Invalid selection."); sys.exit(1)

    use_pp = input("\nAdd a BIP39 passphrase? Highly recommended. [y/N]: ").strip().lower() == "y"
    passphrase = ""
    if use_pp:
        passphrase = getpass.getpass("Enter passphrase (case-sensitive; WRITE ON PAPER): ")
        # simple confirmation
        passphrase2 = getpass.getpass("Re-enter passphrase: ")
        if passphrase2 != passphrase:
            print("Passphrases do not match."); sys.exit(1)

    print("\n=== WRITE THESE ON PAPER (NEVER DIGITIZE) ===")
    print("Mnemonic:\n" + textwrap.fill(mnemonic, width=88))
    if use_pp:
        print("\nBIP39 passphrase:  (write on separate paper)")
    else:
        print("\n(No BIP39 passphrase)")
    print("============================================\n")
    return mnemonic, passphrase

# --------- CLI ---------
def main():
    # Load wordlist
    try:
        words = load_wordlist()
    except Exception as e:
        print("Error loading BIP39 wordlist:", e)
        print("Expected at:", WORDLIST_PATH)
        sys.exit(1)

    mnemonic, passphrase = choose_mnemonic(words)
    seed = mnemonic_to_seed(mnemonic, passphrase)

    # derive zpub/xpub and first addresses
    zpub, xpub, addrs = derive_receive_addresses(seed, count=DEFAULT_ADDR_COUNT, hrp="bc")

    print("Account (BIP84, m/84'/0'/0'):")
    print("  zpub:", zpub)
    print("  xpub:", xpub)
    print("\nFirst receive addresses (bech32, m/84'/0'/0'/0/i):")
    for i, a in enumerate(addrs):
        print(f"  [{i}] {a}")

    print("\nSAFE TO TAKE ONLINE:")
    print("  - zpub")
    print("  - xpub (compat)")
    print("  - addresses above")
    print("\nNEVER TAKE ONLINE:")
    print("  - mnemonic")
    print("  - BIP39 passphrase\n")

if __name__ == "__main__":
    main()
