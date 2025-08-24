# Offline-Keykit

> **Air-gapped key generation tools** for Bitcoin (BIP39/BIP84 xpub/zpub + bech32 addresses) and EVM (Ethereum/Base) with **zero third-party wallet apps**. Designed for **paper-cold** workflows: create keys on a **temporary offline OS**, write secrets on paper, bring **only public data** (xpub/zpub/addresses, EVM address) online.

* No Sparrow, no Ledger/Trezor required (watch-only apps are optional for verification).
* **Single-file Python scripts**, run **offline**, no internet, no external packages.
* **Outputs**

  * **BTC**: 12/24-word BIP39 mnemonic (+ optional BIP39 passphrase), **BIP84 account xpub + zpub**, and **first N bech32 P2WPKH addresses** (`bc1…`) at `m/84'/0'/0'/0/i`.
  * **EVM**: 32-byte private key (hex), **checksummed address**.

> ⚠️ **Important (air-gap)**: This repo ships code only. **You** must follow offline procedure. Never run the scripts on an internet-connected machine. Never store seed words in cloud docs or screenshots. **Write on paper** only.

---

## Table of Contents

* [Why this exists](#why-this-exists)
* [Threat model](#threat-model)
* [What’s included](#whats-included)
* [Workflow at a glance](#workflow-at-a-glance)
* [Step-by-step (non-technical)](#step-by-step-non-technical)
* [File integrity & sanity checks](#file-integrity--sanity-checks)
* [Files in this repo](#files-in-this-repo)
* [Auditing the scripts](#auditing-the-scripts)
* [FAQ](#faq)
* [License](#license)
* [Disclaimer](#disclaimer)

---

## Why this exists

We needed a transparent, reproducible, **auditable** way to generate keys for the RAABX bridge demo **without** installing closed-source wallet apps. Everything here is plain, readable code.

* On the **BTC** side we publish **only the xpub/zpub** online (to derive **watch-only deposit addresses**). The **mnemonic + passphrase stay offline on paper**.
* On the **EVM** side we publish **only the address** online. The private key stays on paper (or in a password manager *you* control on the host that signs).

---

## Threat model

**Protects against**

* **Compromised online dev machine** – no seed words ever typed online; only public xpub/zpub/addresses & EVM address go online.
* **GitHub compromise** – repo contains only code and public data (no secrets); `.env.sample` should list **addresses only**.
* **Password-manager compromise** – you can avoid storing BTC seed words digitally. (EVM PK may be stored if you choose.)

**Does not protect against**

* **Paper theft/duplication** – if someone copies your paper seed or EVM key, funds are gone. Use **two safes in separate locations**. Consider a **BIP39 passphrase** for BTC.
* **Carelessness** – screenshots, photos, printing over Wi-Fi, clipboard sync, etc. **Do not**.

---

## What’s included

* **`scripts/btc_bip39_tool.py`**

  * Generates **BIP39 mnemonic** (12 or 24 words) from **dice** or **system entropy**.
  * Optional **BIP39 passphrase** (“25th word”).
  * Derives **BIP84 account** `m/84'/0'/0'` (mainnet).
  * Exports **xpub** (BIP32 v=0x0488B21E) and **zpub** (SLIP-0132 v=0x04B24746).
  * Prints **first N bech32 P2WPKH addresses** (`bc1…`) at `m/84'/0'/0'/0/i`.
  * Pure Python **RIPEMD-160**, **bech32** (BIP173), **secp256k1** point math, **BIP32**.
  * Requires **`data/bip39_english.txt`** (official 2048-word list). The tool validates the wordlist length and prints its **SHA-256** so you can verify source integrity.

* **`scripts/evm_tool.py`**

  * Generates **EVM private key** (dice or system entropy) + **checksummed address**.
  * Pure Python secp256k1 + Keccak.

No third-party libraries. No network calls.

---

## Workflow at a glance

You will:

1. Boot a **Live Ubuntu** USB in **offline** mode; copy scripts via a second USB.
2. Run the tools offline; **write secrets on paper**; (optionally) save only **public xpub/zpub/addresses** to the second USB.
3. Shut down (RAM wiped).
4. Bring **only public data** online.

---

## Step-by-step (non-technical)

### 0) Prepare two USB drives

* **USB-A**: Live Ubuntu installer.
* **USB-B**: Plain FAT32 stick to shuttle the scripts **in** and public outputs **out**.

### 1) Create a one-time offline OS

1. On your normal computer, download **Ubuntu Desktop** ISO from ubuntu.com.
2. Use **balenaEtcher** (or Rufus on Windows) to write the ISO to **USB-A**.
3. **Shut down** your computer.
4. **Physically disconnect** Ethernet; disable Wi-Fi (hardware switch/BIOS if possible).
5. Boot from **USB-A**, choose **“Try Ubuntu”** (do **not** install).
6. Verify you’re **offline**: the network icon must show **disconnected**.

### 2) Move scripts into the offline OS

1. On your online machine, download this repo as ZIP or `git clone` for code review.
2. Copy `scripts/*.py` and `data/bip39_english.txt` to **USB-B**.
3. Plug **USB-B** into **offline** Ubuntu and copy to **Desktop**.

### 3) Generate **BTC** seed, **xpub/zpub**, **addresses** (offline)

Open **Terminal** (still offline) and run:

```bash
python3 ~/Desktop/btc_bip39_tool.py
```

* Choose **Dice** mode (roll a fair d6 \~100+ times) **or** **System** entropy.
* Choose **12** or **24** words (24 recommended).
* The script prints:

  * **Mnemonic** – *write on paper*.
  * **Optional BIP39 passphrase** – *write on a separate paper*.
  * **BIP84 account xpub + zpub** (`m/84'/0'/0'`).
  * **First N bech32 receive addresses** (`bc1…`) at `m/84'/0'/0'/0/i`.

> Do **not** save the mnemonic digitally. If you must persist xpub/zpub/addresses, save **only those** on **USB-B** (public data).

### 4) Generate **EVM** keypair (offline)

```bash
python3 ~/Desktop/evm_tool.py
```

* Choose **Dice** or **System** entropy.
* The script prints:

  * **Private key** (64-hex) – *write on paper (make two copies; store separately).*
  * **Checksummed address** – you can save this to **USB-B** (public).

> You may later type the EVM private key **once** into a password manager on the machine that actually signs. Never commit it to git.

### 5) Shut down (wipe RAM)

* Eject **USB-B** (containing only public outputs).
* Power off the Live Ubuntu. Remove both USBs.

### 6) Bring public data online

Plug **USB-B** into your online machine and copy **only**:

* BTC **xpub or zpub** and the derivation path `m/84'/0'/0'` (mainnet).
* EVM **address** (not the private key).
* Optional: the first few BTC addresses to cross-check in a watch-only wallet.

---

## File integrity & sanity checks

* The BTC tool validates that `data/bip39_english.txt` has **exactly 2048 words** and prints its **SHA-256**. Compare with the official BIP39 wordlist you obtained.
* Built-in test vector for RIPEMD-160 (empty string) is:
  `9c1185a5c5e9fc54612808977ee8f548b2258d31`
* Bech32 is implemented per BIP173 reference.
* Address format: **bech32 P2WPKH (v0)** `bc1…` (mainnet HRP = `bc`).

> Optional verification (watch-only): import the **zpub** into a watch-only wallet (e.g., Sparrow, Specter) and confirm the **first addresses match**. Do **not** import the mnemonic.

---

## Files in this repo

```
scripts/
  btc_bip39_tool.py   # Offline BTC tool (BIP39/BIP32/BIP84, Base58Check, bech32, RIPEMD-160) – pure Python
  evm_tool.py         # Offline EVM tool (pure-Python secp256k1 + keccak)
data/
  bip39_english.txt   # Official 2048-word BIP39 wordlist (English) – required by btc_bip39_tool
  .gitkeep            # folder placeholder
LICENSE               # Apache-2.0
README.md
```

> The BTC wordlist is a plain text file (2048 lines). The tool **refuses to run** without it and shows the file’s SHA-256 so you can audit what you pasted.

---

## Auditing the scripts

* Standalone, readable **single files**.
* **No network calls.**
* Only Python standard library; cryptography is implemented inline (secp256k1 math, PBKDF2, HMAC-SHA512, SHA-256, RIPEMD-160, bech32).
* You can compare derived addresses/xpub/zpub against known tools **without ever exposing seeds**.

---

## FAQ

**Why not Sparrow/Ledger/etc.?**
They’re great, but this kit demonstrates a **zero-dependency** workflow. You may still use Sparrow **watch-only** to verify addresses.

**Should I use a BIP39 passphrase?**
Yes, recommended. Store it **separately** from the mnemonic. Losing either loses funds.

**Is dice entropy necessary?**
It’s optional. Dice give human-verifiable randomness. System entropy on an offline OS is also fine.

**Where do I store the papers?**
Two physical locations (two safes). **Never** photograph them. Consider a **fire/water-resistant** storage.

**Mainnet vs testnet?**
This tool derives **mainnet** (`m/84'/0'/0'`, HRP=`bc`). For testnet you’d use `m/84'/1'/0'` and HRP=`tb` (the script focuses on mainnet).

**Can the BTC tool export to a text file automatically?**
By default it prints to the screen to avoid accidental disk writes of secrets. If you want an **addresses-only** export (`--out`), open an issue and we’ll add a safe, public-only writer.

---

## License

Licensed under **Apache-2.0**. See `LICENSE`.

---

## Disclaimer

This software is provided **“as is”**, without warranty of any kind. Use at your own risk. Cryptographic mistakes can be irreversible. **Read and understand the code** before using with significant value.
