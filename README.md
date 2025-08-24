# Offline-Keykit

> **Air-gapped key generation tools** for Bitcoin (BIP39/BIP84 xpub) and EVM (Ethereum/Base) with **zero third-party wallet apps**. Designed for paper-cold workflows: create keys on a **temporary offline OS**, write secrets on paper, bring only public data (xpub/address) online.

* No Sparrow, no Ledger/Trezor needed.
* Single-file Python scripts (to be added in this repo) you run **offline**.
* Outputs:

  * **BTC**: 24-word mnemonic (+ optional BIP39 passphrase), **xpub/zpub**, and first receive addresses (BIP84 `m/84'/0'/0'`).
  * **EVM**: 32-byte private key (hex), **checksummed address**.

> ⚠️ **Important (Air-gap procedure):** This repo ships **code only**. **You** are responsible for following the offline/air-gap workflow. Never run these scripts on an internet-connected machine. Never store seeds in cloud docs or screenshots. Print/write on paper only.

---

## Table of Contents

* [Why this exists](#why-this-exists)
* [Threat model (what this protects against)](#threat-model-what-this-protects-against)
* [Tools & workflow (at a glance)](#tools--workflow-at-a-glance)
* [Step-by-step (non-technical, click-through)](#step-by-step-non-technical-click-through)
* [Files (to be added next)](#files-to-be-added-next)
* [Auditing the scripts](#auditing-the-scripts)
* [FAQ](#faq)
* [License](#license)
* [Disclaimer](#disclaimer)

---

## Why this exists

We needed a transparent, reproducible, auditable way to generate keys for the RAABX bridge demo **without** any third-party wallet UX. Everything here is plain code you can read end-to-end.

* BTC deposits in our bridge use only the **xpub** online (to derive per-user deposit addresses). The **seed + passphrase stay offline on paper**.
* The EVM operator account is generated offline; **only its address** goes online. The private key is typed once into a password manager on the machine that runs the relayer (or kept fully offline until needed).

---

## Threat model (what this protects against)

**Protects against:**

* **Compromised online dev laptop:** No seeds are ever typed there. Only public xpub/address go online.
* **GitHub compromise:** Repo never contains secrets. A `.env.sample` may contain public addresses only.
* **Password manager compromise:** You may choose to store the **EVM private key** in a password manager, but **not** your BTC seed (paper only). Your call.

**Does not protect against:**

* **Paper theft/duplication:** If someone copies your paper seed/key, they control funds. Use two separate safes. Consider a BIP39 passphrase for BTC.
* **Carelessness:** Screenshots, phone pics, printing over Wi-Fi — don’t.

---

## Tools & workflow (at a glance)

You’ll boot a **Live Linux** (Ubuntu) from USB **offline**, copy the scripts via another USB, run them once, write down the outputs on paper, then shut down (RAM wiped). Bring back **only**:

* BTC **xpub** + derivation path (`m/84'/0'/0'`)
* EVM **address**

The scripts you’ll use (added in the next commits):

* `scripts/btc_tool.py` — Generate BTC mnemonic from dice or system entropy, derive `zpub/xpub`, print first addresses (BIP84).
* `scripts/evm_tool.py` — Generate EVM private key from dice or system entropy, derive checksummed address (pure Python secp256k1 + keccak).

> The BTC tool will use the official BIP39 English wordlist (`data/bip39_english.txt`) bundled in this repo.

---

## Step-by-step (non-technical, click-through)

### 0) Prepare two USB drives

* **USB-A:** Live Ubuntu installer (we’ll boot from this).
* **USB-B:** A plain FAT32 stick to carry the Python scripts **into** the offline OS and carry public outputs **out**.

### 1) Make a one-time offline OS

1. Download **Ubuntu Desktop** ISO from ubuntu.com on your normal computer.
2. Use **balenaEtcher** (or Rufus on Windows) to write the ISO to **USB-A**.
3. **Shut down** your computer.
4. **Unplug Ethernet**; keep Wi-Fi physically off (hardware switch or BIOS).
5. Boot from **USB-A** (select it in BIOS boot menu), choose **“Try Ubuntu”** (do not install).
6. Verify you’re offline: the network icon should show **disconnected**.

### 2) Copy scripts into the offline OS

1. On your online machine, download this repo as ZIP or `git clone` (for code review).
2. Copy `scripts/*.py` and `data/bip39_english.txt` to **USB-B**.
3. Plug **USB-B** into the **offline** Ubuntu. Copy files to **Desktop**.

> *(The scripts will be added in commits after this README. See “Files” below.)*

### 3) Generate **BTC** seed and **xpub** (offline)

1. Open **Terminal** (still offline).
2. Run the BTC tool (adjust path if needed):

```bash
python3 ~/Desktop/btc_tool.py
```

3. Choose **Dice** mode (you’ll roll a six-sided die \~99 times) **or** **System entropy**.
4. The script prints:

   * **24-word mnemonic** — *write on paper*.
   * **Optional BIP39 passphrase** — *write on separate paper*.
   * **zpub/xpub** for BIP84 path `m/84'/0'/0'`.
   * First few **receive addresses** for sanity check.
5. Do **not** save the mnemonic digitally. If you must save the xpub, save it on **USB-B** in a text file (public).

### 4) Generate **EVM** private key and address (offline)

1. In **Terminal** (still offline), run:

```bash
python3 ~/Desktop/evm_tool.py
```

2. Choose **Dice** mode or **System entropy**.
3. The script prints:

   * **Private key (64-hex)** — *write on paper (two copies)*.
   * **Checksummed address** — you can save this to **USB-B** (public).
4. We keep the EVM PK on paper for maximum safety. Later, you may type it **once** into a password manager on the machine that actually signs transactions.

### 5) Shut down (wipe RAM)

1. Eject **USB-B** (now containing public xpub/address if you saved them).
2. Power off the Live Ubuntu. Remove both USBs.

### 6) Bring public data online

On your online machine, plug **USB-B** and copy **only**:

* The **BTC xpub** + path `m/84'/0'/0'`
* The **EVM address**

Use these to configure your relayer/bridge. **Never** bring mnemonics/private keys online.

---

## Files (to be added next)

```
scripts/
  btc_tool.py        # Single-file BTC offline tool (BIP39/BIP32/BIP84, Base58Check)
  evm_tool.py        # Single-file EVM offline tool (pure-Python secp256k1 + keccak)
data/
  bip39_english.txt  # Official 2048-word BIP39 wordlist (English)
LICENSE              # Apache-2.0
```

> As we add each file, we’ll include click-to-create links in this README and commit messages.

---

## Auditing the scripts

* Both scripts are **standalone** and readable end-to-end.
* **No network calls.**
* Use only Python standard library (plus embedded math/keccak where noted).
* You can diff the outputs with known wallets (watch-only, xpub/address level) to confirm derivations match BIP specs.

---

## FAQ

**Q: Why not Sparrow/Ledger/etc.?**
A: Great tools, but we wanted zero third-party apps and fully inspectable code paths. This repo demonstrates that approach.

**Q: Can I use a BIP39 passphrase for BTC?**
A: Yes, and it’s recommended. Store it on a separate paper from the mnemonic.

**Q: Is dice entropy really necessary?**
A: It’s optional. Dice give human-verifiable randomness. System entropy on an offline OS is also fine.

**Q: Where should I store the papers?**
A: Two separate physical locations (e.g., two safes). Never photograph them.

---

## License

Licensed under **Apache-2.0**. See `LICENSE`.

---

## Disclaimer

This software is provided **“as is”**, without warranty of any kind. Use at your own risk. Cryptographic mistakes can be irreversible. **Read and understand the code** before using with significant value.

---



