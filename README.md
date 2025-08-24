# offline-keykit

> **Air-gapped key generation tools** for Bitcoin (BIP39/BIP84 xpub) and EVM (Ethereum/Base) with **zero third-party wallet apps**. Designed for paper-cold workflows: create keys on a **temporary offline OS**, write secrets on paper, bring only public data (xpub/address) online.

- No Sparrow, no Ledger/Trezor needed.
- Single-file Python scripts (to be added in this repo) you run **offline**.
- Outputs:
  - **BTC**: 24-word mnemonic (+ optional BIP39 passphrase), **xpub/zpub**, and first receive addresses (BIP84 `m/84'/0'/0'`).
  - **EVM**: 32-byte private key (hex), **checksummed address**.

> ⚠️ This repo ships **code only**. **You** are responsible for following the air-gap procedure. Never run these scripts on an internet-connected machine. Never store seeds in cloud docs or screenshots. Print/write on paper only.

---

## Why this exists

We needed a transparent, reproducible, auditable way to generate keys for the RAABX bridge demo **without** any third-party wallet UX. Everything here is plain code you can read end-to-end.

- BTC deposits in our bridge use only the **xpub** online (to derive per-user deposit addresses). The **seed + passphrase stay offline on paper**.
- The EVM operator account is generated offline; **only its address** goes online. The private key is typed once into a password manager on the machine that runs the relayer (or kept fully offline until needed).

---

## Threat model (what this protects against)

- **Compromised online dev laptop**: No seeds are ever typed there. Only public xpub/address go online.
- **GitHub compromise**: Repo never contains secrets. A `.env.sample` may contain public addresses only.
- **Password manager compromise**: You may choose to store the **EVM private key** in a password manager, but **not** your BTC seed (paper only). Your call.

What it does **not** protect against:

- **Paper theft/duplication**: If someone copies your paper seed/key, they control funds. Use two separate safes. Consider a BIP39 passphrase for BTC.
- **Carelessness**: Screenshots, phone pics, printing over Wi-Fi — don’t.

---

## Tools & workflow (at a glance)

You’ll boot a **Live Linux** (Ubuntu) from USB **offline**, copy the scripts via another USB, run them once, write down the outputs on paper, then shut down (RAM wiped). Bring back **only**:

- BTC **xpub** + derivation path (`m/84'/0'/0'`)
- EVM **address**

The scripts you’ll use (added in the next commits):

- `scripts/btc_tool.py` — Generate BTC mnemonic from dice or system entropy, derive `zpub/xpub`, print first addresses (BIP84).
- `scripts/evm_tool.py` — Generate EVM private key from dice or system entropy, derive checksummed address (pure Python secp256k1 + keccak).

> The BTC tool will use the official BIP39 English wordlist (`data/bip39_english.txt`) bundled in this repo.

---

## Step-by-step (non-technical, click-through)

### 0) Prepare two USB drives
- **USB-A**: Live Ubuntu installer (we’ll boot from this).
- **USB-B**: A plain FAT32 stick to carry the Python scripts **into** the offline OS and carry public outputs **out**.

### 1) Make a one-time offline OS
1. Download **Ubuntu Desktop** ISO from ubuntu.com on your normal computer.
2. Use **balenaEtcher** (or Rufus on Windows) to write the ISO to **USB-A**.
3. **Shut down** your computer.
4. **Unplug Ethernet**; keep Wi-Fi physically off (hardware switch or BIOS).
5. Boot from **USB-A** (select it in BIOS boot menu), choose **“Try Ubuntu”** (do not install).
6. Verify you’re offline: network icon should show **disconnected**.

### 2) Copy scripts into the offline OS
1. On your online machine, download this repo as ZIP or `git clone` (for code review).
2. Copy `scripts/*.py` and `data/bip39_english.txt` to **USB-B**.
3. Plug **USB-B** into the **offline** Ubuntu. Copy files to **Desktop**.

*(The scripts will be added in commits after this README. See “Files” below.)*

### 3) Generate **BTC** seed and **xpub** (offline)
1. Open Terminal (offline).
2. Run the BTC tool:

   ```bash
   python3 ~/Desktop/btc_tool.py
