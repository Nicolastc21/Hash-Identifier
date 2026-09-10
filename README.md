# 🕵️ Hash Identifier

A lightning-fast, zero-dependency Python script to identify cryptographic hashes, password formats, and non-hash encodings. 

Designed for penetration testers, CTF players, and security researchers, this tool provides instant identification with a rich, colorized terminal table—without requiring any external libraries like `rich` or `colorama`.

## ✨ Features

* **Zero Dependencies:** Built entirely with standard Python libraries (`sys`, `re`, `argparse`). Drop it into any environment and it just works.
* **Smart Detection:** Identifies ~30 formats using a mix of length analysis, prefix matching, and shape detection.
* **Non-Hash Catching:** Automatically detects JWTs and Base64 blobs so you don't waste time trying to crack encoded strings.
* **Rich CLI Output:** Renders an ANSI-colored table directly in your terminal.
* **IDE Friendly:** Can be run via command line arguments or in an interactive mode if launched directly from an IDE (like Spyder or PyCharm).
* **Scriptable:** Returns standard exit codes (`0` for success, `1` for unknown) for easy bash scripting.

## 🚀 Usage

You can run the script directly from your terminal by passing the hash as an argument:

```bash
# Run with a specific hash
python hash_identifier.py "5f4dcc3b5aa765d61d8327deb882cf99"

# Run with a modern password hash
python hash_identifier.py '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK'
