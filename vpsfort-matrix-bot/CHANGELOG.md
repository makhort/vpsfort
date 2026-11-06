# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.3.1 - 2026-11-06

Fixes.

- The package's question whether to replace `config.env` is asked on the terminal itself, so it shows under dnf too: dnf held it back with the install's output, and the install looked hung for the question's minute before keeping the config.
- vodozemac 0.11.2 (RUSTSEC-2026-0445, RUSTSEC-2026-0451): 0.11.1 left copies of Olm root and chain keys in freed memory after each ratchet step, and its cryptographic dependencies no longer zeroized their secrets. Someone able to read the bot's memory (a core dump, swapped-out pages) could have decrypted earlier messages of an Olm session.

## 0.3.0 - 2026-11-05

First public release.

- Delivers the daemon's alerts, digests and weekly abuse reports over Matrix, Olm/Megolm-encrypted with its own vodozemac client; OpenPGP files where encryption isn't available.
- Verified against matrix.org with Element X, the weekly report as an attachment.
- An overlong Ed25519 key is refused, not a panic; sanitizing repeats until nothing changes.
