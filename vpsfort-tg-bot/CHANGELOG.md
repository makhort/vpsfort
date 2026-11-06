# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.5.1 - 2026-11-06

Fixes.

- The package's question whether to replace `config.env` is asked on the terminal itself, so it shows under dnf too: dnf held it back with the install's output, and the install looked hung for the question's minute before keeping the config.

## 0.5.0 - 2026-11-05

First public release.

- Delivers the daemon's alerts, digests and weekly abuse reports to Telegram, pseudonymized: accounts, addresses and names never leave the host in the clear; files go OpenPGP-encrypted.
- Sanitizing repeats until nothing changes, so nested or overlapping matches can't leak.
- Runs on a relay node of its own, as its own system user.
