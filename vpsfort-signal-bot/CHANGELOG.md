# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.3.1 - 2026-11-06

Fixes.

- The package's question whether to replace `config.env` is asked on the terminal itself, so it shows under dnf too: dnf held it back with the install's output, and the install looked hung for the question's minute before keeping the config.

## 0.3.0 - 2026-11-05

First public release.

- Delivers the daemon's alerts, digests and weekly abuse reports over Signal through signal-cli, with the admin's safety number pinned; OpenPGP files after a change of it.
- Sanitizing repeats until nothing changes.
