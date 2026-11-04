# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.3.0 - 2026-11-05

First public release.

- Delivers the daemon's alerts, digests and weekly abuse reports over Matrix, Olm/Megolm-encrypted with its own vodozemac client; OpenPGP files where encryption isn't available.
- Verified against matrix.org with Element X, the weekly report as an attachment.
- An overlong Ed25519 key is refused, not a panic; sanitizing repeats until nothing changes.
