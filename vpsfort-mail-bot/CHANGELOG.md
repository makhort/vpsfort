# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.5.0 - 2026-11-05

First public release.

- Sends the daemon's alerts, digests and weekly abuse reports by SMTP, PGP/MIME-encrypted to each admin's key; send-only, no mailbox.
- Optional sanitizing of what the mail names; sanitizing repeats until nothing changes.
- Read with any standard PGP/MIME client.
