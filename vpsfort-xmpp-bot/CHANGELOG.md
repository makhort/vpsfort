# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.6.0 - 2026-11-05

First public release.

- Delivers the daemon's alerts, digests and weekly abuse reports over XMPP, OMEMO-encrypted, to the admins; files as OpenPGP where OMEMO can't carry them.
- Admin mode answers the admins' commands; client mode copies another bot's outbox for relays and desktops.
- SCRAM-SHA-256-PLUS, direct TLS, a new client when a session can't be resumed, ban-safe reconnects.
- A first install on a clean host from the bundle's install.sh.
