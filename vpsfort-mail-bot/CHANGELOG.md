# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.5.5 - 2026-11-26

Dependency updates, url 2.5.9 for RUSTSEC-2026-0592.

- url 2.5.9, for RUSTSEC-2026-0592: `Url::origin()` on a URL nested in many `blob:` prefixes overflowed the stack and aborted the process. The bot's own code doesn't call it.
- The other dependencies are updated within their semver ranges (`cargo update`), pgp 0.21.1, email_address 0.2.10, rustls-webpki 0.103.17 among them.

## 0.5.4 - 2026-11-21

lettre 0.11.24, for six advisories in the SMTP client.

- lettre, the bot's SMTP client, is 0.11.24: 0.11.23 let a man in the middle forge the server's replies through the STARTTLS response (RUSTSEC-2026-0560), sent a bare CR or LF in a message without dot-stuffing it, so a message's text could carry SMTP commands (RUSTSEC-2026-0561), sent mail for an address with a quoted local part to another address (RUSTSEC-2026-0563), and could be made to panic or run out of memory by a server's reply or a display name (RUSTSEC-2026-0562, -0564, -0565).

## 0.5.3 - 2026-11-11

Installer hardening, after vpsfort's audit of 2026-11-10.

- `deploy.sh`: the command pasted into the root shell refuses a staging copy holding anything but regular files. A link left there by the SSH user passed the hash check through its target, which could be changed before `install.sh` ran as root (found by vpsfort's thirteenth audit, 2026-11-10).
- `scripts/ci.sh`: `VPSFORT_MAIL_BOT_SKIP_AUDIT=1` skips the licence check too, as its message says.

## 0.5.2 - 2026-11-08

Installer hardening, after vpsfort's audit of 2026-11-07.

- `install.sh` and the package's post-install step change the owner and mode of the bot's files (the pseudonym and signing keys, `bot.log`, the OpenPGP key, the SMTP password and CA files) only when they are regular files with one name. The directory is the bot's user's to write in, so a link planted under one of those names made root change the owner and mode of whatever it pointed at (found by vpsfort's audit of 2026-11-07).
- vpsfort's next release names its messages `alert-<time>-<n>-<signature>.msg`; the bot's matching (`alert-*.msg`) is unchanged.

## 0.5.1 - 2026-11-06

Fixes.

- The package's question whether to replace `config.env` is asked on the terminal itself, so it shows under dnf too: dnf held it back with the install's output, and the install looked hung for the question's minute before keeping the config.

## 0.5.0 - 2026-11-05

First public release.

- Sends the daemon's alerts, digests and weekly abuse reports by SMTP, PGP/MIME-encrypted to each admin's key; send-only, no mailbox.
- Optional sanitizing of what the mail names; sanitizing repeats until nothing changes.
- Read with any standard PGP/MIME client.
