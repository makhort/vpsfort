# vpsfort

Behaviour-based intrusion prevention for a small self-hosted server family: an XMPP server
(ejabberd) with Nextcloud, a WireGuard VPN host and a Telegram relay node. Everything is
written in Rust and runs as single static binaries on Linux (musl; x86_64, aarch64 and 32-bit ARMv7 with hardware floating point).

**vpsfort** follows the systemd journal (ejabberd, sshd, the UFW or firewalld kernel log,
Nextcloud AIO), scores every remote address by what it does, and bans attackers in nftables,
firewalld, ufw, iptables or ipset within seconds. It can also drop whole countries or networks
(ASNs), by the offline geo database it already uses for labels. Nodes can share bans and suspicion reports over an encrypted cluster link. Six
optional bots carry vpsfort's admin alerts, daily digest and weekly abuse report to the
admins, and an optional web console shows the whole cluster to its admins, read only. They only
carry messages and show data: protection never depends on them.

```
        ┌──────────── server ─────────────┐        cluster (XChaCha20-Poly1305, TCP 7946)
journal ─► vpsfort ─► nftables/firewalld/ufw/iptables/ipset ◄─► vpsfort on other nodes
            │  outboxes (files)
            ├─► vpsfort-xmpp-bot ─► XMPP, OMEMO-encrypted (client mode: else OpenPGP files)
            ├─► vpsfort-tg-bot     ─► Telegram (pseudonymized, files OpenPGP-encrypted)
            ├─► vpsfort-mail-bot   ─► SMTP, PGP/MIME-encrypted
            ├─► vpsfort-signal-bot ─► Signal through signal-cli (else OpenPGP files)
            ├─► vpsfort-matrix-bot ─► Matrix, Olm/Megolm-encrypted (else OpenPGP files)
            └─► vpsfort-push-bot   ─► ntfy, Gotify or a webhook (sanitized, files OpenPGP-encrypted)
            │  read-only console socket
            └─► vpsfort-web (agent) ◄─ web key, TCP 7949 ─ vpsfort-web (console) ─► HTTPS ─► the admin's browser
```

How vpsfort compares with fail2ban, sshguard, CrowdSec, CSF, Wazuh and OSSEC, the host
integrity and monitoring tools, and commercial products, with pros and cons per category and
feature: [COMPARISON.md](COMPARISON.md).

## Contents

1. [Crates](#crates)
2. [Build and test](#build-and-test)
3. [Deployment](#deployment)
4. [License](#license)
5. [Authorship](#authorship)

## Crates

Each directory is its own Cargo project with a README that covers setup, settings and design
in detail.

| crate | what it does |
|---|---|
| [`vpsfort`](vpsfort/README.md) | The daemon and its CLI/TUI: log parsers, the scoring and ban engine, firewall backends, cluster, exposure/cron/antivirus watches, package checks (dpkg or rpm), blocklist feeds, country and network blocking, daily digest, weekly abuse reports. |
| [`vpsfort-xmpp-bot`](vpsfort-xmpp-bot/README.md) | XMPP bot in two modes. Admin (on the XMPP server): curated `ejabberdctl` commands in chat, plus vpsfort's admin messages over OMEMO. Client (`BOT_MODE=client`, any host and XMPP server, e.g. a desktop): send-only, vpsfort's admin messages over OMEMO, else as OpenPGP-encrypted files. SCRAM-SHA-256-PLUS login. |
| [`vpsfort-tg-bot`](vpsfort-tg-bot/README.md) | Telegram transport for vpsfort's admin messages. Account names become pseudonyms and servers appear only by node id. Reports go out as OpenPGP-encrypted files. |
| [`vpsfort-mail-bot`](vpsfort-mail-bot/README.md) | Send-only SMTP bot that mails vpsfort's admin messages, each OpenPGP-encrypted as a whole (subject included). |
| [`vpsfort-signal-bot`](vpsfort-signal-bot/README.md) | Send-only Signal bot over signal-cli (installed separately): vpsfort's admin messages while the safety number with the admin is the pinned one, else as OpenPGP-encrypted files. |
| [`vpsfort-web`](vpsfort-web/README.md) | Read-only web console for the whole cluster: an agent on every node hands its vpsfort's data (through a read-only socket) to the console, sealed with a web key of its own (never the cluster key) and forward-secret; the console shows bans, alerts, offenders, places and every node's health and every node's abuse report split per network owner, ready to mail, over HTTPS (TLS 1.3) to its admins (one or a few, all equal), each with a password and a one-time code or a passkey, plus `/metrics` for Prometheus. It also runs alone on a host without vpsfort, as an aggregator. |
| [`vpsfort-sim`](vpsfort-sim/README.md) | A simulated cluster and its web console in one process, from real decision logs (each node's state from vpsfort's own log reader, digest renderer and abuse report builder) or a console export, with real vpsfort-web agents and console: for trying the console without servers, screenshots and page work. Makes the web key, the admin's password and one-time secret and a certificate when missing, and says so. |
| [`vpsfort-matrix-bot`](vpsfort-matrix-bot/README.md) | Send-only Matrix client: vpsfort's admin messages end-to-end encrypted (Olm/Megolm, vodozemac) to the devices the admin verified, else as OpenPGP-encrypted files. |
| [`vpsfort-push-bot`](vpsfort-push-bot/README.md) | Send-only push bot for ntfy, Gotify or any webhook: vpsfort's admin messages sanitized as for Telegram (the service reads them), files only OpenPGP-encrypted. |
| `vpsfort-botlib` | What the Telegram, mail, Signal, Matrix and push bots share: the outbox format, the pseudonyms and server names, the OpenPGP files, the log. A library, not shipped on its own. |

The supported combinations of bots and cluster peers are described in vpsfort's README,
"Deployment layouts". `vpsfort/tests/layouts.rs` runs each layout end to end.

## Build and test

You need Rust stable and the `x86_64-unknown-linux-musl` target (for ARM also `aarch64-unknown-linux-musl`,
`armv7-unknown-linux-musleabihf`; `TARGET=<target> ./scripts/ci.sh` builds one). The bots and vpsfort-web also need the
`llvm-tools` component. Each crate builds and tests on its own:

```bash
cd vpsfort            # or vpsfort-xmpp-bot, vpsfort-tg-bot, vpsfort-mail-bot, vpsfort-signal-bot, vpsfort-matrix-bot, vpsfort-push-bot, vpsfort-web
./scripts/ci.sh        # fmt, clippy -D warnings, tests, cargo audit, cargo deny, static musl build
./scripts/bundle.sh    # the release bundle (zip); ./scripts/package.sh: the .deb, .rpm and .apk (both take --target TRIPLE)
```

`package.sh` needs `cargo install cargo-deb cargo-generate-rpm --locked` once; they write the
packages without dpkg or rpm, so the packages build on macOS too.

The static Linux binary also builds from macOS without a C cross toolchain (see each crate's
`.cargo/config.toml`). Some tests listen on 127.0.0.1, so they need a machine or sandbox that
allows local sockets. `.github/workflows/` runs the same `ci.sh` per crate on GitHub Actions
and uploads the bundles: the tests on x86_64 and on GitHub's arm64 runners, the 32-bit ARM
binary cross-built, linted for its target and started under qemu.

Each crate has `fuzz/` targets for cargo-fuzz (nightly). `tests/fuzz_smoke.rs` runs the same
targets on stable over their seeds.

## Deployment

**From a release bundle** (no Rust needed): one zip per crate and architecture,
`<crate>-<version>-<commit>-<arch>.zip`, `<arch>` one of `x86_64-linux-musl`,
`aarch64-linux-musl` (arm64) and `armv7-linux-musleabihf` (32-bit ARMv7, hard-float). It holds the static binary, the systemd
units, logrotate files and config templates, `SHA256SUMS`, and an `install.sh`. Unzip it on
the server and run `sudo ./install.sh` (the first run of each puts a config in place to edit,
then you run it again). Each crate's README has a section "Install from a release bundle",
with how to download and verify one.

**From a package** (Debian, Ubuntu and their derivatives; Fedora, RHEL and its rebuilds; Alpine):
the same releases carry `<crate>_<version>-1_<arch>.deb` (`amd64`, `arm64`, `armhf`),
`<crate>-<version>-1.<arch>.rpm` (`x86_64`, `aarch64`, `armv7hl`) and
`<crate>-<version>-r0.<arch>.apk` (`x86_64`, `aarch64`, `armv7`), the same static binary and
deploy files for the package manager: `sudo apt install ./<file>.deb`, `sudo dnf install
./<file>.rpm` or `apk add --allow-untrusted ./<file>.apk` (the `.apk` is unsigned; its `.sha256`
and attestation verify it, and it brings OpenRC scripts instead of the units: Alpine has no
systemd, and no journal, so vpsfort follows `/var/log/messages` there). vpsfort goes to
`/usr/bin` with its units in `/usr/lib/systemd/system` and the templates in
`/usr/share/vpsfort/templates`; the bots and vpsfort-web stay in `/opt/<crate>`.
Nothing starts on its own: the first install puts the config template in place to edit, then
you enable the service. An upgrade keeps the config (asking, when a terminal is there, whether
to replace it with the new template) and restarts a running service when its config is valid.
The packages also install over a bundle or `deploy.sh` install and take it over, keeping its
config, keys and state. Rollback is installing the previous version's package. Each crate's
README has a section "Install from a package".

**From the repository** (a public repository with GitHub Pages): `.github/workflows/repository.yml`
runs after every release is published, gathers the newest `.deb` and `.rpm` of every crate from
the releases, builds a signed apt repository (`deb/`, suite `stable`, component `main`) and a
signed dnf repository per architecture (`rpm/<arch>/`) with `scripts/repo.sh`, and pushes them
to the `gh-pages` branch, which Pages serves at `https://makhort.github.io/vpsfort/` with
the instructions on its index page; the rpms in it are signed with the same key (dnf checks
each package, `gpgcheck=1`), the debs are covered by the signed `InRelease`. The same workflow
builds the **documentation site** under `docs/` there (the READMEs and COMPARISON.md with
mdBook, `scripts/docs-site.sh`) after every push to `main` that changes them, also without a
signing key. It needs the repository secret `REPO_GPG_KEY` (an armored OpenPGP private key made
for this: `gpg --quick-generate-key "vpsfort packages <you@example.org>" rsa4096 sign 0`;
RSA, since rpm before 4.16 (RHEL 8) can't verify ed25519 signatures; exported with
`--export-secret-keys`), `REPO_GPG_PASSPHRASE` if it has one, and Pages set to deploy from the
`gh-pages` branch (the workflow's first run creates it: choose it in Settings → Pages after
that); without the key, or before the first release, only the documentation is published. Then:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://makhort.github.io/vpsfort/vpsfort.asc | sudo install -m 0644 /dev/stdin /etc/apt/keyrings/vpsfort.asc
echo "deb [signed-by=/etc/apt/keyrings/vpsfort.asc] https://makhort.github.io/vpsfort/deb stable main" | sudo tee /etc/apt/sources.list.d/vpsfort.list
sudo apt update && sudo apt install vpsfort
```

and on Fedora or RHEL `sudo curl -fsSL https://makhort.github.io/vpsfort/vpsfort.repo -o /etc/yum.repos.d/vpsfort.repo && sudo dnf install vpsfort`.
Compare the key's fingerprint on the index page with the one you made. `apt upgrade` and `dnf
upgrade` then bring new versions, with the same post-install steps as a single package.

**The signing key's fingerprint is** `12A75B42C4ADD340896F5E7A2F64B712E37F3CEC`; compare it with
the downloaded key's before the first `apt update`: `gpg --show-keys /etc/apt/keyrings/vpsfort.asc`.

**Releases:** a version is a tag `<crate>-v<version>` (`vpsfort-v0.6.1`,
`vpsfort-xmpp-bot-v0.6.1`, ...), with the version in that crate's `Cargo.toml`
and the release notes as that version's `## <version>` section in the crate's `CHANGELOG.md`
(`./scripts/bundle.sh --check-tag TAG` checks both). Pushing the tag runs that crate's workflow,
which refuses a tag that doesn't match or has no notes, tests, builds and installs the bundles and packages as
on every commit (the `.deb` on the runner, over the bundle's install; the `.rpm` in Fedora and
AlmaLinux containers, the `.apk` in an Alpine container), then attaches them to the GitHub Release of the tag, each with its `.sha256` and
(in a public repository) a signed build provenance attestation, `.sigstore.json`, that
`gh attestation verify` checks, and a software bill of materials, `<crate>-<version>.cdx.json`
(CycloneDX, from `cargo cyclonedx`: every crate in the binary with its version, license and
`pkg:cargo` identifier, with its `.sha256` and covered by the attestation). Every CI run,
tagged or not, also keeps its zip, `.deb`, `.rpm`, `.apk` and SBOM as workflow artifacts.

**Dependencies:** `cargo audit` (known vulnerabilities, unsound code, yanked versions) and
`cargo deny` ([`deny.toml`](deny.toml): permissive licenses only, crates from crates.io only, two
versions of one crate reported) run in every crate's `ci.sh`, locally and on every CI run.
vpsfort's workflow also enforces on the runner's own kernel with the real `nft`, as root
(`tests/real_nft.rs`, and the installed daemon in enforce mode: a ban, the table deleted and
rebuilt, an unban); the other enforcement tests use a stand-in `nft`.

**Fedora and RHEL:** vpsfort's `package_manager = "dnf"` (its `-dnf` config templates, the
`.rpm`'s default on a host with dnf) reads rpm's database and asks dnf for pending updates
instead of dpkg and apt; with firewalld as the firewall. Tried on a Fedora 44 server, step by step in
[vpsfort/TESTING-fedora.md](vpsfort/TESTING-fedora.md); the results are in vpsfort's README,
"Verified on the servers".

**From a checkout:** each crate has a `deploy/` directory: a `deploy.sh` that runs `ci.sh`,
builds the binary and copies everything to a host over SSH, and an `install.sh` to run there
as root. It also holds the systemd units, logrotate files and config templates.
`scripts/bundle.sh` builds the release bundle locally. vpsfort ships config templates for
four roles: `vpsfort.toml` (XMPP server), `vpsfort-standalone.toml` (a host with SSH and UFW
only, e.g. a VPN server), `vpsfort-tg.toml` (Telegram relay node) and `vpsfort-desktop.toml`
(a Linux desktop or laptop), each also as a `-dnf` variant for Fedora and RHEL.

The templates use placeholder names and addresses (`example.org`, documentation ranges).
Replace them, and the allowlist entries, with your own before deploying. Start in
`mode = "shadow"`, review the decisions, then switch to `"enforce"`.

**SSH hardening:** `hardening/harden-vps.sh`, run from your laptop, turns SSH on a VPS
(Debian/Ubuntu or Fedora/RHEL-like) into the gateway layout vpsfort's SSH audit checks: one
key-only user forced into `su` or sftp, keys in a root-owned file, `su` limited by pam_wheel.
It takes over a server hardened partly by hand too (`-g` keeps its user, `--su` works without
root login or sudo). It tests the new login before it commits and rolls back otherwise;
`hardening/harden-vps.sh --help` lists the options.


## License

[MIT](LICENSE).

## Authorship

This project was co-authored by Claude (Anthropic; Opus 5.5, then Fable 5.1) in Claude Code: the design,
the code, the tests and the documentation were written in collaboration with the model.
