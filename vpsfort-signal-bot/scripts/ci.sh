#!/bin/bash
# The checks to pass before deploying (deploy/deploy.sh runs them first).
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

step "format"
cargo fmt --check
step "clippy"
cargo clippy --all-targets --quiet -- -D warnings
step "tests"
cargo test --quiet
step "dependency advisories (cargo audit)"
if [ "${VPSFORT_SIGNAL_BOT_SKIP_AUDIT:-}" = 1 ]; then
    echo "skipped (VPSFORT_SIGNAL_BOT_SKIP_AUDIT=1)"
elif ! cargo audit --version > /dev/null 2>&1; then
    echo "cargo-audit is not installed:  cargo install cargo-audit --locked   (or VPSFORT_SIGNAL_BOT_SKIP_AUDIT=1)" >&2
    exit 1
elif ! cargo audit --quiet --deny unsound --deny yanked > /dev/null 2>&1; then
    if cargo audit --quiet --no-fetch --stale --deny unsound --deny yanked; then
        echo "note: advisory database not updated (offline?); checked against the copy on disk"
    else
        exit 1
    fi
fi
step "licenses, duplicate crates and sources (cargo deny)"
# Permissive licenses only, two versions of one crate reported, crates from crates.io only
# (../deny.toml). VPSFORT_SIGNAL_BOT_SKIP_AUDIT=1 skips this step too.
if [ "${VPSFORT_SIGNAL_BOT_SKIP_AUDIT:-}" = 1 ]; then
    echo "skipped (VPSFORT_SIGNAL_BOT_SKIP_AUDIT=1)"
elif ! cargo deny --version > /dev/null 2>&1; then
    echo "cargo-deny is not installed:  cargo install cargo-deny --locked   (or VPSFORT_SIGNAL_BOT_SKIP_AUDIT=1)" >&2
    exit 1
else
    cargo deny --config ../deny.toml check --hide-inclusion-graph licenses bans sources
fi
step "static Linux binary"
# TARGET=aarch64-unknown-linux-musl or armv7-unknown-linux-musleabihf builds for ARM instead
TARGET=${TARGET:-x86_64-unknown-linux-musl}
cargo build --release --quiet --target "$TARGET"
ls -l target/$TARGET/release/vpsfort-signal-bot
