#!/bin/bash
# Builds the distribution packages for one architecture, in target/package/:
#   <name>_<version>-1_<deb arch>.deb     Debian, Ubuntu and their derivatives (dpkg, apt)
#   <name>-<version>-1.<rpm arch>.rpm     Fedora, RHEL and its rebuilds (rpm, dnf)
#   <name>-<version>-r0.<apk arch>.apk    Alpine (apk, OpenRC)
# each with its .sha256. An admin installs one with  apt install ./<file>.deb,
# dnf install ./<file>.rpm  or  apk add --allow-untrusted ./<file>.apk  (README, "Install from a
# package"). CI builds and publishes them after ci.sh, next to the release bundle
# (scripts/bundle.sh).
#
#   ./scripts/package.sh                   the static x86_64 binary (cargo builds it, or finds the
#                                          one ci.sh built up to date): amd64 .deb, x86_64 .rpm and .apk
#   ./scripts/package.sh --target TRIPLE   aarch64-unknown-linux-musl (arm64 .deb, aarch64 .rpm and
#                                          .apk) or armv7-unknown-linux-musleabihf (armhf .deb,
#                                          armv7hl .rpm, armv7 .apk)
#
# cargo-deb and cargo-generate-rpm write the first two (cargo install cargo-deb
# cargo-generate-rpm --locked); neither needs dpkg or rpm, so this runs on macOS too. The .apk
# is written by scripts/apk.py at the repository's root (python3, no apk-tools). What goes in
# is listed in Cargo.toml, [package.metadata.deb], [package.metadata.generate-rpm] and
# [package.metadata.apk]: the binary, the deploy files this script stages in
# target/package/stage/ (deploy/'s files with the package's paths: /usr/bin for /usr/local/bin
# and /usr/local/sbin), the maintainer scripts in deploy/pkg/ (dpkg's preinst, postinst, prerm
# and postrm; the same files are rpm's %pre, %post, %preun and %postun) and, for the .apk, the
# OpenRC and install scripts in deploy/alpine/ (pre-install, post-install, pre-deinstall:
# POSIX sh), README.md and LICENSE. Only files git tracks go in, so deploy/config.env and keys
# (git-ignored) never do. The .apk is unsigned (apk add --allow-untrusted) unless APK_SIGN_KEY
# names an RSA private key (PEM) and APK_KEY_NAME its public key's file name in /etc/apk/keys/.
# (The same script in every crate.)
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=x86_64-unknown-linux-musl
NAME=$(sed -n 's/^name = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
[ -n "$NAME" ] && [ -n "$VERSION" ] || { echo "no name or version in Cargo.toml" >&2; exit 1; }
case $#:${1:-} in
    0:) ;;
    2:--target) TARGET=$2 ;;
    *) echo "usage: $0 [--target TRIPLE]" >&2; exit 2 ;;
esac
case $TARGET in
    x86_64-unknown-linux-musl) DEB_ARCH=amd64 RPM_ARCH=x86_64 APK_ARCH=x86_64 ;;
    aarch64-unknown-linux-musl) DEB_ARCH=arm64 RPM_ARCH=aarch64 APK_ARCH=aarch64 ;;
    armv7-unknown-linux-musleabihf) DEB_ARCH=armhf RPM_ARCH=armv7hl APK_ARCH=armv7 ;;
    *) echo "unsupported target $TARGET" >&2; exit 2 ;;
esac
for tool in cargo-deb cargo-generate-rpm; do
    command -v $tool > /dev/null || { echo "$tool is not installed:  cargo install cargo-deb cargo-generate-rpm --locked" >&2; exit 1; }
done
command -v python3 > /dev/null || { echo "python3 is needed (scripts/apk.py)" >&2; exit 1; }
[ -f ../scripts/apk.py ] || { echo "../scripts/apk.py is missing (the repository's scripts/)" >&2; exit 1; }

# Always asked: a binary built before the last commit (or edit) would go out under this
# version. Nothing to do when ci.sh just built it.
cargo build --release --quiet --target "$TARGET"
BIN=target/$TARGET/release/$NAME
[ -x "$BIN" ] || { echo "no $BIN" >&2; exit 1; }
OUT=target/package
STAGE=$OUT/stage
# The packages' files get the last commit's time, so the same commit packs the same bytes.
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct 2> /dev/null || date +%s)

if git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    deploy=$(git ls-files deploy)
else
    deploy=$(find deploy -type f ! -name config.env ! -name '*.key*' ! -path '*/.*' | sort)
fi

# deploy/'s files as the package installs them. The bundle's install.sh puts vpsfort in
# /usr/local/bin and its helper scripts in /usr/local/sbin (the admin's directories); a
# package's place is /usr/bin, so the units and scripts that name those paths are rewritten.
# Nothing else changes; a file without those paths is copied as it is.
rm -rf "$STAGE"
mkdir -p "$STAGE"
for f in $deploy; do
    case $f in
        # run on the admin's machine, from a bundle, or by hand: not packaged
        deploy/deploy.sh | deploy/release-install.sh | deploy/install.sh | deploy/rotate-cluster-key.sh) continue ;;
        deploy/pkg/*) continue ;;   # the maintainer scripts: Cargo.toml names them where they are
        deploy/alpine/*) continue ;;   # the .apk's scripts: [package.metadata.apk] names them where they are
        deploy/*/*) echo "unexpected subdirectory in deploy/: $f" >&2; exit 1 ;;
    esac
    perl -pe 's{/usr/local/bin/vpsfort\b}{/usr/bin/vpsfort}g; s{/usr/local/sbin/(vpsfort-[a-z-]+)}{/usr/bin/$1}g' "$f" > "$STAGE/${f#deploy/}"
    chmod --reference="$f" "$STAGE/${f#deploy/}" 2> /dev/null || chmod "$(stat -f %Lp "$f")" "$STAGE/${f#deploy/}"
    # Every staged file must be in both packages: a new file in deploy/ needs a line in each
    # metadata table (by name, or by its extension's wildcard, e.g. stage/*.toml).
    base=${f#deploy/}
    for table in metadata.deb metadata.generate-rpm; do
        awk -v t="[package.$table]" '/^\[/ { s = ($0 == t) } s' Cargo.toml | grep -qF -e "stage/$base" -e "stage/*.${base##*.}" \
            || { echo "$f is not in Cargo.toml's [package.$table] assets (or excluded here)" >&2; exit 1; }
    done
done
for s in postinst prerm postrm; do
    [ -f deploy/pkg/$s ] || { echo "deploy/pkg/$s is missing" >&2; exit 1; }
done
for s in deploy/pkg/*; do bash -n "$s"; done
[ -f ../LICENSE ] && cp ../LICENSE "$STAGE/LICENSE"

# older packages of this architecture go; the other architectures' stay
rm -f "$OUT"/*_"$DEB_ARCH".deb "$OUT"/*_"$DEB_ARCH".deb.sha256 "$OUT"/*."$RPM_ARCH".rpm "$OUT"/*."$RPM_ARCH".rpm.sha256 \
    "$OUT"/*."$APK_ARCH".apk "$OUT"/*."$APK_ARCH".apk.sha256
DEB=$OUT/${NAME}_${VERSION}-1_${DEB_ARCH}.deb
RPM=$OUT/${NAME}-${VERSION}-1.${RPM_ARCH}.rpm
APK=$OUT/${NAME}-${VERSION}-r0.${APK_ARCH}.apk
# The binaries are already stripped (profile.release) and built: cargo-deb must not build or
# strip (it would look for a cross strip). The rpm's architecture is named: cargo-generate-rpm
# would call 32-bit ARM "armv7", which is not what rpm calls it.
cargo deb --quiet --no-build --no-strip --target "$TARGET" --output "$DEB"
cargo generate-rpm --target "$TARGET" --arch "$RPM_ARCH" --auto-req disabled --output "$RPM" > /dev/null
[ -f "$DEB" ] && [ -f "$RPM" ] || { echo "the packages were not written" >&2; exit 1; }

# What went in, from the packages themselves: with dpkg and rpm (Linux), else with ar and
# tar (macOS); the rpm's payload needs rpm2cpio, so only its header is checked there.
list_deb() {
    if command -v dpkg-deb > /dev/null; then dpkg-deb -c "$1" | awk '{ print $6 }'
    else ar p "$1" data.tar.xz 2> /dev/null | tar -tJf - ; fi | sed 's|^\./||; s|^/||' | grep -v '/$' | sort
}
echo "$DEB:"
list_deb "$DEB" | sed 's/^/    /'
expected=$(awk '/^\[package.metadata.deb\]/ { s = 1; next } /^\[/ { s = 0 } s' Cargo.toml \
    | perl -ne 'print "$1\n" if /^\s*\["[^"]*",\s*"([^"]*)",/' | sed 's|^/||' | { grep -v '/$' || true; } | sort -u)
missing=$(comm -23 <(printf '%s\n' "$expected" | sed '/^$/d') <(list_deb "$DEB"))
[ -z "$missing" ] || { printf 'not in the .deb:\n%s\n' "$missing" >&2; exit 1; }
if command -v rpm > /dev/null; then
    echo "$RPM:"
    rpm -qpl --nosignature "$RPM" 2> /dev/null | sed 's/^/    /'
    rpm -qp --nosignature --scripts "$RPM" > /dev/null 2>&1
fi

# The Alpine package: the files [package.metadata.apk] lists, laid out as installed in
# target/package/apk/, and deploy/alpine/'s scripts, written by scripts/apk.py.
APKROOT=$OUT/apk
rm -rf "$APKROOT"
mkdir -p "$APKROOT"
apk_table() { awk '/^\[package.metadata.apk\]/ { s = 1; next } /^\[/ { s = 0 } s' Cargo.toml; }
apk_table | perl -ne 'print "$1\t$2\t$3\n" if /^\s*\["([^"]*)",\s*"([^"]*)",\s*"([^"]*)"\]/' | while IFS=$'\t' read -r src dest mode; do
    src=${src/#target\/release\//target/$TARGET/release/}   # the deb table's name for the binary
    for f in $src; do   # a wildcard (stage/*.toml) names several files
        [ -f "$f" ] || { echo "apk: $f is missing (Cargo.toml's [package.metadata.apk] assets)" >&2; exit 1; }
        case $dest in */) d=$APKROOT/$dest${f##*/} ;; *) d=$APKROOT/$dest ;; esac
        mkdir -p "${d%/*}"
        cp "$f" "$d"
        chmod "$mode" "$d"
    done
done
for s in post-install pre-deinstall; do
    [ -f deploy/alpine/$s ] || { echo "deploy/alpine/$s is missing" >&2; exit 1; }
done
for s in deploy/alpine/*; do sh -n "$s"; done
apk_depends=()
for dep in $(apk_table | perl -ne 'print "$1\n" if /^depends = \[(.*)\]/' | tr -d '",'); do apk_depends+=(--depends "$dep"); done
apk_sign=()
if [ -n "${APK_SIGN_KEY:-}" ]; then apk_sign=(--sign "$APK_SIGN_KEY" --key-name "${APK_KEY_NAME:?APK_KEY_NAME: the public key file name in /etc/apk/keys/}"); fi
python3 ../scripts/apk.py --name "$NAME" --version "$VERSION" --arch "$APK_ARCH" \
    --desc "$(sed -n 's/^summary = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)" \
    --url "$(sed -n 's/^repository = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)" \
    --license "$(sed -n 's/^license = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)" \
    --root "$APKROOT" --scripts deploy/alpine ${apk_depends[@]+"${apk_depends[@]}"} ${apk_sign[@]+"${apk_sign[@]}"} --out "$APK"   # (empty arrays, bash 3)
# The names in an .apk: gzip reads its three members in a row (the control section's names
# start with a dot). tar stops at the end of the archive, so what gzip still has to write is
# read to the end: gzip would die of the closed pipe now and then, and with pipefail this
# script with it. GNU tar's notes on apk's checksum headers are turned off.
tar_quiet=()
if tar --version 2> /dev/null | grep -q 'GNU tar'; then tar_quiet=(--warning=no-unknown-keyword); fi
apk_names() {
    gzip -dc "$1" | (rc=0; tar ${tar_quiet[@]+"${tar_quiet[@]}"} -tf - || rc=$?; cat > /dev/null; exit "$rc")
}
echo "$APK:"
apk_names "$APK" | grep -v '^\.' | grep -v '/$' | sort | sed 's/^/    /'
expected=$(apk_table | perl -ne 'print "$2\n" if /^\s*\["([^"]*)",\s*"([^"]*)",\s*"([^"]*)"\]/' | { grep -v '/$' || true; } | sort -u)
missing=$(comm -23 <(printf '%s\n' "$expected" | sed '/^$/d') <(apk_names "$APK" | grep -v '^\.' | grep -v '/$' | sort))
[ -z "$missing" ] || { printf 'not in the .apk:\n%s\n' "$missing" >&2; exit 1; }
rm -rf "$APKROOT"

sha256() { if command -v sha256sum > /dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$OUT" && sha256 "${DEB##*/}" > "${DEB##*/}.sha256" && sha256 "${RPM##*/}" > "${RPM##*/}.sha256" && sha256 "${APK##*/}" > "${APK##*/}.sha256")
rm -rf "$STAGE"
echo "$DEB"
echo "$RPM"
echo "$APK"
