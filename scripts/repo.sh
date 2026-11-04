#!/bin/bash
# Builds the signed apt and dnf repositories from the packages of the releases, for GitHub
# Pages (`.github/workflows/repository.yml` runs it; by hand: see --help). The result is a
# directory to serve as it is:
#
#   deb/dists/stable/{InRelease,Release,Release.gpg,main/binary-{amd64,arm64,armhf}/Packages{,.gz}}
#   deb/pool/main/<crate>_<version>-1_<arch>.deb
#   rpm/<arch>/{<crate>-<version>-1.<arch>.rpm (signed), repodata/ (repomd.xml signed)}
#   vpsfort.asc                 the signing key (public)
#   vpsfort.repo                the dnf repository file
#   index.html                   how to use it
#
# Needs: apt-ftparchive (apt-utils), createrepo_c, gpg with the signing key in its keyring
# (REPO_GPG_KEY_ID names it), dpkg-deb (for the architectures), rpmsign (the rpm package:
# dnf checks each package's own signature, gpgcheck=1, so the rpms are signed with the same
# key; apt checks the InRelease only). Each package goes in once, whatever release it came
# from: the newest version of each crate per architecture.
set -euo pipefail

usage() {
    cat <<EOF
usage: $0 --packages DIR --out DIR --url URL [--key-id ID]
  --packages DIR   the .deb and .rpm files (every release's; the newest of each crate is kept)
  --out DIR        the repository to write (emptied first)
  --url URL        where it will be served, e.g. https://example.github.io/vpsfort
  --key-id ID      the GPG key to sign with (default: \$REPO_GPG_KEY_ID)
EOF
}

packages= out= url= key_id=${REPO_GPG_KEY_ID:-}
while [ $# -gt 0 ]; do
    case "$1" in
        --packages) packages=$2; shift 2 ;;
        --out) out=$2; shift 2 ;;
        --url) url=$2; shift 2 ;;
        --key-id) key_id=$2; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[ -n "$packages" ] && [ -n "$out" ] && [ -n "$url" ] && [ -n "$key_id" ] || { usage >&2; exit 2; }
for tool in apt-ftparchive createrepo_c gpg dpkg-deb rpm rpmsign; do
    command -v "$tool" > /dev/null || { echo "$tool is needed" >&2; exit 1; }
done
url=${url%/}

rm -rf "$out"
mkdir -p "$out/deb/pool/main" "$out/rpm"

# The newest version of each crate per architecture: "<crate>_<version>-1_<arch>.deb" and
# "<crate>-<version>-1.<arch>.rpm" sort by version with `sort -V`.
newest() {
    # $1: a list of "key version path" lines; prints the newest path per key
    sort -k1,1 -k2,2V | awk '{ last[$1] = $3 } END { for (k in last) print last[k] }'
}
find "$packages" -name '*.deb' | while read -r f; do
    b=$(basename "$f" .deb)
    crate=${b%%_*}; rest=${b#*_}; version=${rest%%-*}; arch=${rest##*_}
    echo "$crate/$arch $version $f"
done | newest | while read -r f; do cp -p "$f" "$out/deb/pool/main/"; done
find "$packages" -name '*.rpm' | while read -r f; do
    b=$(basename "$f" .rpm)
    arch=${b##*.}; b=${b%.*}
    crate=${b%-*-*}; version=${b#"$crate"-}; version=${version%-*}
    echo "$crate/$arch $version $f"
done | newest | while read -r f; do
    arch=$(basename "$f" .rpm); arch=${arch##*.}
    mkdir -p "$out/rpm/$arch"
    cp -p "$f" "$out/rpm/$arch/"
done

# Every release carries both kinds: with none of one there is nothing to sign and index
# (before the first release, the workflow publishes the documentation only).
for kind in deb rpm; do
    if [ -z "$(find "$out/$kind" -name "*.$kind" | head -n 1)" ]; then
        echo "no .$kind files under $packages: no repository to build" >&2
        rm -rf "$out"
        exit 1
    fi
done

# apt: one suite "stable", one component "main", the architectures the packages carry
cd "$out/deb"
archs=$(for f in pool/main/*.deb; do dpkg-deb -f "$f" Architecture; done | sort -u)
for arch in $archs; do
    mkdir -p "dists/stable/main/binary-$arch"
    apt-ftparchive --arch "$arch" packages pool > "dists/stable/main/binary-$arch/Packages"
    gzip -9 -k -f "dists/stable/main/binary-$arch/Packages"
done
cat > apt-release.conf <<EOF
APT::FTPArchive::Release::Origin "vpsfort";
APT::FTPArchive::Release::Label "vpsfort";
APT::FTPArchive::Release::Suite "stable";
APT::FTPArchive::Release::Codename "stable";
APT::FTPArchive::Release::Architectures "$(echo $archs)";
APT::FTPArchive::Release::Components "main";
APT::FTPArchive::Release::Description "vpsfort, its bots and web console (static binaries)";
EOF
apt-ftparchive -c apt-release.conf release dists/stable > dists/stable/Release
rm apt-release.conf
gpg --batch --yes --local-user "$key_id" --digest-algo SHA256 --clearsign -o dists/stable/InRelease dists/stable/Release
gpg --batch --yes --local-user "$key_id" --digest-algo SHA256 --detach-sign --armor -o dists/stable/Release.gpg dists/stable/Release
cd - > /dev/null

# dnf: the packages signed (the repository's copies, not the releases' files), then one
# repository per architecture, repomd.xml signed
for f in "$out"/rpm/*/*.rpm; do
    rpmsign --addsign --define "_gpg_name $key_id" --define "_gpg_digest_algo sha256" "$f" > /dev/null
    sig=$(rpm -qp --nosignature --qf '%{SIGPGP:pgpsig}' "$f" 2> /dev/null || true)
    case $sig in "" | "(none)") echo "$f: not signed" >&2; exit 1 ;; esac
done
for d in "$out"/rpm/*/; do
    createrepo_c --quiet "$d"
    gpg --batch --yes --local-user "$key_id" --digest-algo SHA256 --detach-sign --armor "$d/repodata/repomd.xml"
done

gpg --batch --armor --export "$key_id" > "$out/vpsfort.asc"
cat > "$out/vpsfort.repo" <<EOF
[vpsfort]
name=vpsfort
baseurl=$url/rpm/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$url/vpsfort.asc
EOF
fingerprint=$(gpg --batch --with-colons --fingerprint "$key_id" | awk -F: '$1 == "fpr" { print $10; exit }')
cat > "$out/index.html" <<EOF
<!doctype html>
<meta charset="utf-8">
<title>vpsfort packages</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:46em;margin:3em auto;padding:0 1em}pre{background:#f4f4f4;padding:.7em 1em;overflow:auto}</style>
<h1>vpsfort packages</h1>
<p>Signed apt and dnf repositories for <a href="https://github.com/makhort/vpsfort">vpsfort</a>, its bots and the web console: the newest release of each, as static binaries for amd64, arm64 and armhf. The signing key's fingerprint: <code>$fingerprint</code> (compare it with the one in the repository's README).</p>
<h2>Debian, Ubuntu</h2>
<pre>sudo curl -fsSL $url/vpsfort.asc -o /etc/apt/keyrings/vpsfort.asc
echo "deb [signed-by=/etc/apt/keyrings/vpsfort.asc] $url/deb stable main" | sudo tee /etc/apt/sources.list.d/vpsfort.list
sudo apt update &amp;&amp; sudo apt install vpsfort      # or vpsfort-web, vpsfort-xmpp-bot, ...</pre>
<h2>Fedora, RHEL</h2>
<pre>sudo curl -fsSL $url/vpsfort.repo -o /etc/yum.repos.d/vpsfort.repo
sudo dnf install vpsfort</pre>
<p>The rpms here are signed with the same key (dnf checks each package); the releases' own files are not, and carry a build provenance attestation instead.</p>
<p>Nothing starts on its own after an install: each package puts a config template in place and says what to fill in. An upgrade keeps the config and restarts a running service. The same packages, with their <code>.sha256</code> and build provenance attestations, are on each <a href="https://github.com/makhort/vpsfort/releases">release</a>.</p>
EOF
touch "$out/.nojekyll"
echo "repository written to $out ($(find "$out" -name '*.deb' | wc -l | tr -d ' ') .deb, $(find "$out" -name '*.rpm' | wc -l | tr -d ' ') .rpm)"
