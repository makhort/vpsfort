#!/usr/bin/env python3
"""Writes an Alpine package (.apk, the v2 format apk-tools reads) from a staged tree, without
abuild or apk-tools, so every crate's scripts/package.sh builds one on any machine next to its
.deb and .rpm. An .apk is three gzip streams in a row: the signature (left out when no key is
given: `apk add --allow-untrusted` then), the control section (.PKGINFO and the install
scripts, a tar without its end-of-archive blocks) and the data section (the files, a pax tar
whose entries carry an APK-TOOLS.checksum.SHA1 header each, as abuild-tar --hash writes).

  apk.py --name NAME --version VER --arch ARCH --desc TEXT --url URL --license L
         --root DIR [--depends PKG]... [--scripts DIR] [--sign KEY.rsa --key-name NAME]
         --out FILE.apk

--root DIR holds the files with the paths the package installs them at (DIR/usr/bin/x ->
/usr/bin/x), their modes as they are to be installed, owned by root. --scripts DIR holds the
install scripts by their apk names (pre-install, post-install, pre-deinstall, post-deinstall,
pre-upgrade, post-upgrade), POSIX sh; without pre-upgrade or post-upgrade, the -install
script of the same kind runs on an upgrade too. --sign is an RSA private key (PEM); --key-name the name
its public key has in /etc/apk/keys/ (abuild's "<packager>-<id>.rsa.pub"). ARCH is apk's
name: x86_64, aarch64, armv7 (32-bit ARMv7 with hardware floating point; armhf is ARMv6).
"""
import argparse
import gzip
import hashlib
import io
import os
import subprocess
import sys
import tarfile
import time

BLOCK = 512


def tar_bytes(add, with_end=True):
    """A tar stream (pax format) built by `add(tar)`; without its end-of-archive blocks when
    with_end is false (the signature and control sections, as abuild-tar --cut writes them)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        add(tar)
    data = buf.getvalue()
    if not with_end:
        while len(data) >= BLOCK and data[-BLOCK:] == b"\0" * BLOCK:
            data = data[:-BLOCK]
    return data


def entry(name, mode, mtime, size=0, kind=tarfile.REGTYPE):
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.mtime = mtime
    info.size = size
    info.type = kind
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    return info


def add_tree(tar, root, mtime):
    """Every directory and file under root, directories first, in a fixed order, each file
    with its SHA1 in a pax header (what apk verifies on install)."""
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        rel = os.path.relpath(dirpath, root)
        if rel != ".":
            tar.addfile(entry(rel + "/", 0o755, mtime, kind=tarfile.DIRTYPE))
        for f in sorted(filenames):
            path = os.path.join(dirpath, f)
            name = f if rel == "." else f"{rel}/{f}"
            if os.path.islink(path):
                info = entry(name, 0o777, mtime, kind=tarfile.SYMTYPE)
                info.linkname = os.readlink(path)
                tar.addfile(info)
                continue
            with open(path, "rb") as fh:
                content = fh.read()
            info = entry(name, os.stat(path).st_mode & 0o7777, mtime, len(content))
            info.pax_headers = {"APK-TOOLS.checksum.SHA1": hashlib.sha1(content).hexdigest()}
            tar.addfile(info, io.BytesIO(content))
            total += len(content)
    return total


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True)
    ap.add_argument("--version", required=True, help="the crate's version; the package's is VERSION-r0")
    ap.add_argument("--arch", required=True, choices=["x86_64", "aarch64", "armv7"])
    ap.add_argument("--desc", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--license", required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--depends", action="append", default=[])
    ap.add_argument("--scripts", default=None)
    ap.add_argument("--sign", default=None, help="RSA private key (PEM); unsigned without")
    ap.add_argument("--key-name", default=None, help="the public key's file name in /etc/apk/keys/")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if bool(a.sign) != bool(a.key_name):
        ap.error("--sign and --key-name go together")
    mtime = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))

    # the data section: the files, and their total size for .PKGINFO
    sizes = {}
    data = tar_bytes(lambda t: sizes.setdefault("n", add_tree(t, a.root, mtime)))
    data_gz = gzip.compress(data, compresslevel=9, mtime=mtime)

    # the control section: .PKGINFO (abuild's fields) and the scripts
    scripts = {}
    if a.scripts:
        for s in ("pre-install", "post-install", "pre-deinstall", "post-deinstall", "pre-upgrade", "post-upgrade"):
            p = os.path.join(a.scripts, s)
            if os.path.isfile(p):
                with open(p, "rb") as fh:
                    scripts["." + s] = fh.read()
        # apk runs the -upgrade scripts instead of the -install ones on an upgrade: without
        # ones of their own, the install scripts serve both (as dpkg's postinst does)
        for s in ("pre", "post"):
            if f".{s}-install" in scripts and f".{s}-upgrade" not in scripts:
                scripts[f".{s}-upgrade"] = scripts[f".{s}-install"]
    pkginfo = [
        "# Generated by scripts/apk.py",
        f"# {time.strftime('%a %b %d %H:%M:%S UTC %Y', time.gmtime(mtime))}",
        f"pkgname = {a.name}",
        f"pkgver = {a.version}-r0",
        f"pkgdesc = {a.desc}",
        f"url = {a.url}",
        f"builddate = {mtime}",
        "packager = scripts/apk.py",
        f"size = {sizes['n']}",
        f"arch = {a.arch}",
        f"origin = {a.name}",
        "maintainer = The vpsfort contributors",
        f"license = {a.license}",
    ]
    pkginfo += [f"depend = {d}" for d in a.depends]
    pkginfo.append(f"datahash = {hashlib.sha256(data_gz).hexdigest()}")
    pkginfo_bytes = ("\n".join(pkginfo) + "\n").encode()

    def add_control(tar):
        tar.addfile(entry(".PKGINFO", 0o644, mtime, len(pkginfo_bytes)), io.BytesIO(pkginfo_bytes))
        for name, content in scripts.items():
            tar.addfile(entry(name, 0o755, mtime, len(content)), io.BytesIO(content))

    control_gz = gzip.compress(tar_bytes(add_control, with_end=False), compresslevel=9, mtime=mtime)

    parts = []
    if a.sign:
        # RSA over SHA1 of the control section's gzip bytes, as abuild-sign does
        sig = subprocess.run(["openssl", "dgst", "-sha1", "-sign", a.sign], input=control_gz, capture_output=True, check=True).stdout
        sig_name = f".SIGN.RSA.{a.key_name}"
        sig_gz = gzip.compress(tar_bytes(lambda t: t.addfile(entry(sig_name, 0o644, mtime, len(sig)), io.BytesIO(sig)), with_end=False), 9, mtime=mtime)
        parts.append(sig_gz)
    parts += [control_gz, data_gz]
    with open(a.out, "wb") as out:
        for p in parts:
            out.write(p)
    print(f"{a.out}: {len(scripts)} scripts, {sizes['n']} bytes of files" + (" (signed)" if a.sign else " (unsigned)"), file=sys.stderr)


if __name__ == "__main__":
    main()
