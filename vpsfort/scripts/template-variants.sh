#!/bin/bash
# Writes the variants of the config templates from the templates themselves; edit the
# template, then run this:
#   deploy/<name>-dnf.toml from each deploy/<name>.toml: the same settings for a Fedora or
#   RHEL host (package_manager = "dnf", rpm's database, dnf's tools);
#   deploy/vpsfort-alpine.toml from deploy/vpsfort.toml: an Alpine host (the .apk's
#   template): no journal ([journal] syslog_file = /var/log/messages), no systemd units to
#   watch, and no apt or dnf for the patch and package checks.
#
#   ./scripts/template-variants.sh           writes them
#   ./scripts/template-variants.sh --check   only says (and fails) if one is out of date (ci.sh)
set -euo pipefail
cd "$(dirname "$0")/.."

check=no
case $#:${1:-} in
    0:) ;;
    1:--check) check=yes ;;
    *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

alpine() { # the Alpine variant of deploy/vpsfort.toml, on stdout
    printf '# The variant of vpsfort.toml for Alpine (OpenRC, busybox syslog, apk), written from it\n# by scripts/template-variants.sh: edit that file, then run the script. See the README,\n# "Requirements" (Alpine): lines come from /var/log/messages, unchecked for their sender.\n'
    perl -pe '
        $section = $1 if /^\[(\w+)\]/;
        s/^# syslog_file = "\/var\/log\/messages"$/syslog_file = "\/var\/log\/messages"/;
        s/^services = \[.*\]$/services = []            # (systemd units: none here)/ if $section eq "sources";
        s/^enabled = true$/enabled = false            # needs apt or dnf: not on Alpine/ if $section eq "patches" || $section eq "verify";
    ' deploy/vpsfort.toml
}

variant() { # the dnf variant of template $1, on stdout
    local name=${1##*/}
    printf '# The variant of %s for Fedora and RHEL (dnf), written from it by\n# scripts/template-variants.sh: edit that file, then run the script.\n' "$name"
    perl -pe '
        s/^package_manager = "apt"$/package_manager = "dnf"/;
        s/^dpkg_db = .*$/rpm = "\/usr\/bin\/rpm"            # asked which package owns a changed file (rpm -qf)/;
        s/\(MD5 recorded by dpkg\)/(digest recorded by rpm)/;
        s/apt install clamav clamav-freshclam/dnf install clamav clamav-freshclam (older Fedora, RHEL: clamav-update)/;
        s/\(apt-get -s, a simulation,$/(dnf --cacheonly check-update,/;
        s/^apt = true$/apt = true                 # here: dnf (package_manager)/;
        s/hashed against dpkg\x27s checksums \(like debsums;/hashed against rpm\x27s digests (like rpm -Va;/;
    ' "$1"
}

stale=0
if [ "$check" = yes ]; then
    if ! alpine | cmp -s - deploy/vpsfort-alpine.toml; then
        echo "deploy/vpsfort-alpine.toml is out of date: ./scripts/template-variants.sh" >&2
        stale=1
    fi
else
    alpine > deploy/vpsfort-alpine.toml
    echo "wrote deploy/vpsfort-alpine.toml"
fi
for t in deploy/*.toml; do
    case $t in *-dnf.toml | *-alpine.toml) continue ;; esac
    v=${t%.toml}-dnf.toml
    if [ "$check" = yes ]; then
        if ! variant "$t" | cmp -s - "$v"; then
            echo "$v is out of date: ./scripts/template-variants.sh" >&2
            stale=1
        fi
    else
        variant "$t" > "$v"
        echo "wrote $v"
    fi
done
exit $stale
