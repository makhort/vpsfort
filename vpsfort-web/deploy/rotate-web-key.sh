#!/bin/bash
# Replaces the web key on every node (the agents and the console) without a moment in which
# the console can't ask an agent: vpsfort-web's agent also answers requests sealed under
# <WEB_KEY_FILE>.next and <WEB_KEY_FILE>.prev, while the console sends with WEB_KEY_FILE.
# Three rounds, each finished on every node before the next:
#
#   ./deploy/rotate-web-key.sh start  xmpp vpn   # new key as <key>.next everywhere
#   ./deploy/rotate-web-key.sh switch xmpp vpn   # send with it; the old one becomes .prev
#   ./deploy/rotate-web-key.sh finish xmpp vpn   # drop the old key
#
# Like deploy.sh, this only copies files (ssh host aliases) to a fresh /tmp/vpsfort-web-rotate.XXXX
# on each node; then paste the printed command into a root shell on each node (it checks the
# files, runs the step and restarts vpsfort-web). Share links made before 'switch' end with
# it: they are signed with the key.
set -euo pipefail
cd "$(dirname "$0")/.."

step=${1:-}
shift || true
hosts=("$@")
[ ${#hosts[@]} -gt 0 ] || { echo "name the hosts (ssh aliases) after the step" >&2; exit 2; }
case "$step" in
    start | switch | finish) ;;
    *)
        sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac

key=deploy/web.key
vpsfort_web() { cargo run --quiet --release -- "$@"; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
if [ "$step" = start ]; then
    if [ ! -f "$key.next" ]; then
        (umask 077 && vpsfort_web keygen > "$key.next.tmp" && mv "$key.next.tmp" "$key.next")
        echo "New key: $key.next (git-ignored)"
    fi
    cp "$key.next" "$stage/new.key"
    chmod 600 "$stage/new.key"
fi
# The fingerprint each node must end up with: the new key (still .next here until 'finish').
if [ -f "$key.next" ]; then
    expect=$(WEB_KEY_FILE=$key.next vpsfort_web key-id | cut -d' ' -f1)
elif [ -f "$key" ]; then
    expect=$(WEB_KEY_FILE=$key vpsfort_web key-id | cut -d' ' -f1)
else
    echo "no $key here: copy the current web key to $key first (or run 'start')" >&2
    exit 1
fi

# Run on the node as root, from the private directory it was copied into.
cat > "$stage/rotate.sh" <<'REMOTE'
set -euo pipefail
step=${1:-}
expect=@EXPECT@
dir=$(cd "$(dirname "$0")" && pwd)
trap 'rm -rf "$dir"' EXIT
if [ "$(id -u)" != 0 ]; then
    echo "run this as root (it installs the key and restarts vpsfort-web)" >&2
    exit 1
fi
env_file=/opt/vpsfort-web/config.env
kf=$(grep -E '^WEB_KEY_FILE=' "$env_file" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' || true)
kf=${kf:-/opt/vpsfort-web/web.key}
case "$step" in
    start)
        [ -f "$dir/new.key" ] || { echo "no new key next to this script: stage 'start' again" >&2; exit 1; }
        install -m 640 -o root -g vpsfort-web "$dir/new.key" "$kf.next"
        ;;
    switch)
        if [ -f "$kf.next" ]; then
            cp -p "$kf" "$kf.prev"
            mv "$kf.next" "$kf"
        elif [ -f "$kf.prev" ]; then
            echo "already switched here"
            step=none
        else
            echo "no $kf.next - run 'start' on this node first" >&2
            exit 1
        fi
        ;;
    finish)
        if [ -f "$kf.next" ]; then
            echo "$kf.next is still there - run 'switch' on this node first" >&2
            exit 1
        fi
        rm -f "$kf.prev"
        ;;
    *)
        echo "usage: bash $0 start|switch|finish" >&2
        exit 2
        ;;
esac
if [ "$step" != none ]; then
    systemctl restart vpsfort-web
    sleep 2
    systemctl is-active --quiet vpsfort-web || { echo "vpsfort-web did not start: journalctl -u vpsfort-web -n 30" >&2; exit 1; }
fi
ids=$(set -a; . "$env_file"; set +a; /opt/vpsfort-web/vpsfort-web key-id)
echo "$ids"
if printf '%s\n' "$ids" | grep -q "^$expect"; then
    echo "OK: the new key ($expect) is in place."
else
    echo "WARNING: the new key ($expect) is not among the keys above." >&2
    exit 1
fi
REMOTE
sed -i.bak "s/@EXPECT@/$expect/" "$stage/rotate.sh" && rm "$stage/rotate.sh.bak"

# Root copies the files into a private directory and checks them against these hashes,
# pasted into the root shell: the SSH user owning the staging directory can't swap them.
(cd "$stage" && shasum -a 256 -- * > SHA256SUMS)
MANIFEST=$(shasum -a 256 "$stage/SHA256SUMS" | cut -d' ' -f1)

cmds=()
for h in "${hosts[@]}"; do
    remote=/tmp/vpsfort-web-rotate.$(openssl rand -hex 8)
    {
        echo "mkdir $remote"
        echo "chmod 700 $remote"
        for f in "$stage"/*; do echo "put \"$f\" $remote/"; done
    } | sftp -q -o BatchMode=no -b - "$h" >/dev/null
    echo "Copied to $h:$remote"
    cmds+=("$h:" "d=\$(mktemp -d /root/vpsfort-web-rotate.XXXXXX) && cp -R $remote/. \"\$d\" && [ -z \"\$(find \"\$d\" -mindepth 1 ! -type f)\" ] && cd \"\$d\" && echo '$MANIFEST  SHA256SUMS' | sha256sum -c --quiet && sha256sum -c --quiet --strict SHA256SUMS && bash rotate.sh $step; cd /; rm -rf \"\$d\" $remote" "")
done
echo
echo "Now paste into a root shell on each node:"
printf '%s\n' "${cmds[@]}"
echo "Each node should end with 'OK: the new key ($expect) is in place.'"
case "$step" in
    start) echo "Then, once every node is done:  $0 switch ${hosts[*]}" ;;
    switch) echo "Then, once every node is done:  $0 finish ${hosts[*]}" ;;
    finish)
        if [ -f "$key.next" ]; then
            mv "$key.next" "$key"
            echo "Local $key is the new key now."
        fi
        ;;
esac
