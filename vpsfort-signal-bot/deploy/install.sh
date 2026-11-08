#!/bin/bash
# Installs the bot. Run as root from the directory holding vpsfort-signal-bot,
# vpsfort-signal-bot.service, vpsfort-signal-bot.logrotate and config.env.example (deploy.sh copies them there).
#
#   bash install.sh            install and restart
#   bash install.sh rollback   back to the previous binary and unit (a copy of this script
#                              stays in /opt/vpsfort-signal-bot for that)
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

DIR=/opt/vpsfort-signal-bot
UNIT=/etc/systemd/system/vpsfort-signal-bot.service
BOT=vpsfort-signal-bot

show_start() { # systemd's view, then the bot's own log (it doesn't write to the journal)
    local start=$1
    sleep 5
    echo
    journalctl -u $BOT --since "$start" --no-pager -o cat | tail -n 5
    echo
    LD=$(grep -E '^LOG_DIR=' "$DIR/config.env" 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d "\"'")
    tail -n 10 "${LD:-/var/log/$BOT}/bot.log" 2>/dev/null || true
    echo
}

if [ "${1:-}" = rollback ]; then
    [ -f "$DIR/$BOT.prev" ] || { echo "no $DIR/$BOT.prev to roll back to" >&2; exit 1; }
    install -m 0755 "$DIR/$BOT.prev" "$DIR/$BOT"
    [ -f "$DIR/$BOT.service.prev" ] && install -m 0644 "$DIR/$BOT.service.prev" "$UNIT"
    systemctl daemon-reload
    start=$(date '+%Y-%m-%d %H:%M:%S')
    systemctl restart $BOT
    show_start "$start"
    systemctl --no-pager status $BOT | head -5
    exit 0
fi

# vpsfort's integrity watch covers the account files: announce what useradd (or a rename)
# wrote, so it is logged instead of raised as a high alert.
announce_accounts() {
    [ -x /usr/local/bin/vpsfort ] && [ -f /etc/vpsfort/vpsfort.toml ] || return 0
    local f files=()
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do [ -f "$f" ] && files+=("$f"); done
    /usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml expect-change "${files[@]}" 2> /dev/null || true
}

# A system user of its own, without a home or a shell.
if ! id "$BOT" > /dev/null 2>&1; then
    useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$BOT"
    echo "created the system user $BOT"
    announce_accounts
fi

mkdir -p "$DIR"
first=no
if [ ! -f "$DIR/config.env" ]; then
    install -m 0640 -o root -g "$BOT" config.env.example "$DIR/config.env"
    first=yes
fi

setting() { # the value of $1 in config.env, quotes removed
    grep -E "^$1=" "$DIR/config.env" | tail -n 1 | cut -d= -f2- | tr -d "\"'" || true
}

# The owner and mode of one of the bot's files in a directory the bot's user writes to ($DIR,
# its log directory): only a regular file with one name, never through a link the bot could
# have planted there, which would make root change another file (chown -h follows no link;
# chmod would, so it isn't run on one).
own_file() { # owner mode file
    [ -n "$3" ] && [ -f "$3" ] && [ ! -L "$3" ] || return 0
    if [ "$(stat -c %h "$3" 2> /dev/null)" != 1 ]; then
        echo "WARNING: $3 has more than one name (a hard link): left as it is"
        return 0
    fi
    chown -h "$1" "$3"
    chmod "$2" "$3"
}

# Owners and modes. The directory is sticky: the bot may replace its own files (the state
# is written to a temporary file and renamed), but not root's ones.
#   config.env, OPENPGP_KEY              root:vpsfort-signal-bot 640  (the bot reads them)
#   state.json, pseudonym.key            vpsfort-signal-bot 600       (the bot writes them)
#   signal-cli/ (the account's keys)     vpsfort-signal-bot 700
#   vpsfort-signal-bot, install.sh      root
chown root:"$BOT" "$DIR"
chmod 1770 "$DIR"
chown root:"$BOT" "$DIR/config.env"
chmod 640 "$DIR/config.env"
SP=$(setting BOT_STATE_PATH); SP=${SP:-$DIR/state.json}
KEY=$(setting PSEUDONYM_KEY); KEY=${KEY:-$(dirname "$SP")/pseudonym.key}
# the admin's OpenPGP public key: root's, the bot only reads it
PGPKEY=$(setting OPENPGP_KEY)
if [ -n "$PGPKEY" ] && [ -f "$PGPKEY" ]; then
    own_file root:"$BOT" 640 "$PGPKEY"
elif [ -n "$PGPKEY" ]; then
    echo "WARNING: OPENPGP_KEY=$PGPKEY does not exist, so the bot won't start. Export your public"
    echo "  key from OpenKeychain or iPGMail and copy it there (root:$BOT 640), or comment OPENPGP_KEY out."
fi
for f in "$SP" "$KEY"; do
    if [ -f "$f" ]; then
        own_file "$BOT:$BOT" 600 "$f"
    fi
done
# leftovers of an interrupted write, possibly root's: the bot could not replace them
rm -f "${DIR:?}"/*.tmp
LOGDIR=$(setting LOG_DIR); LOGDIR=${LOGDIR:-/var/log/$BOT}
mkdir -p "$LOGDIR"
chown "$BOT:$BOT" "$LOGDIR"
chmod 700 "$LOGDIR"
if [ -f "$LOGDIR/bot.log" ]; then
    own_file "$BOT:$BOT" 600 "$LOGDIR/bot.log"
fi

# signal-cli's data: the bot account's identity keys and sessions. The bot's alone.
DATA=$(setting SIGNAL_CLI_DATA); DATA=${DATA:-$DIR/signal-cli}
mkdir -p "$DATA"
chown -R "$BOT:$BOT" "$DATA"
chmod 700 "$DATA"

# Outbox: vpsfort (root) writes alerts and the weekly report here and hands each file to
# the bot, which sends and deletes it. Sticky like $DIR.
OUTBOX=$(setting OUTBOX_DIR); OUTBOX=${OUTBOX:-$(dirname "$SP")/outbox}
mkdir -p "$OUTBOX"
chown root:"$BOT" "$OUTBOX"
chmod 1770 "$OUTBOX"

# The running version becomes the rollback target, unless it is failing (restarting).
if systemctl is-active -q $BOT && [ "$(systemctl show -p NRestarts --value $BOT)" = 0 ]; then
    [ -x "$DIR/$BOT" ] && cp -p "$DIR/$BOT" "$DIR/$BOT.prev"
    [ -f "$UNIT" ] && cp -p "$UNIT" "$DIR/$BOT.service.prev"
elif [ -f "$UNIT" ]; then
    echo "$BOT is not running cleanly: keeping the previous rollback version"
fi
install -m 0755 $BOT "$DIR/$BOT"
echo "Installed $("$DIR/$BOT" --version)"
# the directory this runs from is removed afterwards: keep this script for rollback. It is
# here since the cd above, but $0 may name it from elsewhere (files/install.sh from a bundle).
install -o root -g root -m 0700 "${0##*/}" "$DIR/install.sh"
# vpsfort's integrity watch covers the unit and the logrotate rule: announce their new content
# (logged, not alerted).
if [ -x /usr/local/bin/vpsfort ] && [ -f /etc/vpsfort/vpsfort.toml ]; then
    /usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml expect-change "$UNIT=$BOT.service" \
        "/etc/systemd/system/multi-user.target.wants/$BOT.service=$BOT.service" \
        "/etc/logrotate.d/$BOT=$BOT.logrotate" 2> /dev/null || true
fi
install -m 0644 $BOT.service "$UNIT"
install -m 0644 $BOT.logrotate /etc/logrotate.d/$BOT
install -o root -g root -m 0644 config.env.example "$DIR/config.env.example"
systemctl daemon-reload

# not filled in yet: empty, or still config.env.example's placeholders
placeholder() { local v; v=$(setting "$1"); [ -z "$v" ] || [[ "$v" == *REPLACE* ]]; }
if placeholder SIGNAL_ACCOUNT || placeholder ADMIN; then
    [ "$first" = yes ] && echo "New $DIR/config.env from the template."
    echo "Not started: $DIR/config.env needs SIGNAL_ACCOUNT and ADMIN. Then run this again."
    exit 0
fi
CLI=$(setting SIGNAL_CLI); CLI=${CLI:-/usr/local/bin/signal-cli}
if [ ! -x "$CLI" ]; then
    echo "Not started: no signal-cli at $CLI (SIGNAL_CLI). Install it (README, \"signal-cli\"), then run this again."
    exit 0
fi
ACCOUNT=$(setting SIGNAL_ACCOUNT)
RUN="runuser -u $BOT -- env SIGNAL_CLI=$CLI SIGNAL_CLI_DATA=$DATA SIGNAL_ACCOUNT=$ACCOUNT $DIR/$BOT"
if ! grep -qsF "\"$ACCOUNT\"" "$DATA/data/accounts.json"; then
    echo "Not started: signal-cli has no account $ACCOUNT yet. Register the bot's number (README, \"Setup\"):"
    echo "  $RUN signal-cli register --captcha 'signalcaptcha://...'"
    echo "      (the captcha token from https://signalcaptchas.org/registration/generate.html)"
    echo "  $RUN signal-cli verify CODE      # the code Signal sent by SMS"
    echo "or link signal-cli to a Signal account of the bot's own as a device:"
    echo "  $RUN signal-cli link -n vpsfort    # then open the printed link as a QR code in that account's app"
    echo "Then: systemctl enable --now $BOT"
    exit 0
fi

start=$(date '+%Y-%m-%d %H:%M:%S')
systemctl enable -q $BOT
systemctl restart $BOT
show_start "$start"
if ! systemctl is-active -q $BOT; then
    echo "FAILED: $BOT is not running. Back to the previous version:  bash $DIR/install.sh rollback" >&2
    exit 1
fi
echo "OK: $BOT is running. Its first message to you pins your safety number (see bot.log)."
# vpsfort feeds the bot only when its config says so (off by default)
LG=/etc/vpsfort/vpsfort.toml
if [ -f "$LG" ] && ! grep -qE "^[[:space:]]*signal_outbox[[:space:]]*=[[:space:]]*\"$OUTBOX\"" "$LG"; then
    echo "vpsfort doesn't write to this outbox yet. In [notify] of $LG set"
    echo "  signal_outbox = \"$OUTBOX\""
    echo "  signal_user = \"$BOT\""
    echo "(the weekly abuse report job reads it from there too)"
    echo "then: systemctl restart vpsfort, and test: vpsfort -c $LG notify-test --signal"
fi
