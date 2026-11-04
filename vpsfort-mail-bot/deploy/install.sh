#!/bin/bash
# Installs the bot. Run as root from the directory holding vpsfort-mail-bot,
# vpsfort-mail-bot.service, vpsfort-mail-bot.logrotate and config.env.example (deploy.sh copies them there).
#
#   bash install.sh            install and restart
#   bash install.sh rollback   back to the previous binary and unit (a copy of this script
#                              stays in /opt/vpsfort-mail-bot for that)
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

DIR=/opt/vpsfort-mail-bot
UNIT=/etc/systemd/system/vpsfort-mail-bot.service
BOT=vpsfort-mail-bot

show_start() { # systemd's view, then the bot's own log (it doesn't write to the journal)
    local start=$1
    sleep 5
    echo
    journalctl -u vpsfort-mail-bot --since "$start" --no-pager -o cat | tail -n 5
    echo
    LD=$(grep -E '^LOG_DIR=' "$DIR/config.env" 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d "\"'")
    tail -n 10 "${LD:-/var/log/vpsfort-mail-bot}/bot.log" 2>/dev/null || true
    echo
}

if [ "${1:-}" = rollback ]; then
    [ -f "$DIR/vpsfort-mail-bot.prev" ] || { echo "no $DIR/vpsfort-mail-bot.prev to roll back to" >&2; exit 1; }
    install -m 0755 "$DIR/vpsfort-mail-bot.prev" "$DIR/vpsfort-mail-bot"
    [ -f "$DIR/vpsfort-mail-bot.service.prev" ] && install -m 0644 "$DIR/vpsfort-mail-bot.service.prev" "$UNIT"
    systemctl daemon-reload
    start=$(date '+%Y-%m-%d %H:%M:%S')
    systemctl restart vpsfort-mail-bot
    show_start "$start"
    systemctl --no-pager status vpsfort-mail-bot | head -5
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

# Owners and modes. The directory is sticky: the bot may delete its own files in the
# outbox, but not root's ones here.
#   config.env, OPENPGP_KEY, SMTP_PASSWORD_FILE, SMTP_CA_FILE   root:vpsfort-mail-bot 640 (the bot reads them)
#   SIGNING_KEY, PSEUDONYM_KEY                                 vpsfort-mail-bot 600 (the bot's secrets)
#   vpsfort-mail-bot, install.sh                              root
chown root:"$BOT" "$DIR"
chmod 1770 "$DIR"
chown root:"$BOT" "$DIR/config.env"
chmod 640 "$DIR/config.env"
for var in OPENPGP_KEY SMTP_PASSWORD_FILE SMTP_CA_FILE; do
    f=$(setting "$var")
    [ -n "$f" ] || continue
    if [ -f "$f" ]; then
        chown root:"$BOT" "$f"
        chmod 640 "$f"
    else
        echo "WARNING: $var=$f does not exist, so the bot won't start (or comment $var out)."
    fi
done
# SANITIZE's pseudonym key: the bot's, made by it on the first start (or by a `check` as root)
PK=$(setting PSEUDONYM_KEY); PK=${PK:-$DIR/pseudonym.key}
if [ -f "$PK" ]; then
    chown "$BOT:$BOT" "$PK"
    chmod 600 "$PK"
fi
SK=$(setting SIGNING_KEY)
if [ -n "$SK" ] && [ -f "$SK" ]; then
    chown "$BOT:$BOT" "$SK"
    chmod 600 "$SK"
elif [ -n "$SK" ]; then
    echo "WARNING: SIGNING_KEY=$SK does not exist, so the bot won't start (make it with keygen, or comment it out)."
fi
LOGDIR=$(setting LOG_DIR); LOGDIR=${LOGDIR:-/var/log/vpsfort-mail-bot}
mkdir -p "$LOGDIR"
chown "$BOT:$BOT" "$LOGDIR"
chmod 700 "$LOGDIR"
if [ -f "$LOGDIR/bot.log" ]; then
    chown "$BOT:$BOT" "$LOGDIR/bot.log"
    chmod 600 "$LOGDIR/bot.log"
fi

# Outbox: vpsfort (root) writes alerts and the weekly report here and hands each file to
# the bot, which sends and deletes it. Sticky like $DIR.
OUTBOX=$(setting OUTBOX_DIR); OUTBOX=${OUTBOX:-$DIR/outbox}
mkdir -p "$OUTBOX"
chown root:"$BOT" "$OUTBOX"
chmod 1770 "$OUTBOX"

# The running version becomes the rollback target, unless it is failing (restarting).
if systemctl is-active -q vpsfort-mail-bot && [ "$(systemctl show -p NRestarts --value vpsfort-mail-bot)" = 0 ]; then
    [ -x "$DIR/vpsfort-mail-bot" ] && cp -p "$DIR/vpsfort-mail-bot" "$DIR/vpsfort-mail-bot.prev"
    [ -f "$UNIT" ] && cp -p "$UNIT" "$DIR/vpsfort-mail-bot.service.prev"
elif [ -f "$UNIT" ]; then
    echo "vpsfort-mail-bot is not running cleanly: keeping the previous rollback version"
fi
install -m 0755 vpsfort-mail-bot "$DIR/vpsfort-mail-bot"
echo "Installed $("$DIR/vpsfort-mail-bot" --version)"
# the directory this runs from is removed afterwards: keep this script for rollback. It is
# here since the cd above, but $0 may name it from elsewhere (files/install.sh from a bundle).
install -o root -g root -m 0700 "${0##*/}" "$DIR/install.sh"
# vpsfort's integrity watch covers the unit and the logrotate rule: announce their new content
# (logged, not alerted).
if [ -x /usr/local/bin/vpsfort ] && [ -f /etc/vpsfort/vpsfort.toml ]; then
    /usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml expect-change "$UNIT=vpsfort-mail-bot.service" \
        "/etc/systemd/system/multi-user.target.wants/vpsfort-mail-bot.service=vpsfort-mail-bot.service" \
        "/etc/logrotate.d/vpsfort-mail-bot=vpsfort-mail-bot.logrotate" 2> /dev/null || true
fi
install -m 0644 vpsfort-mail-bot.service "$UNIT"
install -m 0644 vpsfort-mail-bot.logrotate /etc/logrotate.d/vpsfort-mail-bot
install -o root -g root -m 0644 config.env.example "$DIR/config.env.example"
systemctl daemon-reload

# not filled in yet: still config.env.example's placeholders, or no key
FROM=$(setting MAIL_FROM)
TO=$(setting MAIL_TO)
KEY=$(setting OPENPGP_KEY)
if [[ -z "$FROM" || "$FROM" == REPLACE* || -z "$TO" || "$TO" == REPLACE* || "$(setting SMTP_USER)" == REPLACE* || -z "$KEY" || ! -f "$KEY" ]]; then
    [ "$first" = yes ] && echo "New $DIR/config.env from the template."
    echo "Not started: fill in $DIR/config.env (MAIL_FROM, MAIL_TO, the mail server), then:"
    echo "  1. copy the recipients' OpenPGP public keys to ${KEY:-$DIR/recipients.asc}, and the SMTP password"
    echo "     (if any) to its SMTP_PASSWORD_FILE; then run this script again to set their owners and modes"
    echo "  2. set -a; . $DIR/config.env; set +a; $DIR/vpsfort-mail-bot check       # logs in, sends nothing"
    echo "     $DIR/vpsfort-mail-bot send-test                                     # a test mail"
    echo "  3. systemctl enable --now vpsfort-mail-bot"
    exit 0
fi

start=$(date '+%Y-%m-%d %H:%M:%S')
systemctl enable -q vpsfort-mail-bot
systemctl restart vpsfort-mail-bot
show_start "$start"
if ! systemctl is-active -q vpsfort-mail-bot; then
    echo "FAILED: vpsfort-mail-bot is not running. Back to the previous version:  bash $DIR/install.sh rollback" >&2
    exit 1
fi
echo "OK: vpsfort-mail-bot is running."
# vpsfort feeds the bot only when its config says so (off by default)
LG=/etc/vpsfort/vpsfort.toml
if [ -f "$LG" ] && ! grep -qE "^[[:space:]]*mail_outbox[[:space:]]*=[[:space:]]*\"$OUTBOX\"" "$LG"; then
    echo "vpsfort doesn't write to this outbox yet. In [notify] of $LG set"
    echo "  mail_outbox = \"$OUTBOX\""
    echo "  mail_user = \"$BOT\""
    echo "(the weekly abuse report job reads it from there too)"
    echo "then: systemctl restart vpsfort, and test: vpsfort -c $LG notify-test --mail"
fi
