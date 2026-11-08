#!/bin/bash
# Installs the bot. Run as root from the directory holding vpsfort-xmpp-bot,
# vpsfort-xmpp-bot.service, vpsfort-xmpp-bot-client.service, vpsfort-xmpp-bot@.service and
# vpsfort-xmpp-bot.logrotate (deploy.sh copies them there). BOT_MODE in config.env picks the
# kind: admin (default) runs as the user ejabberd runs as, on the XMPP server; client runs as
# its own user vpsfort-xmpp-bot, anywhere, with the client unit.
#
#   bash install.sh            install and restart (the bots of the server's other domains
#                              too: they run the same binary)
#   bash install.sh --client   the same; on the first install, with the client mode's template
#   bash install.sh rollback   back to the previous binary and unit, for every bot here (a copy
#                              of this script stays in /opt/vpsfort-xmpp-bot for that)
#   bash install.sh --instance NAME
#                              the admin bot for another domain of this ejabberd (README,
#                              "Several domains"): vpsfort-xmpp-bot@NAME.service, its files in
#                              /opt/vpsfort-xmpp-bot/instances/NAME/, its log in
#                              /var/log/vpsfort-xmpp-bot/NAME/. The first run puts the config
#                              there and starts nothing; later runs check it and (re)start that
#                              bot. It uses the installed binary and units, so it runs as well
#                              from the copy:  bash /opt/vpsfort-xmpp-bot/install.sh --instance NAME
#
# The first install (no /opt/vpsfort-xmpp-bot/config.env yet) creates the directory and puts
# config.env.example (with --client, or where no user ejabberd exists: config-client.env.example)
# in place as config.env, then installs everything for that template's mode (the client mode's
# user, the binary, the unit, the log directory, the outbox) without starting the bot: fill
# the config in, then  systemctl enable --now vpsfort-xmpp-bot.
#
# (The Python bot can't come back: it only logs in with DIGEST-MD5 or PLAIN, which the
# server no longer offers.)
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

DIR=/opt/vpsfort-xmpp-bot
UNIT=/etc/systemd/system/vpsfort-xmpp-bot.service
# The bots for the server's other domains: one systemd instance each, a directory each.
TUNIT=/etc/systemd/system/vpsfort-xmpp-bot@.service
INSTANCES=$DIR/instances
WANTS=/etc/systemd/system/multi-user.target.wants
# the config being installed: the first bot's, or an instance's (--instance)
CONF=$DIR/config.env

usage() { echo "usage: bash install.sh [--client] [rollback]  |  bash install.sh --instance NAME" >&2; exit 2; }
TEMPLATE=
INSTANCE=
ACTION=
while [ $# -gt 0 ]; do
    case $1 in
        --client) TEMPLATE=config-client.env.example ;;
        --instance) [ $# -ge 2 ] || usage; INSTANCE=$2; shift ;;
        rollback) ACTION=rollback ;;
        *) usage ;;
    esac
    shift
done
if [ -n "$INSTANCE" ]; then
    if [ -n "$TEMPLATE" ] || [ -n "$ACTION" ]; then
        echo "--instance is an admin bot of this ejabberd (no --client), and rollback is for all bots at once:" >&2
        echo "  bash install.sh rollback" >&2
        exit 2
    fi
    # a systemd instance name, a directory name, and no escaping between the two
    if ! [[ $INSTANCE =~ ^[a-z0-9][a-z0-9._-]{0,62}$ ]]; then
        echo "--instance $INSTANCE: use lower-case letters, digits, '.', '_' and '-' (e.g. the domain)" >&2
        exit 2
    fi
fi

setting() { # the value of $1 in config.env ($2: another config), quotes removed
    grep -E "^$1=" "${2:-$CONF}" 2> /dev/null | tail -n 1 | cut -d= -f2- | tr -d "\"'" || true
}

# The names of the bots for other domains that have a config here.
instance_names() {
    local d
    for d in "$INSTANCES"/*/; do
        [ -f "${d}config.env" ] && basename "$d"
    done
    return 0
}

show_start() { # systemd's view, then the bot's own log (it doesn't write to the journal)
    # $1 the start time; an instance's: $2 its unit, $3 its config, $4 its default log directory
    local start=$1 unit=${2:-vpsfort-xmpp-bot} conf=${3:-$DIR/config.env} ld
    sleep 5
    echo
    journalctl -u "$unit" --since "$start" --no-pager -o cat | tail -n 5
    echo
    ld=$(setting LOG_DIR "$conf")
    tail -n 15 "${ld:-${4:-/var/log/vpsfort-xmpp-bot}}/bot.log" 2> /dev/null || true
    echo
}

# The bots for the server's other domains run the same binary: each running one is restarted
# onto the new (or previous) version. Their failure is reported, not fatal: the first bot's
# install goes on.
restart_instances() {
    local name unit start
    for name in $(instance_names); do
        unit=vpsfort-xmpp-bot@$name.service
        systemctl is-active -q "$unit" || continue
        start=$(date '+%Y-%m-%d %H:%M:%S')
        systemctl restart "$unit" || true
        show_start "$start" "$unit" "$INSTANCES/$name/config.env" "/var/log/vpsfort-xmpp-bot/$name"
        if systemctl is-active -q "$unit"; then
            echo "OK: $unit is running."
        else
            echo "WARNING: $unit is not running after the restart (journalctl -u $unit; back to the" >&2
            echo "  previous version for every bot:  bash $DIR/install.sh rollback)" >&2
        fi
    done
}

if [ "$ACTION" = rollback ]; then
    [ -f "$DIR/vpsfort-xmpp-bot.prev" ] || { echo "no $DIR/vpsfort-xmpp-bot.prev to roll back to" >&2; exit 1; }
    install -m 0755 "$DIR/vpsfort-xmpp-bot.prev" "$DIR/vpsfort-xmpp-bot"
    [ -f "$DIR/vpsfort-xmpp-bot.service.prev" ] && install -m 0644 "$DIR/vpsfort-xmpp-bot.service.prev" "$UNIT"
    [ -f "$DIR/vpsfort-xmpp-bot@.service.prev" ] && install -m 0644 "$DIR/vpsfort-xmpp-bot@.service.prev" "$TUNIT"
    systemctl daemon-reload
    if grep -qE '^[A-Z_]+=REPLACE' "$DIR/config.env" 2> /dev/null; then
        echo "vpsfort-xmpp-bot: not started ($DIR/config.env is not filled in)"
    else
        start=$(date '+%Y-%m-%d %H:%M:%S')
        systemctl restart vpsfort-xmpp-bot
        show_start "$start"
        systemctl --no-pager status vpsfort-xmpp-bot | head -5
    fi
    restart_instances
    exit 0
fi

# From the old names: up to 2026-10-17 the bot was /opt/xmpp-bot/xmppbot, run by
# xmpp-bot.service, logging to /var/log/xmpp-bot. Moved over once, keeping its state, OMEMO
# keys and trust pins, avatar, outbox and log; the old unit and logrotate rule go. vpsfort's
# settings naming the old outbox or unit are updated too (a copy of each file stays next to
# it) and vpsfort restarted. The XMPP account and OMEMO device stay the same. Safe to run
# again.
OLD_DIR=/opt/xmpp-bot
OLD_UNIT=/etc/systemd/system/xmpp-bot.service
migrated=no
migrate_old_names() {
    [ -e "$OLD_DIR" ] || [ -e "$OLD_UNIT" ] || return 0
    if [ -e "$OLD_DIR" ] && [ -e "$DIR" ]; then
        echo "both $OLD_DIR and $DIR exist: keep one (move what you need into $DIR, remove $OLD_DIR), then run this again" >&2
        exit 1
    fi
    echo "Renaming xmpp-bot to vpsfort-xmpp-bot (directory, unit, log directory)"
    local clean=no
    if systemctl is-active -q xmpp-bot && [ "$(systemctl show -p NRestarts --value xmpp-bot)" = 0 ]; then
        clean=yes
    fi
    systemctl disable -q --now xmpp-bot 2> /dev/null || true
    if [ -d "$OLD_DIR" ]; then
        mv "$OLD_DIR" "$DIR"
        rm -f "$DIR/xmpp-bot.service.prev" # names the old paths: no rollback target any more
        # the running version becomes the rollback target, as on every install
        if [ "$clean" = yes ] && [ -f "$DIR/xmppbot" ]; then
            mv "$DIR/xmppbot" "$DIR/vpsfort-xmpp-bot.prev"
            rm -f "$DIR/xmppbot.prev"
        elif [ -f "$DIR/xmppbot.prev" ]; then
            mv "$DIR/xmppbot.prev" "$DIR/vpsfort-xmpp-bot.prev"
        fi
        rm -f "$DIR/xmppbot"
        if [ -f "$DIR/config.env" ]; then
            cp -p "$DIR/config.env" "$DIR/config.env.pre-rename"
            sed -i -E 's#/opt/xmpp-bot\b#/opt/vpsfort-xmpp-bot#g; s#/var/log/xmpp-bot\b#/var/log/vpsfort-xmpp-bot#g' "$DIR/config.env"
            # the old binary (the rollback target) would fall back to the old log directory
            grep -qE '^LOG_DIR=' "$DIR/config.env" || echo "LOG_DIR=/var/log/vpsfort-xmpp-bot" >> "$DIR/config.env"
        fi
    fi
    if [ -d /var/log/xmpp-bot ] && [ ! -e /var/log/vpsfort-xmpp-bot ]; then
        mv /var/log/xmpp-bot /var/log/vpsfort-xmpp-bot
    fi
    rm -f /etc/logrotate.d/xmpp-bot
    # local changes (systemctl edit xmpp-bot) carry over
    if [ -d "$OLD_UNIT.d" ] && [ ! -e "$UNIT.d" ]; then
        mv "$OLD_UNIT.d" "$UNIT.d"
    fi
    rm -f "$OLD_UNIT"
    systemctl daemon-reload
    systemctl reset-failed xmpp-bot 2> /dev/null || true
    migrate_vpsfort 's#/opt/xmpp-bot\b#/opt/vpsfort-xmpp-bot#g; s#"xmpp-bot\.service"#"vpsfort-xmpp-bot.service"#g'
    migrated=yes
}

# vpsfort's settings: $1 (sed -E) applied to its config and the abuse report job's, each
# changed one kept as <file>.pre-rename-<time>. A config vpsfort then refuses goes back.
migrate_vpsfort() {
    local f bak changed=no
    for f in /etc/vpsfort/vpsfort.toml /etc/default/vpsfort-abuse-report; do
        [ -f "$f" ] || continue
        bak="$f.pre-rename-$(date +%Y%m%d-%H%M%S)"
        cp -p "$f" "$bak"
        sed -i -E "$1" "$f"
        if cmp -s "$f" "$bak"; then
            rm -f "$bak"
            continue
        fi
        echo "updated $f (before: $bak)"
        if [ "$f" = /etc/vpsfort/vpsfort.toml ]; then
            if [ -x /usr/local/bin/vpsfort ] && ! /usr/local/bin/vpsfort --config "$f" print-config > /dev/null; then
                echo "WARNING: vpsfort refuses the updated $f; restored it. Update it by hand:" >&2
                echo "  /opt/xmpp-bot -> $DIR, \"xmpp-bot.service\" -> \"vpsfort-xmpp-bot.service\"" >&2
                cp -p "$bak" "$f"
                continue
            fi
            changed=yes
        fi
    done
    if [ "$changed" = yes ] && systemctl is-active -q vpsfort; then
        systemctl restart vpsfort
        echo "restarted vpsfort (it writes to $DIR/outbox now)"
    fi
    if [ -f /etc/systemd/system/vpsfort-abuse-report.service ] \
        && ! grep -q "$DIR/outbox" /etc/systemd/system/vpsfort-abuse-report.service; then
        echo "WARNING: vpsfort-abuse-report.service still names only the old outbox: deploy the"
        echo "  current vpsfort too, or the weekly abuse report can't reach $DIR/outbox"
    fi
}

# vpsfort's [canary] xmpp names (or `except`, with $1 = except) on this host, lower case, one
# per line: from its effective config, where arrays span several lines.
canary_list() {
    [ -x /usr/local/bin/vpsfort ] && [ -f /etc/vpsfort/vpsfort.toml ] || return 0
    /usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml print-config 2> /dev/null | awk -v key="${1:-xmpp}" '
        /^\[/ { sec = $0; inlist = 0 }
        sec == "[canary]" && $1 == key && $2 == "=" { inlist = 1 }
        inlist {
            line = $0
            while (match(line, /"[^"]*"/)) { print tolower(substr(line, RSTART + 1, RLENGTH - 2)); line = substr(line, RSTART + RLENGTH) }
            if ($0 ~ /\]/) inlist = 0
        }'
}
# Whether the bot's account is a canary there: listed by name or full JID, not excepted.
bot_is_canary() {
    local jid local_part
    jid=$(setting BOT_JID | cut -d/ -f1 | tr '[:upper:]' '[:lower:]')
    local_part=${jid%%@*}
    [ -n "$jid" ] || return 1
    canary_list except | grep -qxF -e "$jid" -e "$local_part" && return 1
    canary_list xmpp | grep -qxF -e "$jid" -e "$local_part"
}
# vpsfort's integrity watch covers the account files: announce what useradd (or a rename)
# wrote, so it is logged instead of raised as a high alert.
announce_accounts() {
    [ -x /usr/local/bin/vpsfort ] && [ -f /etc/vpsfort/vpsfort.toml ] || return 0
    local f files=()
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do [ -f "$f" ] && files+=("$f"); done
    /usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml expect-change "${files[@]}" 2> /dev/null || true
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

# Owners and modes of a bot's files: $1 its directory (with $CONF), $2 its default log
# directory; $BOT its user. The directory is sticky: the bot may replace its own files (state
# and OMEMO keys are written to a temporary file and renamed), but not root's ones. $BOT is
# ejabberd in admin mode, vpsfort-xmpp-bot in client mode.
#   config.env (the password), omemo-trust.txt, avatar, OPENPGP_KEY
#                                         root:$BOT 640  (the bot reads them)
#   state.json, omemo.json                $BOT 600       (the bot writes them)
#   vpsfort-xmpp-bot, backups            root
# Sets LOGDIR, SP (BOT_STATE_PATH as set) and OUTBOX.
own_files() {
    local cdir=$1 f
    chown root:"$BOT" "$cdir"
    chmod 1770 "$cdir"
    own_file root:"$BOT" 640 "$CONF"
    for f in "$cdir/omemo-trust.txt" "$(setting AVATAR_PATH)"; do
        if [ -n "$f" ] && [ -f "$f" ]; then
            own_file root:"$BOT" 640 "$f"
        fi
    done
    for f in "$(setting BOT_STATE_PATH)" "$cdir/state.json" "$cdir/omemo.json" "$(setting OMEMO_STORE)"; do
        if [ -n "$f" ] && [ -f "$f" ]; then
            own_file "$BOT:$BOT" 600 "$f"
        fi
    done
    # leftovers of an interrupted write, possibly root's: the bot could not replace them
    rm -f "$cdir"/*.tmp
    LOGDIR=$(setting LOG_DIR); LOGDIR=${LOGDIR:-$2}
    mkdir -p "$LOGDIR"
    chown "$BOT:$BOT" "$LOGDIR"
    chmod 700 "$LOGDIR"
    # copies from the older, longer rotation (8 weeks): /privacy promises 14 days at most
    rm -f "$LOGDIR"/bot.log.[2-9]* "$LOGDIR"/bot.log.1.gz
    if [ -f "$LOGDIR/bot.log" ]; then
        own_file "$BOT:$BOT" 600 "$LOGDIR/bot.log"
    fi

    # Outbox: files for the admin (vpsfort's weekly abuse report, written by root and handed to
    # the bot, which sends them encrypted and deletes them). Sticky like the directory.
    SP=$(setting BOT_STATE_PATH)
    OUTBOX=$(setting OUTBOX_DIR); OUTBOX=${OUTBOX:-$(dirname "${SP:-$cdir/state.json}")/outbox}
    mkdir -p "$OUTBOX"
    chown root:"$BOT" "$OUTBOX"
    chmod 1770 "$OUTBOX"
    # files waiting there from the other mode's user: the bot could not delete them once sent
    find "$OUTBOX" -maxdepth 1 -type f -links 1 ! -user "$BOT" -exec chown -h "$BOT:$BOT" {} +
}

# vpsfort's integrity watch covers the units, the links that enable them and the logrotate
# rules: announce their new content (logged, not alerted). Each argument is PATH=SOURCE.
announce() {
    [ -x /usr/local/bin/vpsfort ] && [ -f /etc/vpsfort/vpsfort.toml ] || return 0
    /usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml expect-change "$@" 2> /dev/null || true
}

# --- The bots for the server's other domains (--instance) -----------------------------------

# A bot's account and files, from its config ($1) and directory ($2), as the bot resolves them
# (relative paths from its directory: the unit's WorkingDirectory). A placeholder is no value.
jid_of() { setting BOT_JID "$1" | cut -d/ -f1 | tr '[:upper:]' '[:lower:]' | grep -v '^replace' || true; }
domain_of() {
    local d
    d=$(setting XMPP_DOMAIN "$1" | tr '[:upper:]' '[:lower:]')
    [ -n "$d" ] || d=$(jid_of "$1" | cut -s -d@ -f2)
    case $d in replace*) d= ;; esac
    echo "$d"
}
path_in() { (cd "$1" 2> /dev/null && realpath -m -- "$2" 2> /dev/null) || echo "${2%/}"; }
state_dir_of() { local p; p=$(setting BOT_STATE_PATH "$1"); dirname "$(path_in "$2" "${p:-$2/state.json}")"; }
outbox_of() { local p; p=$(setting OUTBOX_DIR "$1"); path_in "$2" "${p:-$(state_dir_of "$1" "$2")/outbox}"; }
store_of() { local p; p=$(setting OMEMO_STORE "$1"); path_in "$2" "${p:-$(state_dir_of "$1" "$2")/omemo.json}"; }

# Each bot on this host needs an account and files of its own: two logins as one JID push each
# other out (and look like an attack to mod_fail2ban and vpsfort), two bots on one state
# directory, OMEMO store or outbox overwrite each other's (the bot itself refuses to start on
# those too). Checks the bot of config $1 (directory $2) against every other one here.
check_unique() {
    local conf=$1 cdir=$2 name other odir clash=no
    for name in - $(instance_names); do
        if [ "$name" = - ]; then other=$DIR/config.env odir=$DIR; else other=$INSTANCES/$name/config.env odir=$INSTANCES/$name; fi
        if [ "$other" = "$conf" ] || [ ! -f "$other" ]; then continue; fi
        if [ -n "$(jid_of "$conf")" ] && [ "$(jid_of "$conf")" = "$(jid_of "$other")" ]; then
            echo "BOT_JID $(jid_of "$conf") is also the account of the bot in $other: each bot needs its own" >&2
            echo "  (two logins as one JID push each other out)" >&2
            clash=yes
        fi
        if [ "$(state_dir_of "$conf" "$cdir")" = "$(state_dir_of "$other" "$odir")" ]; then
            echo "BOT_STATE_PATH: $conf and $other both keep their state in $(state_dir_of "$conf" "$cdir")" >&2
            clash=yes
        else
            if [ "$(store_of "$conf" "$cdir")" = "$(store_of "$other" "$odir")" ]; then
                echo "OMEMO_STORE: $conf and $other both name $(store_of "$conf" "$cdir")" >&2
                clash=yes
            fi
            if [ "$(outbox_of "$conf" "$cdir")" = "$(outbox_of "$other" "$odir")" ]; then
                echo "OUTBOX_DIR: $conf and $other both name $(outbox_of "$conf" "$cdir")" >&2
                clash=yes
            fi
        fi
        if [ -n "$(domain_of "$conf")" ] && [ "$(domain_of "$conf")" = "$(domain_of "$other")" ]; then
            echo "note: XMPP_DOMAIN $(domain_of "$conf") is also the domain of the bot in $other (two bots for one domain)"
        fi
    done
    if [ "$clash" = yes ]; then
        echo "Not installed: give each bot its own account and directory (README.md, \"Several domains\")." >&2
        exit 1
    fi
}

# --instance NAME: the admin bot for another domain of this ejabberd, as vpsfort-xmpp-bot@NAME
# with its files in $INSTANCES/NAME. It uses the installed binary and template unit.
setup_instance() {
    local name=$INSTANCE idir=$INSTANCES/$INSTANCE unit=vpsfort-xmpp-bot@$INSTANCE.service first=no start tmp jid
    CONF=$idir/config.env
    if [ ! -x "$DIR/vpsfort-xmpp-bot" ] || [ ! -f "$TUNIT" ]; then
        echo "$TUNIT is missing: install (or upgrade) the bot with this version first:  bash install.sh" >&2
        exit 1
    fi
    BOT=ejabberd
    if ! id "$BOT" > /dev/null 2>&1; then
        echo "no user '$BOT': the bots for an ejabberd's domains run on the XMPP server, as the user ejabberd runs as" >&2
        exit 1
    fi
    if [ ! -f "$CONF" ]; then
        [ -f config.env.example ] || { echo "config.env.example is missing next to this script" >&2; exit 1; }
        install -d -o root -g "$BOT" -m 0750 "$INSTANCES"
        install -d -o root -g root -m 0700 "$idir"   # own_files below opens it to the bot
        # the admin bot's template, naming this instance's files
        tmp=$(mktemp)
        sed -e "s#^\(\# vpsfort-xmpp-bot's settings\): $DIR/config\.env,#\1 for $name: $CONF,#" \
            -e "s#^\# vpsfort-xmpp-bot\.service (EnvironmentFile)#\# $unit (EnvironmentFile)#" \
            -e "s#^\(\#\{0,1\}[A-Z_]*=\)$DIR/#\1$idir/#" \
            -e "s#^\(\#\{0,1\}LOG_DIR=\)/var/log/vpsfort-xmpp-bot\$#\1/var/log/vpsfort-xmpp-bot/$name#" \
            config.env.example > "$tmp"
        # root's until own_files gives the bot's group read access
        install -m 0600 -o root -g root "$tmp" "$CONF"
        rm -f "$tmp"
        first=yes
    fi
    MODE=$(setting BOT_MODE); MODE=${MODE:-admin}
    if [ "$MODE" != admin ]; then
        echo "$CONF says BOT_MODE=$MODE: the bots for an ejabberd's domains are admin bots (the client bot" >&2
        echo "  runs once per host, as vpsfort-xmpp-bot.service)" >&2
        exit 1
    fi
    if bot_is_canary; then
        echo "BOT_JID $(setting BOT_JID) is a [canary] xmpp name in /etc/vpsfort/vpsfort.toml: every login of" >&2
        echo "  the bot would be a critical alert, and one failed login would ban it. Use another account, or" >&2
        echo "  add the name to [canary] except there (then: systemctl restart vpsfort)." >&2
        exit 1
    fi
    check_unique "$CONF" "$idir"
    own_files "$idir" "/var/log/vpsfort-xmpp-bot/$name"
    # /export: ejabberd keeps each domain in its own database (host_config's sql_database)
    if [ -n "$(setting EJABBERD_DB)" ]; then
        command -v sqlite3 > /dev/null || echo "WARNING: EJABBERD_DB is set but sqlite3 is missing (apt install sqlite3, or dnf install sqlite): /export sends no file"
    else
        echo "note: /export sends its full JSON file only with EJABBERD_DB set in $CONF: this domain's"
        echo "  sql_database (host_config in ejabberd.yml), e.g. EJABBERD_DB=/opt/ejabberd/database/example.org.db"
    fi

    if grep -qE '^[A-Z_]+=REPLACE' "$CONF"; then
        [ "$first" = yes ] && echo "New $CONF from the template config.env.example."
        echo "Not started: fill in $CONF ($(grep -oE '^[A-Z_]+=REPLACE' "$CONF" | cut -d= -f1 | xargs);"
        echo "README.md, \"Several domains\"), then:"
        echo "  1. the bot's account, if it has none yet:  ejabberdctl register bot <domain> '<a long random password>'"
        echo "  2. bash $DIR/install.sh --instance $name"
        exit 0
    fi
    announce "$WANTS/$unit=$TUNIT"
    systemctl enable -q "$unit"
    start=$(date '+%Y-%m-%d %H:%M:%S')
    systemctl restart "$unit"
    show_start "$start" "$unit" "$CONF" "/var/log/vpsfort-xmpp-bot/$name"
    if ! systemctl is-active -q "$unit"; then
        echo "FAILED: $unit is not running (journalctl -u $unit; its log: $LOGDIR/bot.log)" >&2
        exit 1
    fi
    jid=$(jid_of "$CONF")
    echo "OK: $unit is running as $jid for $(domain_of "$CONF"). Send /help to it to check."
    if [ ! -s "$idir/omemo-trust.txt" ] && ! grep -qi '^OMEMO=off' "$CONF"; then
        echo "OMEMO: no keys pinned yet, so any device of an allowed user is trusted. To pin yours, send"
        echo "/omemo to the bot, then add '<your jid> <fingerprint>' lines to $idir/omemo-trust.txt"
        echo "(as root; then: chown root:$BOT $idir/omemo-trust.txt && chmod 640 $idir/omemo-trust.txt)"
    fi
    if [ -f /etc/vpsfort/vpsfort.toml ] && ! grep -qF "\"$unit\"" /etc/vpsfort/vpsfort.toml; then
        echo "vpsfort reports a bot that stops for good only when its [sources] services lists it: add \"$unit\""
        echo "  there (/etc/vpsfort/vpsfort.toml; then: systemctl restart vpsfort)."
    fi
    echo "ejabberd's side of the login:"
    grep -h "Accepted c2s .* authentication for " /opt/ejabberd/logs/ejabberd.log 2> /dev/null | grep -F "authentication for $jid" | tail -n 1 || true
}

if [ -n "$INSTANCE" ]; then
    setup_instance
    exit 0
fi

migrate_old_names

# The first install: the directory and the config to fill in, from the mode's template.
first=no
if [ ! -f "$DIR/config.env" ]; then
    if [ -z "$TEMPLATE" ]; then
        # the admin bot's template where ejabberd runs, the client bot's elsewhere
        TEMPLATE=config.env.example
        id ejabberd > /dev/null 2>&1 || TEMPLATE=config-client.env.example
    fi
    [ -f "$TEMPLATE" ] || { echo "$TEMPLATE is missing next to this script" >&2; exit 1; }
    mkdir -p "$DIR"
    # root's until the owners below give the mode's user read access
    install -m 0600 -o root -g root "$TEMPLATE" "$DIR/config.env"
    first=yes
fi

MODE=$(setting BOT_MODE); MODE=${MODE:-admin}

if bot_is_canary; then
    # A canary is an account-level tripwire: one failed login = immediate ban of the address,
    # every login = a critical alert.
    if [ "$MODE" = admin ]; then
        echo "BOT_JID $(setting BOT_JID) is a [canary] xmpp name in /etc/vpsfort/vpsfort.toml: every login of" >&2
        echo "  the bot would be a critical alert, and one failed login would ban it. Use another account, or" >&2
        echo "  add the name to [canary] except there (then: systemctl restart vpsfort)." >&2
        exit 1
    fi
    echo "WARNING: BOT_JID $(setting BOT_JID) is a [canary] xmpp name in this host's vpsfort config; if the bot's"
    echo "  XMPP server runs vpsfort with the same list, every login is a critical alert there and one failed"
    echo "  login bans this address. Use another account, or add it to [canary] except on that server."
fi
case $MODE in
    admin) UNIT_SRC=vpsfort-xmpp-bot.service ;;
    client) UNIT_SRC=vpsfort-xmpp-bot-client.service ;;
    *) echo "BOT_MODE must be admin or client, not '$MODE'" >&2; exit 1 ;;
esac

if [ "$MODE" = client ]; then
    # A system user of its own, without a home or a shell: no ejabberd here.
    BOT=vpsfort-xmpp-bot
    if ! id "$BOT" > /dev/null 2>&1; then
        useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$BOT"
        echo "created the system user $BOT"
        announce_accounts
    fi
    # the admin's OpenPGP public key: root's, the bot only reads it
    PGPKEY=$(setting OPENPGP_KEY)
    if [ -n "$PGPKEY" ] && [ -f "$PGPKEY" ]; then
        own_file root:"$BOT" 640 "$PGPKEY"
    elif [ -n "$PGPKEY" ]; then
        echo "WARNING: OPENPGP_KEY=$PGPKEY does not exist, so the bot won't start. Export your public"
        echo "  key from OpenKeychain or iPGMail and copy it there (root:$BOT 640), or comment OPENPGP_KEY out."
    fi
else
# The bot runs as the user ejabberd runs as (the unit says User=ejabberd), so that
# ejabberdctl works for it without root.
BOT=ejabberd
HAVE=$(systemctl show -p User --value ejabberd 2>/dev/null || true)
id "$BOT" >/dev/null 2>&1 || { echo "no user '$BOT'" >&2; exit 1; }
if [ -n "$HAVE" ] && [ "$HAVE" != "$BOT" ]; then
    echo "ejabberd runs as '$HAVE', but vpsfort-xmpp-bot.service runs the bot as '$BOT'" >&2
    exit 1
fi

# ejabberdctl's CTL_OVER_HTTP mode (ejabberdctl.cfg) puts arguments into JSON unescaped:
# line breaks and quotes (announcements, passwords) break commands, and replies with
# non-ASCII text come back empty. The bot needs the classic mode.
CTLCFG=/opt/ejabberd/conf/ejabberdctl.cfg
if grep -qE '^[[:space:]]*CTL_OVER_HTTP=[^[:space:]]' "$CTLCFG" 2>/dev/null; then
    echo "WARNING: CTL_OVER_HTTP is on in $CTLCFG: /maintenance, /restart, multi-line"
    echo "  announcements and replies with non-ASCII text will fail. To turn it off:"
    echo "  sed -i 's/^CTL_OVER_HTTP=/#CTL_OVER_HTTP=/' $CTLCFG"
fi

# /export's JSON file reads ejabberd's database with the sqlite3 tool.
if [ -n "$(setting EJABBERD_DB)" ]; then
    command -v sqlite3 > /dev/null || echo "WARNING: EJABBERD_DB is set but sqlite3 is missing (apt install sqlite3, or dnf install sqlite): /export sends no file"
else
    echo "note: /export sends its full JSON file only with EJABBERD_DB set in config.env, e.g."
    echo "  EJABBERD_DB=/opt/ejabberd/database/example.org.v2.db"
fi
fi

check_unique "$DIR/config.env" "$DIR"
own_files "$DIR" /var/log/vpsfort-xmpp-bot
if [ "$MODE" = admin ] && [ "$OUTBOX" != /opt/vpsfort-xmpp-bot/outbox ]; then
    echo "note: the outbox is $OUTBOX; set ABUSE_REPORT_OUTBOX=$OUTBOX in /etc/default/vpsfort-abuse-report"
fi

# A copy of the state, root's: under a random name (mktemp, never through a link the bot's
# user could have put under a name made of the time), and read only if it is a file.
if [ "$MODE" = admin ] && [ -f "$DIR/state.json" ] && [ ! -L "$DIR/state.json" ]; then
    bak=$(mktemp "$DIR/state.json.bak-$(date +%Y%m%d-%H%M%S).XXXXXX") && cat "$DIR/state.json" > "$bak" || true
fi
# The running version becomes the rollback target, unless it is failing (restarting).
if [ "$migrated" = yes ]; then
    : # the version running under the old name became it above
elif systemctl is-active -q vpsfort-xmpp-bot && [ "$(systemctl show -p NRestarts --value vpsfort-xmpp-bot)" = 0 ]; then
    [ -x "$DIR/vpsfort-xmpp-bot" ] && cp -p "$DIR/vpsfort-xmpp-bot" "$DIR/vpsfort-xmpp-bot.prev"
    [ -f "$UNIT" ] && cp -p "$UNIT" "$DIR/vpsfort-xmpp-bot.service.prev"
    [ -f "$TUNIT" ] && cp -p "$TUNIT" "$DIR/vpsfort-xmpp-bot@.service.prev"
elif [ "$first" = no ]; then
    echo "vpsfort-xmpp-bot is not running cleanly: keeping the previous rollback version"
fi
install -m 0755 vpsfort-xmpp-bot "$DIR/vpsfort-xmpp-bot"
echo "Installed $("$DIR/vpsfort-xmpp-bot" --version)"
# the directory this runs from is removed afterwards: keep this script for rollback. It is
# here since the cd above, but $0 may name it from elsewhere (files/install.sh from a bundle).
install -o root -g root -m 0700 "${0##*/}" "$DIR/install.sh"
for f in config.env.example config-client.env.example; do
    [ -f "$f" ] && install -o root -g root -m 0644 "$f" "$DIR/$f"
done
# The logrotate rule as it will be installed (its `su` line names the bot's user).
rotate=$(mktemp)
sed "s/^\([[:space:]]*su\) ejabberd ejabberd\$/\1 $BOT $BOT/" vpsfort-xmpp-bot.logrotate > "$rotate"
# vpsfort's integrity watch covers the unit and the logrotate rule: announce their new content
# (logged, not alerted). In admin mode also the template unit of the bots for the server's
# other domains, and the links enabling them (they lead to it).
expected=("$UNIT=$UNIT_SRC" "$WANTS/vpsfort-xmpp-bot.service=$UNIT_SRC" "/etc/logrotate.d/vpsfort-xmpp-bot=$rotate")
if [ "$MODE" = admin ]; then
    expected+=("$TUNIT=vpsfort-xmpp-bot@.service")
    for name in $(instance_names); do
        if [ -L "$WANTS/vpsfort-xmpp-bot@$name.service" ]; then
            expected+=("$WANTS/vpsfort-xmpp-bot@$name.service=vpsfort-xmpp-bot@.service")
        fi
    done
fi
announce "${expected[@]}"
install -m 0644 "$UNIT_SRC" "$UNIT"
if [ "$MODE" = admin ]; then
    install -m 0644 vpsfort-xmpp-bot@.service "$TUNIT"
fi
install -m 0644 "$rotate" /etc/logrotate.d/vpsfort-xmpp-bot
rm -f "$rotate"
# ejabberd's own log files, 14 days at most like the rest (/privacy). Not when another
# rule already covers them: logrotate refuses duplicate entries.
if [ "$MODE" = client ]; then
    : # no ejabberd here
elif grep -lqs '/opt/ejabberd/logs' /etc/logrotate.d/* 2>/dev/null && ! [ -f /etc/logrotate.d/ejabberd-logs ]; then
    echo "WARNING: another logrotate rule covers /opt/ejabberd/logs; ejabberd-logs not installed:"
    grep -ls '/opt/ejabberd/logs' /etc/logrotate.d/*
else
    install -m 0644 ejabberd-logs.logrotate /etc/logrotate.d/ejabberd-logs
fi
if [ "$MODE" = admin ] && ! grep -qE '^log_rotate_size:[[:space:]]*infinity' /opt/ejabberd/conf/ejabberd.yml 2>/dev/null; then
    echo "note: ejabberd rotates its logs by size itself; for 14 days at most, set"
    echo "  log_rotate_size: infinity   in /opt/ejabberd/conf/ejabberd.yml (logrotate does it then)"
fi
systemctl daemon-reload

# The bots for the server's other domains (install.sh --instance): their files' owners and
# modes as above, and the running ones restarted onto this binary.
if [ "$MODE" = admin ]; then
    for name in $(instance_names); do
        # (in a subshell: own_files sets the first bot's CONF, LOGDIR, SP and OUTBOX)
        (CONF=$INSTANCES/$name/config.env && own_files "$INSTANCES/$name" "/var/log/vpsfort-xmpp-bot/$name")
    done
    restart_instances
fi

# not filled in yet: still the template's placeholders
if grep -qE '^[A-Z_]+=REPLACE' "$DIR/config.env"; then
    [ "$first" = yes ] && echo "New $DIR/config.env from the template $TEMPLATE ($MODE mode)."
    echo "Not started: fill in $DIR/config.env ($(grep -oE '^[A-Z_]+=REPLACE' "$DIR/config.env" | cut -d= -f1 | xargs); README.md, \"Settings\"), then:"
    if [ "$MODE" = client ]; then
        echo "  1. copy your OpenPGP public key to ${PGPKEY:-$DIR/admin.asc} (or comment OPENPGP_KEY out), then"
        echo "     chown root:$BOT ${PGPKEY:-$DIR/admin.asc} && chmod 640 ${PGPKEY:-$DIR/admin.asc}"
        echo "  2. systemctl enable --now vpsfort-xmpp-bot"
    else
        echo "  systemctl enable --now vpsfort-xmpp-bot"
    fi
    exit 0
fi

# enabled here: a unit renamed from xmpp-bot.service is not yet
systemctl enable -q vpsfort-xmpp-bot
start=$(date '+%Y-%m-%d %H:%M:%S')
systemctl restart vpsfort-xmpp-bot
show_start "$start"
if [ "$MODE" = client ] && systemctl is-active -q vpsfort-xmpp-bot; then
    echo "OK: vpsfort-xmpp-bot is running in client mode. Accept its subscription request in your"
    echo "client, and send it /status."
    # vpsfort feeds the bot only when its config says so (off by default)
    LG=/etc/vpsfort/vpsfort.toml
    if [ -f "$LG" ] && ! grep -qE "^[[:space:]]*xmpp_outbox[[:space:]]*=[[:space:]]*\"$OUTBOX\"" "$LG"; then
        echo "vpsfort doesn't write to this outbox yet. In [notify] of $LG set"
        echo "  xmpp_outbox = \"$OUTBOX\""
        echo "  xmpp_user = \"$BOT\""
        echo "(the weekly abuse report job reads it from there too)"
        echo "then: systemctl restart vpsfort, and test: vpsfort -c $LG notify-test --xmpp"
    fi
elif systemctl is-active -q vpsfort-xmpp-bot; then
    echo "OK: vpsfort-xmpp-bot is running. Send /help from Conversations to check."
    if [ ! -s "$DIR/omemo-trust.txt" ] && ! grep -qi '^OMEMO=off' "$DIR/config.env"; then
        echo "OMEMO: no keys pinned yet, so any device of an allowed user is trusted. To pin yours,"
        echo "send /omemo to the bot, then add '<your jid> <fingerprint>' lines to $DIR/omemo-trust.txt"
        echo "(as root; then: chown root:$BOT $DIR/omemo-trust.txt && chmod 640 $DIR/omemo-trust.txt)"
    fi
    echo "ejabberd's side of the login:"
    grep -h "Accepted c2s .* authentication for bot@" /opt/ejabberd/logs/ejabberd.log 2>/dev/null | tail -n 1 || true
else
    echo "FAILED: vpsfort-xmpp-bot is not running. Back to the previous version:  bash $DIR/install.sh rollback" >&2
    exit 1
fi
