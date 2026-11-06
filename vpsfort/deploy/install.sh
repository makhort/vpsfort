#!/bin/bash
# Installs vpsfort on the server. Run as root from the directory containing
# the vpsfort binary, vpsfort.toml and vpsfort.service.
# Leaves the existing Python cron jobs untouched (run both side by side while in shadow mode).
set -euo pipefail
cd "$(dirname "$0")"

# Defaults of the version being replaced, so config-diff can tell new options and
# changed defaults apart (print-config without a config file prints the defaults).
old_defaults=""
if [ -x /usr/local/bin/vpsfort ]; then
    old_defaults=$(mktemp)
    trap 'rm -f "$old_defaults"' EXIT
    env -u VPSFORT_CONFIG /usr/local/bin/vpsfort print-config > "$old_defaults" 2>/dev/null || old_defaults=""
fi

# The files below are in the integrity watch: announce their new content first, so the
# running daemon logs these changes instead of raising "may be compromised" alerts. Not on a
# first install (a release bundle's puts the config in place first): nothing watches them yet,
# and there is no state directory to announce them in.
if [ -f /etc/vpsfort/vpsfort.toml ] && [ -x /usr/local/bin/vpsfort ]; then
    sysd=/etc/systemd/system
    prev=""
    [ -x /usr/local/bin/vpsfort ] && prev=/usr/local/bin/vpsfort.prev=/usr/local/bin/vpsfort
    ./vpsfort --config /etc/vpsfort/vpsfort.toml expect-change \
        /usr/local/bin/vpsfort=vpsfort \
        $prev \
        $sysd/vpsfort.service=vpsfort.service \
        $sysd/multi-user.target.wants/vpsfort.service=vpsfort.service \
        /usr/local/sbin/vpsfort-avscan=vpsfort-avscan.sh \
        /usr/local/sbin/vpsfort-abuse-report=vpsfort-abuse-report.sh \
        $sysd/vpsfort-avscan.service=vpsfort-avscan.service \
        $sysd/vpsfort-avscan.timer=vpsfort-avscan.timer \
        $sysd/timers.target.wants/vpsfort-avscan.timer=vpsfort-avscan.timer \
        $sysd/vpsfort-abuse-report.service=vpsfort-abuse-report.service \
        $sysd/vpsfort-abuse-report.timer=vpsfort-abuse-report.timer \
        $sysd/timers.target.wants/vpsfort-abuse-report.timer=vpsfort-abuse-report.timer \
        /etc/logrotate.d/vpsfort=vpsfort.logrotate \
        /etc/vpsfort/vpsfort.toml.new=vpsfort.toml \
        || echo "WARNING: could not announce the new files: expect integrity alerts for them"
fi

# Keep the replaced binary: roll back with  mv /usr/local/bin/vpsfort.prev /usr/local/bin/vpsfort
if [ -x /usr/local/bin/vpsfort ]; then
    cp -p /usr/local/bin/vpsfort /usr/local/bin/vpsfort.prev
fi
install -m 0755 vpsfort /usr/local/bin/vpsfort
echo "Installed $(/usr/local/bin/vpsfort --version)"
install -d -m 0755 /etc/vpsfort
if [ -f /etc/vpsfort/vpsfort.toml ]; then
    install -m 0600 vpsfort.toml /etc/vpsfort/vpsfort.toml.new
    echo "Kept existing /etc/vpsfort/vpsfort.toml (new template saved as vpsfort.toml.new)"
    echo
    echo "=== vpsfort config-diff: what this upgrade means for your config ==="
    /usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml config-diff ${old_defaults:+--against "$old_defaults"}
    echo "======================================================================"
    echo
else
    install -m 0600 vpsfort.toml /etc/vpsfort/vpsfort.toml
fi
install -m 0644 vpsfort.service /etc/systemd/system/vpsfort.service
install -m 0644 vpsfort.logrotate /etc/logrotate.d/vpsfort
# Scheduled ClamAV scan for [antivirus]: always installed, enabled below only when configured.
install -m 0755 vpsfort-avscan.sh /usr/local/sbin/vpsfort-avscan
install -m 0644 vpsfort-avscan.service vpsfort-avscan.timer /etc/systemd/system/
if [ ! -f /etc/default/vpsfort-avscan ]; then
    install -m 0644 vpsfort-avscan.default /etc/default/vpsfort-avscan
fi
# Weekly abuse report for the admin bot: enabled below unless ABUSE_REPORT_ROLE=off.
install -m 0755 vpsfort-abuse-report.sh /usr/local/sbin/vpsfort-abuse-report
install -m 0644 vpsfort-abuse-report.service vpsfort-abuse-report.timer /etc/systemd/system/
if [ ! -f /etc/default/vpsfort-abuse-report ]; then
    install -m 0644 vpsfort-abuse-report.default /etc/default/vpsfort-abuse-report
fi
if [ -f cluster.key ] && [ ! -f /etc/vpsfort/cluster.key ]; then
    install -m 0600 cluster.key /etc/vpsfort/cluster.key
    echo "Installed cluster key /etc/vpsfort/cluster.key"
fi

/usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml print-config > /dev/null
echo "Config OK"

# An own account on the canary list ([canary] ssh = ["*"] with a gateway user missing from
# `except`) bans the admin at the next login: say so now, while this SSH session is open.
canary_warning() {
    local out
    if ! out=$(/usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml canary-check 2>&1); then
        echo
        echo "################################################################################"
        echo "# WARNING: an account of this host is on vpsfort's canary list:"
        printf '%s\n' "$out" | sed 's/^/#   /'
        echo "# Its NEXT SSH LOGIN WILL BE BANNED (and a critical alert raised). Fix it NOW,"
        echo "# while this session is open: add the account to [canary] except in"
        echo "# /etc/vpsfort/vpsfort.toml and run  systemctl restart vpsfort"
        echo "################################################################################"
        echo
    fi
}
canary_warning

# Dry run of the nftables ruleset against this kernel (checks rate-limit support too).
if command -v nft > /dev/null; then
    if /usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml print-nft | nft -c -f -; then
        echo "nftables ruleset OK (dry run)"
    elif /usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml print-nft --no-tripwires | nft -c -f - 2> /dev/null; then
        echo "WARNING: this kernel/nft rejects the kernel tripwire rules ([ports] kernel_tripwires); vpsfort runs without them"
    else
        echo "WARNING: this kernel/nft rejects the ruleset above; vpsfort would fall back to ufw or iptables"
    fi
fi

if command -v firewall-cmd > /dev/null && firewall-cmd --state > /dev/null 2>&1; then
    # firewalld (Fedora, RHEL): the peers' rich rules in the default zone, kept across reloads
    rules=$(/usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml cluster-ufw-rules --firewalld)
    if [ -n "$rules" ]; then
        echo "$rules" | while read -r rule; do
            echo "+ $rule"
            eval "$rule" > /dev/null
        done
        firewall-cmd --reload > /dev/null
    fi
    if [ "$(firewall-cmd --get-log-denied)" = off ]; then
        echo "NOTE: firewalld doesn't log denied packets; enable it for firewall-based detection:"
        echo "    firewall-cmd --set-log-denied=unicast"
    fi
elif command -v ufw > /dev/null; then
    /usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml cluster-ufw-rules | while read -r rule; do
        echo "+ $rule"
        eval "$rule"
    done
    if ! ufw status verbose | grep -q '^Logging: on'; then
        echo "NOTE: UFW logging is off; enable it for firewall-based detection:  ufw logging low"
    fi
else
    # Plain iptables (e.g. iptables-persistent): the rules are yours, so only suggest them.
    rules=$(/usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml cluster-ufw-rules --iptables)
    if [ -n "$rules" ]; then
        echo "NOTE: no ufw; open the cluster port to the peers in your iptables rules (and save them):"
        echo "$rules" | sed 's/^/    /'
    fi
    echo "NOTE: for firewall-based detection, log dropped packets with the prefix vpsfort reads, as the"
    echo "      last rules of INPUT (before its DROP policy or final DROP rule), e.g.:"
    echo "    iptables  -A INPUT -m limit --limit 10/second -j LOG --log-prefix '[VPSFORT BLOCK] '"
    echo "    ip6tables -A INPUT -m limit --limit 10/second -j LOG --log-prefix '[VPSFORT BLOCK] '"
fi

systemctl daemon-reload
# Enabled before vpsfort (re)starts, so a first cron-watch baseline includes the timer.
setting() {
    /usr/local/bin/vpsfort --config /etc/vpsfort/vpsfort.toml print-config \
        | awk -v sec="[$1]" -v key="$2" '/^\[/ { s = ($0 == sec) } s && $1 == key { gsub(/"/, "", $3); print $3 }'
}
if [ "$(setting antivirus enabled)" = true ]; then
    if command -v clamscan > /dev/null || command -v clamdscan > /dev/null; then
        systemctl enable --now vpsfort-avscan.timer
        echo "Virus scan: vpsfort-avscan.timer enabled ($(systemctl show -P TimersCalendar vpsfort-avscan.timer | grep -o 'OnCalendar=[^;]*' || true))"
        if [ "$(setting antivirus log)" != /var/log/vpsfort/avscan.log ] && ! grep -q '^AVSCAN_LOG=' /etc/default/vpsfort-avscan; then
            echo "NOTE: [antivirus] log is not the scan script's log; set AVSCAN_LOG in /etc/default/vpsfort-avscan"
        fi
        if { crontab -l 2> /dev/null; cat /etc/crontab /etc/cron.d/* 2> /dev/null; } | grep -v '^\s*#' | grep -qE 'clamscan|clamdscan|av_?scan'; then
            echo "NOTE: a cron job runs a virus scan too; remove it (crontab -e) so two scans don't run"
            echo "      (each clamscan loads ~1-1.5 GB of signatures) - vpsfort-avscan.timer replaces it"
        fi
    else
        echo "WARNING: [antivirus] is enabled but ClamAV is not installed:  apt install clamav clamav-freshclam  (Fedora: dnf install clamav clamav-freshclam; older Fedora, RHEL: clamav-update)"
    fi
elif systemctl is-enabled --quiet vpsfort-avscan.timer 2> /dev/null; then
    systemctl disable --now vpsfort-avscan.timer
    echo "Virus scan: vpsfort-avscan.timer disabled ([antivirus] enabled = false)"
fi

abuse_role=$( (set +u; . /etc/default/vpsfort-abuse-report; echo "${ABUSE_REPORT_ROLE:-auto}") )
if [ "$abuse_role" = off ]; then
    if systemctl is-enabled --quiet vpsfort-abuse-report.timer 2> /dev/null; then
        systemctl disable --now vpsfort-abuse-report.timer
        echo "Abuse report: vpsfort-abuse-report.timer disabled (ABUSE_REPORT_ROLE=off)"
    fi
else
    systemctl enable --now vpsfort-abuse-report.timer
    echo "Abuse report: weekly, ABUSE_REPORT_ROLE=$abuse_role (/etc/default/vpsfort-abuse-report);" \
        "try it now with  systemctl start vpsfort-abuse-report"
fi

# Files written by older versions were world-readable (addresses, account names; the config
# holds users' addresses and JIDs).
chmod 0600 /var/lib/vpsfort/state.json /etc/vpsfort/vpsfort.toml /etc/vpsfort/vpsfort.toml.new 2>/dev/null || true
chmod 0640 /var/log/vpsfort/actions.jsonl* 2>/dev/null || true

systemctl daemon-reload
systemctl enable vpsfort.service
systemctl restart vpsfort.service
sleep 2
systemctl --no-pager --lines=15 status vpsfort.service || true
canary_warning
echo
echo "Dashboard:   sudo vpsfort -c /etc/vpsfort/vpsfort.toml tui"
echo "Decisions:   journalctl -u vpsfort -f    or    tail -f /var/log/vpsfort/actions.jsonl"
