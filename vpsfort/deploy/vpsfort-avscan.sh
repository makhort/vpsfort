#!/bin/bash
# Scheduled ClamAV scan whose results vpsfort reports ([antivirus] in vpsfort.toml):
# infected files, scans that die (e.g. killed for memory) and scans that stop happening.
# Run daily by vpsfort-avscan.timer; settings in /etc/default/vpsfort-avscan.
#
# Each run is appended to the log between two marker lines carrying UTC times and the
# scanner's exit code (0 clean, 1 infected files found, 2 some files unreadable):
#   vpsfort-avscan start 2026-10-12T02:30:01Z
#   ...clamscan output (only infected files, then the summary)...
#   vpsfort-avscan end 2026-10-12T02:31:17Z exit=0
set -u

PATHS=${AVSCAN_PATHS:-"/etc /opt /root /home /srv /usr/local /var/www /var/spool/cron /tmp /var/tmp /dev/shm"}
# Directory regexes clamscan skips (clamdscan uses ExcludePath in clamd.conf instead).
# YARA rule files are malware fragments by design, which ClamAV flags: vpsfort's rules
# directory is skipped unless AVSCAN_EXCLUDE says otherwise (keep it in your own list).
EXCLUDE=${AVSCAN_EXCLUDE-"^/etc/vpsfort/yara"}
LOG=${AVSCAN_LOG:-/var/log/vpsfort/avscan.log}
# auto: clamdscan when clamd runs (clamav-daemon, or Fedora's clamd@scan; no signature
# loading), else clamscan.
SCANNER=${AVSCAN_SCANNER:-auto}
# clamd's configuration for clamdscan, when not clamdscan's own default. Empty: that default,
# or Fedora's /etc/clamd.d/scan.conf when it is there and the default isn't (Fedora's clamd
# reads it; its clamdscan isn't told).
CLAMD_CONFIG=${AVSCAN_CLAMD_CONFIG:-}

mkdir -p "$(dirname "$LOG")"
targets=()
for p in $PATHS; do
    [ -e "$p" ] && targets+=("$p")
done
if [ "$SCANNER" = auto ]; then
    if command -v clamdscan > /dev/null && { systemctl is-active --quiet clamav-daemon || systemctl is-active --quiet clamd@scan; }; then
        SCANNER=clamdscan
    else
        SCANNER=clamscan
    fi
fi
args=(--infected --stdout)
if [ "$SCANNER" = clamdscan ]; then
    args+=(--multiscan --fdpass)
    if [ -z "$CLAMD_CONFIG" ] && [ ! -e /etc/clamd.conf ] && [ ! -e /etc/clamav/clamd.conf ] && [ -e /etc/clamd.d/scan.conf ]; then
        CLAMD_CONFIG=/etc/clamd.d/scan.conf
    fi
    [ -n "$CLAMD_CONFIG" ] && args+=("--config-file=$CLAMD_CONFIG")
else
    args+=(--recursive)
    # the unit's writable temporary directory (the rest of the system is read-only there)
    [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] && args+=("--tempdir=$TMPDIR")
    # Regexes, not file patterns: split on spaces, but never expand `*` against files.
    set -f
    for x in $EXCLUDE; do
        args+=("--exclude-dir=$x")
    done
    set +f
fi

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
echo "vpsfort-avscan start $(now)" >> "$LOG"
if command -v "$SCANNER" > /dev/null; then
    # TZ=UTC: the summary's Start/End Date lines are then in UTC too. Indented, so no line of
    # the output (a file name with line breaks in it) can pass for one of the markers.
    TZ=UTC "$SCANNER" "${args[@]}" "${targets[@]}" 2>&1 | sed -u 's/^/  /' >> "$LOG"
    rc=${PIPESTATUS[0]}
else
    echo "vpsfort-avscan: $SCANNER not found (apt install clamav clamav-freshclam, or dnf install clamav clamav-freshclam, older Fedora and RHEL clamav-update)" >> "$LOG"
    rc=127
fi
echo "vpsfort-avscan end $(now) exit=$rc" >> "$LOG"
exit "$rc"
