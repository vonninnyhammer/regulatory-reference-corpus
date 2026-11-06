#!/bin/bash
# compliance_scan.sh — Wrapper script for cron/systemd timer execution.
# Runs the compliance monitor scan, logs output, and sends an alert when the
# scan fails or when regulatory changes are detected.
#
# Alerts go to ntfy when NTFY_TOPIC is set (NTFY_URL defaults to https://ntfy.sh),
# otherwise to the desktop with notify-send if it is available.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/../change-log"
LOG_FILE="${LOG_DIR}/scan_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "$LOG_DIR"

# notify <title> <message> [priority] [tags]
notify() {
    if [ -n "${NTFY_TOPIC:-}" ]; then
        local url="${NTFY_URL:-https://ntfy.sh}"
        curl -fsS --max-time 15 -H "Title: $1" -H "Priority: ${3:-default}" \
            ${4:+-H "Tags: $4"} --data-binary "$2" "${url%/}/${NTFY_TOPIC}" >/dev/null || true
    elif command -v notify-send >/dev/null 2>&1; then
        notify-send -u normal -t 15000 "$1" "$2" || true
    fi
}

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starting compliance scan..." >> "$LOG_FILE"

# Capture the exit code instead of letting `set -e` end the script, so a failed
# scan is still logged and reported.
rc=0
python3 "${SCRIPT_DIR}/compliance_monitor.py" --scan >> "$LOG_FILE" 2>&1 || rc=$?

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Scan completed with exit code ${rc}" >> "$LOG_FILE"

if [ "$rc" -ne 0 ]; then
    notify "compliance-scan FAILED (rc=$rc)" "$(tail -n 15 "$LOG_FILE" | tr -d '\r')" high rotating_light
    exit "$rc"
fi

CHANGES=$(grep -c "CHANGE DETECTED" "$LOG_FILE" 2>/dev/null || true)
if [ "${CHANGES:-0}" -gt 0 ]; then
    notify "compliance: ${CHANGES} regulatory change(s)" \
        "Scan $(basename "$LOG_FILE") detected changes. See change-log/." default clipboard
fi

exit 0
