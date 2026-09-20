#!/bin/bash
# compliance_scan.sh — Wrapper script for cron/systemd timer execution.
# Runs the compliance monitor scan and logs output.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/../change-log"
LOG_FILE="${LOG_DIR}/scan_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "$LOG_DIR"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starting compliance scan..." >> "$LOG_FILE"

python3 "${SCRIPT_DIR}/compliance_monitor.py" --scan >> "$LOG_FILE" 2>&1

EXIT_CODE=$?

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Scan completed with exit code ${EXIT_CODE}" >> "$LOG_FILE"

# Send summary notification
if [ -f "$LOG_FILE" ]; then
    CHANGES=$(grep -c "CHANGE DETECTED" "$LOG_FILE" 2>/dev/null || echo "0")
    if [ "$CHANGES" -gt 0 ]; then
        notify-send -u normal -t 15000 \
            "📋 Compliance Scan Complete" \
            "${CHANGES} regulatory change(s) detected. Check change-log for details."
    fi
fi

exit $EXIT_CODE
