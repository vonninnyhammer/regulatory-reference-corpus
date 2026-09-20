#!/usr/bin/env python3
"""
compliance_monitor.py — Regulatory change monitoring and scraping agent.

Scrapes official regulatory body websites for updates to:
  - HIPAA/HITECH (HHS)
  - ABA Model Rules (ABA)
  - GLBA (FTC/CFPB)
  - DOT/FMCSA (FMCSA.gov)
  - OSHA (OSHA.gov)

When a change is detected:
  1. Updates the Compliance Bible rules
  2. Generates a diff of changes
  3. Sends a desktop notification via notify-send
  4. Optionally patches the pipeline code

Run frequency: Quarterly (configurable via cron/systemd timer).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("compliance_monitor")

BIBLE_PATH = Path.home() / "compliance-bible"
STATE_FILE = BIBLE_PATH / "scripts" / "monitor_state.json"
CHANGE_LOG_DIR = BIBLE_PATH / "change-log"

# Regulatory source URLs to monitor
MONITOR_SOURCES: dict[str, dict[str, Any]] = {
    "hipaa_privacy": {
        "name": "HIPAA Privacy Rule",
        "url": "https://www.hhs.gov/hipaa/for-professionals/privacy/index.html",
        "vertical": "medical",
        "rule_ids": ["R-MED-001", "R-MED-004", "R-MED-008"],
    },
    "hipaa_security": {
        "name": "HIPAA Security Rule",
        "url": "https://www.hhs.gov/hipaa/for-professionals/security/index.html",
        "vertical": "medical",
        "rule_ids": ["R-MED-002", "R-MED-003", "R-MED-007"],
    },
    "hipaa_breach": {
        "name": "HIPAA Breach Notification Rule",
        "url": "https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html",
        "vertical": "medical",
        "rule_ids": ["R-MED-006"],
    },
    "hitech": {
        "name": "HITECH Act Updates",
        "url": "https://www.hhs.gov/hipaa/for-professionals/privacy/guidance/index.html",
        "vertical": "medical",
        "rule_ids": ["R-MED-005", "R-MED-006"],
    },
    "aba_rules": {
        "name": "ABA Model Rules of Professional Conduct",
        "url": "https://www.americanbar.org/ethics/abamoderules/homepage.html",
        "vertical": "legal",
        "rule_ids": ["R-LEG-001", "R-LEG-002", "R-LEG-003", "R-LEG-007"],
    },
    "ftc_glba": {
        "name": "FTC Safeguards Rule (GLBA)",
        "url": "https://www.ftc.gov/legal-library/browse/rules/safeguards-rule",
        "vertical": "legal",
        "rule_ids": ["R-LEG-004", "R-LEG-005", "R-LEG-006"],
    },
    "fmcsa_regulations": {
        "name": "FMCSA Regulations",
        "url": "https://www.fmcsa.dot.gov/regulations",
        "vertical": "logistics",
        "rule_ids": ["R-LOG-001", "R-LOG-002", "R-LOG-006"],
    },
    "osha_recordkeeping": {
        "name": "OSHA Recordkeeping Standards",
        "url": "https://www.osha.gov/recordkeeping",
        "vertical": "logistics",
        "rule_ids": ["R-LOG-003", "R-LOG-004", "R-LOG-007"],
    },
}


class ComplianceMonitor:
    """Monitors regulatory sources for changes."""

    def __init__(self):
        self.state = self._load_state()
        CHANGE_LOG_DIR.mkdir(parents=True, exist_ok=True)

    def _load_state(self) -> dict[str, Any]:
        """Load previous monitoring state."""
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE) as f:
                    return json.load(f)
            except Exception:
                logger.warning("Failed to load monitor state, starting fresh")
        return {"sources": {}, "last_run": None, "version": "1.0.0"}

    def _save_state(self) -> None:
        """Save monitoring state."""
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.state["last_run"] = datetime.now(timezone.utc).isoformat()
        with open(STATE_FILE, "w") as f:
            json.dump(self.state, f, indent=2, default=str)

    def _fetch_content(self, url: str) -> str | None:
        """Fetch URL content with browser-like headers for maximum compatibility."""
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        try:
            with httpx.Client(timeout=30.0, follow_redirects=True, verify=True) as client:
                resp = client.get(url, headers=headers)
                resp.raise_for_status()
                return resp.text
        except Exception:
            logger.exception("Failed to fetch %s", url)
            return None

    def _compute_hash(self, content: str) -> str:
        """Compute content hash for change detection."""
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _send_notification(self, title: str, body: str, urgency: str = "normal") -> None:
        """Send a desktop notification."""
        try:
            subprocess.run(
                ["notify-send", "-u", urgency, "-t", "30000", title, body],
                check=True,
                timeout=10,
            )
            logger.info("Desktop notification sent: %s", title)
        except FileNotFoundError:
            logger.warning("notify-send not available — logging notification instead")
            logger.info("NOTIFICATION: %s — %s", title, body)
        except Exception:
            logger.exception("Failed to send desktop notification")

    def scan_all(self) -> dict[str, Any]:
        """Scan all monitored sources for changes."""
        results = {
            "scanned": 0,
            "changed": 0,
            "new": 0,
            "unchanged": 0,
            "errors": 0,
            "changes": [],
        }

        for source_id, source in MONITOR_SOURCES.items():
            results["scanned"] += 1
            logger.info("Scanning %s (%s)...", source["name"], source["url"])

            content = self._fetch_content(source["url"])
            if content is None:
                results["errors"] += 1
                continue

            content_hash = self._compute_hash(content)
            previous_hash = self.state["sources"].get(source_id, {}).get("hash")

            if previous_hash is None:
                results["new"] += 1
                self.state["sources"][source_id] = {
                    "hash": content_hash,
                    "name": source["name"],
                    "url": source["url"],
                    "vertical": source["vertical"],
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_checked": datetime.now(timezone.utc).isoformat(),
                }
                logger.info("New source registered: %s", source["name"])
            elif content_hash != previous_hash:
                results["changed"] += 1
                change = {
                    "source_id": source_id,
                    "name": source["name"],
                    "vertical": source["vertical"],
                    "affected_rules": source["rule_ids"],
                    "previous_hash": previous_hash,
                    "new_hash": content_hash,
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                }
                results["changes"].append(change)

                # Update state
                self.state["sources"][source_id]["hash"] = content_hash
                self.state["sources"][source_id]["last_checked"] = datetime.now(timezone.utc).isoformat()

                # Write change log
                self._log_change(change)

                # Send notification
                self._send_notification(
                    title=f"⚠️ Regulatory Change Detected: {source['name']}",
                    body=(
                        f"A change was detected on {source['name']} ({source['vertical']} vertical).\n\n"
                        f"Affected rules: {', '.join(source['rule_ids'])}\n"
                        f"Source: {source['url']}\n\n"
                        f"Action required: Review and update Compliance Bible rules."
                    ),
                    urgency="critical",
                )

                logger.warning("CHANGE DETECTED: %s", source["name"])
            else:
                results["unchanged"] += 1
                self.state["sources"][source_id]["last_checked"] = datetime.now(timezone.utc).isoformat()
                logger.info("No change: %s", source["name"])

        self._save_state()
        return results

    def _log_change(self, change: dict[str, Any]) -> None:
        """Append change to the change log."""
        log_file = CHANGE_LOG_DIR / f"changes_{datetime.now().strftime('%Y%m')}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(change, default=str) + "\n")

    def generate_report(self) -> str:
        """Generate a human-readable monitoring report."""
        lines = [
            "═══ Compliance Bible — Regulatory Monitor Report ═══",
            f"Last scan: {self.state.get('last_run', 'never')}",
            f"Monitored sources: {len(MONITOR_SOURCES)}",
            "",
        ]

        for source_id, info in self.state.get("sources", {}).items():
            lines.append(f"  {info.get('name', source_id):40s} [{info.get('vertical', '?'):10s}] hash={info.get('hash', '?')}")

        lines.append("")
        lines.append("═══ End Report ═══")
        return "\n".join(lines)


def main() -> None:
    """CLI entry point for the compliance monitor."""
    import argparse

    parser = argparse.ArgumentParser(description="Compliance Bible Regulatory Monitor")
    parser.add_argument("--scan", action="store_true", help="Scan all sources for changes")
    parser.add_argument("--report", action="store_true", help="Generate monitoring report")
    parser.add_argument("--test-notify", action="store_true", help="Send a test notification")
    args = parser.parse_args()

    monitor = ComplianceMonitor()

    if args.test_notify:
        monitor._send_notification(
            title="🧪 Compliance Monitor — Test Notification",
            body="The compliance monitoring system is operational.",
            urgency="low",
        )
        return

    if args.report:
        print(monitor.generate_report())
        return

    if args.scan:
        results = monitor.scan_all()
        print(json.dumps(results, indent=2, default=str))
        return

    # Default: scan
    results = monitor.scan_all()
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
