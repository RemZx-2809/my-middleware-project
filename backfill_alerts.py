#!/usr/bin/env python3
"""
Aegis SOC — Wazuh Historical Alert Backfill Script
====================================================
Run this script on the Wazuh Manager server to push
historical alert data into the Aegis SOC Middleware.

Usage:
  python3 backfill_alerts.py

By default it reads alerts from the last 30 days.
Edit DAYS_BACK or MIDDLEWARE_URL below if needed.
"""

import json
import urllib.request
import urllib.error
import os
import sys
from datetime import datetime, timedelta, timezone

# ── Configuration ──────────────────────────────────────────────────────────
MIDDLEWARE_URL = "http://127.0.0.1:3000/api/bulk-ingest"  # uses SSH Reverse Tunnel
ALERTS_FILE    = "/var/ossec/logs/alerts/alerts.json"
DAYS_BACK      = 30        # fallback window in days if INGEST_SINCE is not set
INGEST_SINCE   = "2026-08-25T06:00:00+07:00"  # Only accept alerts occurring on or after this activation timestamp
BATCH_SIZE     = 50        # send alerts in batches
MIN_LEVEL      = 3         # include alerts from level 3+
BEARER_SECRET  = ""        # leave blank unless webhookSecret is set in Aegis config
# ───────────────────────────────────────────────────────────────────────────


def classify_use_case(alert):
    """Map Wazuh rule groups/level to one of the 5 Aegis SOC use cases."""
    groups = alert.get("rule", {}).get("groups", [])
    level  = int(alert.get("rule", {}).get("level", 0))
    g      = " ".join(groups).lower()

    # 1. File / System Changes (FIM / Syscheck)
    if any(k in g for k in ["syscheck", "fim", "file_integrity", "ossec_integrity"]):
        return "critical_file_changes"

    # 2. Access Anomalies (Login / Auth / SSH / Web access)
    if any(k in g for k in [
        "authentication_failed", "authentication_success",
        "sshd", "pam", "login", "web", "win_authentication",
        "invalid_login", "brute_force", "invalid_access",
    ]):
        return "auth_access_anomalies"

    # 3. Blind Spots & Agent Health
    if any(k in g for k in [
        "agent_disconnected", "ossec", "keepalive", "netstat",
        "agent", "agentless", "ports_status",
    ]):
        return "blind_spots_agent_health"

    # 4. Threat Intel Matches (Malware / Threats / IDS)
    if any(k in g for k in [
        "threat", "malware", "virus", "yara", "rootkit",
        "trojan", "ids", "exploit", "injection", "worm",
    ]):
        return "threat_intel_matches"

    # 5. Critical Alerts — everything else
    return "critical_alerts"


def parse_alert_time(alert):
    ts = alert.get("timestamp", "")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def send_batch(batch):
    payload = json.dumps({"alerts": batch, "source": "backfill"}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if BEARER_SECRET:
        headers["Authorization"] = f"Bearer {BEARER_SECRET}"

    req = urllib.request.Request(MIDDLEWARE_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            return result.get("accepted", 0), result.get("skipped", 0)
    except urllib.error.HTTPError as e:
        print(f"  [!] HTTP {e.code}: {e.read().decode()[:200]}")
        return 0, len(batch)
    except Exception as e:
        print(f"  [!] Send error: {e}")
        return 0, len(batch)


def main():
    if not os.path.exists(ALERTS_FILE):
        print(f"[ERROR] Alerts file not found: {ALERTS_FILE}")
        sys.exit(1)

    if INGEST_SINCE:
        try:
            cutoff = datetime.fromisoformat(INGEST_SINCE.replace("Z", "+00:00"))
            print(f"[Aegis Backfill] Ingesting alerts from activation timestamp: {INGEST_SINCE} onwards...")
        except Exception:
            cutoff = datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)
            print(f"[Aegis Backfill] Reading alerts from last {DAYS_BACK} days...")
    else:
        cutoff = datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)
        print(f"[Aegis Backfill] Reading alerts from last {DAYS_BACK} days...")

    print(f"[Aegis Backfill] Source : {ALERTS_FILE}")
    print(f"[Aegis Backfill] Target : {MIDDLEWARE_URL}")
    print()

    batch = []
    total_read = total_sent = total_skip = total_old = 0

    use_case_counts = {
        "critical_alerts":          0,
        "blind_spots_agent_health": 0,
        "critical_file_changes":    0,
        "auth_access_anomalies":    0,
        "threat_intel_matches":     0,
    }

    with open(ALERTS_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            total_read += 1

            alert_time = parse_alert_time(alert)
            if alert_time and alert_time < cutoff:
                total_old += 1
                continue

            level = int(alert.get("rule", {}).get("level", 0))
            if level < MIN_LEVEL:
                total_skip += 1
                continue

            use_case = classify_use_case(alert)
            alert["aegis_use_case"] = use_case
            use_case_counts[use_case] += 1
            batch.append(alert)

            if len(batch) >= BATCH_SIZE:
                accepted, skipped = send_batch(batch)
                total_sent += accepted
                total_skip += skipped
                print(f"  Sent {total_sent} alerts so far...", end="\r")
                batch = []

    if batch:
        accepted, skipped = send_batch(batch)
        total_sent += accepted
        total_skip += skipped

    print()
    print()
    print("=" * 50)
    print(" Aegis SOC Backfill Complete!")
    print("=" * 50)
    print(f"  Total read    : {total_read}")
    print(f"  Too old >30d  : {total_old}")
    print(f"  Sent          : {total_sent}")
    print(f"  Skipped       : {total_skip}")
    print()
    print("  Breakdown by category:")
    print(f"   Critical Alerts      : {use_case_counts['critical_alerts']}")
    print(f"   Blind Spots          : {use_case_counts['blind_spots_agent_health']}")
    print(f"   File/System Changes  : {use_case_counts['critical_file_changes']}")
    print(f"   Access Anomalies     : {use_case_counts['auth_access_anomalies']}")
    print(f"   Threat Intel Matches : {use_case_counts['threat_intel_matches']}")
    print()
    print("  Open http://localhost:3000 to see results!")


if __name__ == "__main__":
    main()
