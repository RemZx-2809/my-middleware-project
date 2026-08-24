#!/usr/bin/env python3
"""
Aegis SOC — Wazuh Manager Custom Integration Script
=====================================================
File location on Wazuh Manager: /var/ossec/integrations/custom-aegis
Permissions: chmod 750 /var/ossec/integrations/custom-aegis (owner root:wazuh)

This script is triggered by Wazuh Manager whenever an alert matches rule criteria.
It filters raw alerts, classifies them into one of the 5 Aegis SOC use cases,
and sends ONLY qualified alerts to the Aegis Middleware webhook.

Usage (invoked automatically by Wazuh):
  /var/ossec/integrations/custom-aegis <alert_file> <api_key> <hook_url>
"""

import sys
import json
import urllib.request
import urllib.error
import logging
import os
from datetime import datetime, timezone

# ── Logging ────────────────────────────────────────────────────────────────
LOG_FILE = "/var/ossec/logs/custom-aegis.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [custom-aegis] %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8") if os.path.isdir("/var/ossec/logs") else logging.StreamHandler(sys.stderr),
        logging.StreamHandler(sys.stderr),
    ],
)
logger = logging.getLogger("custom-aegis")

# ── Defaults ───────────────────────────────────────────────────────────────
DEFAULT_HOOK_URL = "http://127.0.0.1:3000/api/wazuh-webhook"
MIN_LEVEL        = 3   # Drop alerts with rule.level < 3 immediately

VALID_USE_CASES = {
    "critical_alerts",
    "blind_spots_agent_health",
    "critical_file_changes",
    "auth_access_anomalies",
    "threat_intel_matches",
}

# ── Use-case classification keywords (ordered by priority) ──────────────────
USE_CASE_RULES = [
    # (use_case, group_keywords)
    ("critical_file_changes", [
        "syscheck", "fim", "file_integrity", "ossec_integrity",
        "file_monitor", "inotify", "auditd_watch",
    ]),
    ("auth_access_anomalies", [
        "authentication", "sshd", "pam", "login", "web",
        "win_authentication", "invalid_login", "brute_force", "invalid_access",
        "authentication_failed", "authentication_success", "logon", "rdp",
        "ftp_auth", "kerberos", "ntlm", "telnet", "vpn_auth",
    ]),
    ("blind_spots_agent_health", [
        "agent_disconnected", "ossec", "keepalive", "netstat",
        "agent", "agentless", "ports_status", "agent_reconnected",
        "syslog_agent", "wazuh_agent", "ossec_agent",
    ]),
    ("threat_intel_matches", [
        "threat", "malware", "virus", "yara", "rootkit",
        "trojan", "ids", "exploit", "injection", "worm",
        "ransomware", "spyware", "adware", "botnet", "c2",
        "virustotal", "clamav", "suricata", "snort",
        "osquery_threat", "anomaly_detection",
    ]),
]


def classify_use_case(alert):
    """
    Classify Wazuh alert into one of the 5 Aegis SOC use cases based on rule groups and level.

    Priority order:
      1. critical_file_changes   (syscheck / FIM)
      2. auth_access_anomalies   (authentication / SSH / PAM / brute-force)
      3. blind_spots_agent_health (agent / keepalive / ossec)
      4. threat_intel_matches    (malware / IDS / CVE exploits)
      5. critical_alerts         (any rule with level >= 7 that did not match above)

    Returns use case name string, or None if alert does not meet threshold.
    """
    rule   = alert.get("rule", {})
    groups = rule.get("groups", [])
    level  = int(rule.get("level", 0))

    if isinstance(groups, list):
        g = " ".join(str(x) for x in groups).lower()
    else:
        g = str(groups).lower()

    for use_case, keywords in USE_CASE_RULES:
        if any(k in g for k in keywords):
            return use_case

    # Fallback: high-severity alerts that did not match a specific category
    if level >= 7:
        return "critical_alerts"

    return None


def validate_required_fields(alert):
    """
    Lightweight payload schema validation before sending to middleware.
    Returns a list of missing or invalid fields (empty list = OK).
    """
    issues = []
    if not (alert.get("timestamp") or alert.get("@timestamp") or alert.get("receivedAt")):
        issues.append("timestamp")
    if not alert.get("rule", {}).get("id"):
        issues.append("rule.id")
    if alert.get("rule", {}).get("level") is None:
        issues.append("rule.level")
    if not alert.get("rule", {}).get("description"):
        issues.append("rule.description")
    if not (alert.get("agent", {}).get("name") or alert.get("agent", {}).get("id")):
        issues.append("agent.name")
    return issues


def send_webhook(hook_url, alert, bearer_secret=""):
    """POST classified alert to Aegis Middleware webhook."""
    payload = json.dumps(alert).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if bearer_secret:
        headers["Authorization"] = f"Bearer {bearer_secret}"

    req = urllib.request.Request(hook_url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            logger.info("Webhook accepted | status=%d | response=%s", resp.status, body[:120])
            return resp.status == 200
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        logger.error("Webhook HTTP error: %d %s | body=%s", e.code, e.reason, body[:200])
        return False
    except Exception as e:
        logger.error("Webhook send failed: %s", e)
        return False


def main():
    if len(sys.argv) < 2:
        logger.error("Usage: custom-aegis <alert_file> [api_key] [hook_url]")
        sys.exit(1)

    alert_file = sys.argv[1]
    api_key    = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] != "-" else ""
    hook_url   = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != "-" else DEFAULT_HOOK_URL

    # ── Read alert JSON generated by Wazuh ────────────────────────────────
    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception as e:
        logger.error("Could not read alert file %s: %s", alert_file, e)
        sys.exit(1)

    rule_id    = alert.get("rule", {}).get("id", "?")
    rule_desc  = alert.get("rule", {}).get("description", "")[:60]
    level      = int(alert.get("rule", {}).get("level", 0))
    agent_name = alert.get("agent", {}).get("name", "unknown")

    # ── Level filter (drop noise at Wazuh layer) ──────────────────────────
    if level < MIN_LEVEL:
        logger.info("DROPPED level=%d rule=%s — below MIN_LEVEL=%d", level, rule_id, MIN_LEVEL)
        sys.exit(0)

    # ── Use-case classification ────────────────────────────────────────────
    use_case = classify_use_case(alert)
    if not use_case:
        logger.info("DROPPED rule=%s level=%d — unclassified | desc=%s", rule_id, level, rule_desc)
        sys.exit(0)

    # ── Validate required fields ───────────────────────────────────────────
    missing = validate_required_fields(alert)
    if missing:
        logger.warning(
            "INCOMPLETE PAYLOAD rule=%s agent=%s use_case=%s | missing_fields=%s",
            rule_id, agent_name, use_case, missing,
        )
        # Still forward — middleware will track completeness score; do not drop

    # ── Enrich and forward ─────────────────────────────────────────────────
    alert["aegis_use_case"] = use_case
    if "receivedAt" not in alert:
        alert["receivedAt"] = datetime.now(timezone.utc).isoformat()

    logger.info(
        "ACCEPTED rule=%s level=%d agent=%s use_case=%s | desc=%s",
        rule_id, level, agent_name, use_case, rule_desc,
    )

    success = send_webhook(hook_url, alert, bearer_secret=api_key)
    if not success:
        logger.error("FAILED to deliver to middleware — rule=%s", rule_id)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
