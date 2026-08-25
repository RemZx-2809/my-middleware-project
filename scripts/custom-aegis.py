#!/usr/bin/env python3
"""
Aegis SOC - Wazuh Manager Custom Integration Script
File: /var/ossec/integrations/custom-aegis
Permissions: chmod 750 (owner root:wazuh)

Forwards ALL alerts with level >= 7 from ANY rule to Aegis SOC Middleware.
Level >= 12 will auto-open a Redmine Issue via the middleware.

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

DEFAULT_HOOK_URL = "http://127.0.0.1:3000/api/wazuh-webhook"

# Send all alerts level >= 7 from ANY rule.
# Level >= 12 -> Middleware auto-opens Redmine Issue.
MIN_LEVEL = 7

USE_CASE_RULES = [
    ("critical_file_changes", [
        "syscheck", "fim", "file_integrity", "ossec_integrity",
        "file_monitor", "inotify", "auditd_watch",
    ]),
    ("auth_access_anomalies", [
        "authentication", "sshd", "pam", "login", "web",
        "win_authentication", "invalid_login", "brute_force", "invalid_access",
        "authentication_failed", "authentication_success", "logon", "rdp",
        "ftp_auth", "kerberos", "ntlm", "telnet", "vpn_auth", "fortigate",
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
    Classify into 5 Aegis SOC use cases.
    Every alert >= MIN_LEVEL always gets a use_case (never dropped).
    Fallback: critical_alerts for any unclassified alert.
    """
    rule   = alert.get("rule", {})
    groups = rule.get("groups", [])
    desc   = str(rule.get("description", "")).lower()

    g = " ".join(str(x) for x in groups).lower() if isinstance(groups, list) else str(groups).lower()

    for use_case, keywords in USE_CASE_RULES:
        if any(k in g for k in keywords):
            return use_case

    if any(k in desc for k in ["file added", "file modified", "file deleted", "integrity checksum"]):
        return "critical_file_changes"
    if any(k in desc for k in ["failed login", "authentication failed", "invalid user", "brute"]):
        return "auth_access_anomalies"
    if any(k in desc for k in ["agent disconnected", "agent stopped", "keepalive"]):
        return "blind_spots_agent_health"
    if any(k in desc for k in ["attack", "exploit", "malware", "threat", "sqli", "xss", "ransomware"]):
        return "threat_intel_matches"

    return "critical_alerts"


def validate_required_fields(alert):
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

    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception as e:
        logger.error("Could not read alert file %s: %s", alert_file, e)
        sys.exit(1)

    rule_id    = alert.get("rule", {}).get("id", "?")
    rule_desc  = alert.get("rule", {}).get("description", "")[:80]
    level      = int(alert.get("rule", {}).get("level", 0))
    agent_name = alert.get("agent", {}).get("name", "unknown")

    if level < MIN_LEVEL:
        logger.info("DROPPED level=%d rule=%s agent=%s - below MIN_LEVEL=%d", level, rule_id, agent_name, MIN_LEVEL)
        sys.exit(0)

    use_case = classify_use_case(alert)

    missing = validate_required_fields(alert)
    if missing:
        logger.warning("INCOMPLETE PAYLOAD rule=%s agent=%s use_case=%s | missing=%s", rule_id, agent_name, use_case, missing)

    alert["aegis_use_case"] = use_case
    if "receivedAt" not in alert:
        alert["receivedAt"] = datetime.now(timezone.utc).isoformat()

    redmine_note = " [L12+ -> Redmine Issue auto-open]" if level >= 12 else ""
    logger.info("ACCEPTED rule=%s level=%d agent=%s use_case=%s%s | desc=%s", rule_id, level, agent_name, use_case, redmine_note, rule_desc)

    success = send_webhook(hook_url, alert, bearer_secret=api_key)
    if not success:
        logger.error("FAILED to deliver - rule=%s agent=%s", rule_id, agent_name)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
