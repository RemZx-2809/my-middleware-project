#!/usr/bin/env python3
import sys, json, urllib.request, urllib.error, logging, os
from datetime import datetime, timezone

LOG_FILE = '/var/ossec/logs/custom-aegis.log'
handlers = [logging.StreamHandler(sys.stderr)]
if os.path.isdir('/var/ossec/logs'):
    handlers.append(logging.FileHandler(LOG_FILE, encoding='utf-8'))
logging.basicConfig(level=logging.INFO, format='%(asctime)s [custom-aegis] %(levelname)s %(message)s', handlers=handlers)
logger = logging.getLogger('custom-aegis')

DEFAULT_HOOK_URL = 'http://127.0.0.1:3000/api/wazuh-webhook'
MIN_LEVEL = 7

USE_CASE_RULES = [
    ('critical_file_changes', ['syscheck','fim','file_integrity','ossec_integrity','file_monitor','inotify','auditd_watch']),
    ('auth_access_anomalies', ['authentication','sshd','pam','login','web','win_authentication','invalid_login','brute_force','invalid_access','authentication_failed','authentication_success','logon','rdp','ftp_auth','kerberos','ntlm','telnet','vpn_auth','fortigate']),
    ('blind_spots_agent_health', ['agent_disconnected','ossec','keepalive','netstat','agent','agentless','ports_status','agent_reconnected','syslog_agent','wazuh_agent','ossec_agent']),
    ('threat_intel_matches', ['threat','malware','virus','yara','rootkit','trojan','ids','exploit','injection','worm','ransomware','spyware','adware','botnet','c2','virustotal','clamav','suricata','snort','osquery_threat','anomaly_detection']),
]

def classify(alert):
    rule = alert.get('rule', {})
    groups = rule.get('groups', [])
    desc = str(rule.get('description', '')).lower()
    g = ' '.join(str(x) for x in groups).lower() if isinstance(groups, list) else str(groups).lower()
    for uc, kws in USE_CASE_RULES:
        if any(k in g for k in kws): return uc
    if any(k in desc for k in ['file added','file modified','file deleted','integrity checksum']): return 'critical_file_changes'
    if any(k in desc for k in ['failed login','authentication failed','invalid user','brute']): return 'auth_access_anomalies'
    if any(k in desc for k in ['agent disconnected','agent stopped','keepalive']): return 'blind_spots_agent_health'
    if any(k in desc for k in ['attack','exploit','malware','threat','sqli','xss','ransomware']): return 'threat_intel_matches'
    return 'critical_alerts'

def main():
    if len(sys.argv) < 2:
        logger.error('Usage: custom-aegis <alert_file> [api_key] [hook_url]')
        sys.exit(1)
    alert_file = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] != '-' else ''
    hook_url = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != '-' else DEFAULT_HOOK_URL
    try:
        with open(alert_file, 'r', encoding='utf-8') as f:
            alert = json.load(f)
    except Exception as e:
        logger.error('Cannot read %s: %s', alert_file, e)
        sys.exit(1)
    rule_id = alert.get('rule', {}).get('id', '?')
    rule_desc = alert.get('rule', {}).get('description', '')[:80]
    level = int(alert.get('rule', {}).get('level', 0))
    agent_name = alert.get('agent', {}).get('name', 'unknown')
    if level < MIN_LEVEL:
        logger.info('DROPPED level=%d rule=%s agent=%s', level, rule_id, agent_name)
        sys.exit(0)
    use_case = classify(alert)
    alert['aegis_use_case'] = use_case
    if 'receivedAt' not in alert:
        alert['receivedAt'] = datetime.now(timezone.utc).isoformat()
    redmine_note = ' [L12+ Redmine]' if level >= 12 else ''
    logger.info('ACCEPTED rule=%s level=%d agent=%s use_case=%s%s | %s', rule_id, level, agent_name, use_case, redmine_note, rule_desc)
    payload = json.dumps(alert).encode('utf-8')
    headers = {'Content-Type': 'application/json'}
    if api_key: headers['Authorization'] = 'Bearer ' + api_key
    req = urllib.request.Request(hook_url, data=payload, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info('Sent OK status=%d', resp.status)
    except urllib.error.HTTPError as e:
        logger.error('HTTP error %d: %s', e.code, e.read().decode('utf-8', errors='replace')[:200])
        sys.exit(1)
    except Exception as e:
        logger.error('Send failed: %s', e)
        sys.exit(1)

if __name__ == '__main__':
    main()