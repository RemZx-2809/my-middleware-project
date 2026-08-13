#!/usr/bin/env python3
"""
backfill_wazuh.py -- Wazuh Historical Alert Backfill Script
Run this script ON the Wazuh Server to push historical alerts
to the AEGIS SOC Middleware via /api/bulk-ingest.

Usage:
    sudo python3 backfill_wazuh.py ^
        --url http://<middleware-ip>:3000 ^
        --token <your-webhook-secret> ^
        --days 30
"""

import argparse
import gzip
import glob
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

parser = argparse.ArgumentParser(description='Push Wazuh historical alerts to AEGIS Middleware')
parser.add_argument('--url',   required=True,  help='Middleware base URL')
parser.add_argument('--token', default='',     help='Bearer token')
parser.add_argument('--days',  type=int, default=30, help='Days to look back')
parser.add_argument('--batch', type=int, default=50,  help='Alerts per POST batch')
parser.add_argument('--dry',   action='store_true',  help='Dry run only')
args = parser.parse_args()

MIDDLEWARE_URL = args.url.rstrip('/')
INGEST_ENDPOINT = f'{MIDDLEWARE_URL}/api/bulk-ingest'
BEARER_TOKEN = args.token
DAYS_BACK = args.days
BATCH_SIZE = args.batch
DRY_RUN = args.dry

cutoff = datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)

alert_files = ['/var/ossec/logs/alerts/alerts.json']
alert_files += sorted(glob.glob('/var/ossec/logs/alerts/*/*/*.json.gz'))
alert_files += sorted(glob.glob('/var/ossec/logs/alerts/*/*/*.json'))

seen = set()
unique_files = [fp for fp in alert_files if os.path.exists(fp) and fp not in seen and not seen.add(fp)]

print(f'[BACKFILL] Looking back {DAYS_BACK} days | Files: {len(unique_files)} | Endpoint: {INGEST_ENDPOINT}')
if DRY_RUN:
    print('[BACKFILL] DRY RUN -- no data will be sent')

def iter_alerts(files, cutoff):
    for fp in files:
        try:
            opener = gzip.open if fp.endswith('.gz') else open
            with opener(fp, 'rt', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try:
                        alert = json.loads(line)
                        ts = alert.get('timestamp') or alert.get('@timestamp') or ''
                        if ts:
                            try:
                                t = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                                if t < cutoff: continue
                            except Exception: pass
                        yield alert
                    except json.JSONDecodeError: continue
        except Exception as e:
            print(f'[BACKFILL] Warning: {fp}: {e}', file=sys.stderr)

def post_batch(batch):
    if DRY_RUN: return True
    payload = json.dumps({'alerts': batch, 'source': 'backfill'}).encode('utf-8')
    headers = {'Content-Type': 'application/json', 'Content-Length': str(len(payload))}
    if BEARER_TOKEN: headers['Authorization'] = f'Bearer {BEARER_TOKEN}'
    req = urllib.request.Request(INGEST_ENDPOINT, data=payload, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            return result.get('ok', False)
    except Exception as e:
        print(f'[BACKFILL] Error: {e}', file=sys.stderr)
        return False

total_read = total_sent = total_failed = 0
batch = []

for alert in iter_alerts(unique_files, cutoff):
    total_read += 1
    batch.append(alert)
    if len(batch) >= BATCH_SIZE:
        if post_batch(batch): total_sent += len(batch)
        else: total_failed += len(batch)
        batch = []
        if total_read % 500 == 0:
            print(f'[BACKFILL] read={total_read} sent={total_sent} failed={total_failed}')

if batch:
    if post_batch(batch): total_sent += len(batch)
    else: total_failed += len(batch)

print(f'\n[BACKFILL] Done! read={total_read} sent={total_sent} failed={total_failed}')
