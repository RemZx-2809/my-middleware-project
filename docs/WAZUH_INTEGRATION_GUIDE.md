# Wazuh Integration Guide — Aegis SOC Middleware

เอกสารฉบับนี้อธิบายวิธีติดตั้ง `custom-aegis` integration script บน **Wazuh Manager** เพื่อกรองและจัดหมวดหมู่ alerts ก่อนส่งมาที่ **Aegis SOC Middleware** พร้อมตัวอย่างการตั้งค่า `ossec.conf`

---

## สถาปัตยกรรมโดยรวม

```
[ External Log Sources ]
       │ (Agents / Syslog / WinEvt / Auditd)
       ▼
[ Wazuh Manager ]
   ├── Rule Engine & Decoders   ← ประมวลผล log ทุกตัว
   └── custom-aegis script      ← กรอง + classify use case + POST webhook
                │
                │ เฉพาะ alert ที่ผ่านเกณฑ์ (level ≥ 3 + จัด use case ได้)
                ▼
[ Aegis SOC Middleware :3000 ]
   ├── POST /api/wazuh-webhook   ← รับ & เก็บ alert
   ├── GET  /api/data-health     ← ตรวจสอบความสมบูรณ์ข้อมูล
   └── GET  /api/events (SSE)   ← push real-time ไปยัง Dashboard
```

---

## ขั้นตอนที่ 1 — คัดลอกสคริปต์ไปยัง Wazuh Manager

```bash
# บน Wazuh Manager (Linux)
sudo cp custom-aegis.py /var/ossec/integrations/custom-aegis
sudo chmod 750 /var/ossec/integrations/custom-aegis
sudo chown root:wazuh /var/ossec/integrations/custom-aegis
```

> **หมายเหตุ**: ชื่อไฟล์ต้องเป็น `custom-aegis` (ไม่มีนามสกุล `.py`) เพราะ Wazuh เรียกใช้ชื่อนี้ตรงๆ

---

## ขั้นตอนที่ 2 — ตั้งค่า `ossec.conf`

เพิ่ม block `<integration>` ต่อไปนี้ในไฟล์ `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>

  <!-- ══════════════════════════════════════════════════
       Aegis SOC Middleware Integration
  ══════════════════════════════════════════════════ -->
  <integration>
    <name>custom-aegis</name>
    <hook_url>http://YOUR_MIDDLEWARE_IP:3000/api/wazuh-webhook</hook_url>
    <api_key>YOUR_WEBHOOK_SECRET</api_key>
    <alert_format>json</alert_format>
    <!-- ส่งเฉพาะ alert ที่มี level >= 3 เท่านั้น -->
    <alert_level>3</alert_level>
  </integration>

</ossec_config>
```

**แก้ไขค่าต่อไปนี้:**
| ค่า | คำอธิบาย |
|-----|----------|
| `YOUR_MIDDLEWARE_IP` | IP หรือ hostname ของเครื่องที่รัน Aegis Middleware |
| `YOUR_WEBHOOK_SECRET` | ค่า `webhookSecret` ที่ตั้งไว้ใน Aegis Settings (`aegis.config.json`) |

---

## ขั้นตอนที่ 3 — รีสตาร์ท Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
# หรือ
sudo /var/ossec/bin/ossec-control restart
```

ตรวจสอบว่า integration ทำงานได้:
```bash
sudo tail -f /var/ossec/logs/custom-aegis.log
```

---

## 5 Use Cases และ Logic การกรอง

| Use Case | `aegis_use_case` | Rule Groups ที่ตรวจจับ |
|----------|-----------------|----------------------|
| 🔴 Critical Alerts | `critical_alerts` | alert ทั่วไป level ≥ 7 (fallback) |
| 👁 Blind Spots / Agent Health | `blind_spots_agent_health` | `ossec`, `agent`, `keepalive`, `agentless` |
| 📁 Critical File Changes | `critical_file_changes` | `syscheck`, `fim`, `file_integrity` |
| 🔐 Auth & Access Anomalies | `auth_access_anomalies` | `authentication`, `sshd`, `pam`, `brute_force` |
| ☠️ Threat Intel Matches | `threat_intel_matches` | `malware`, `ids`, `yara`, `rootkit`, `ransomware` |

**Priority order**: FIM → Auth → Agent Health → Threat Intel → Critical (fallback)

---

## Fields ที่ Middleware ตรวจสอบ (Data Health)

### Base Fields (ทุก Use Case)
- `timestamp` หรือ `@timestamp`
- `agent.name` หรือ `agent.id`
- `rule.id`
- `rule.level`
- `rule.description`
- `aegis_use_case`

### Use-Case Specific Fields
| Use Case | Fields เพิ่มเติม |
|----------|----------------|
| `auth_access_anomalies` | `data.srcip`, `data.srcuser` |
| `critical_file_changes` | `syscheck.path`, `syscheck.event` |
| `threat_intel_matches` | `data.virustotal.*` หรือ `data.virus_name` |
| `blind_spots_agent_health` | `agent.ip`, `agent.status` |

---

## ตัวอย่างการตั้งค่า Fortigate / VPN Brute-Force Threshold (Rule 100005)

เพื่อจับการ Login พลาด 5 ครั้งภายใน 60 วินาที จาก IP เดียวกันบน Fortigate (ลด Alert Fatigue)

### 1. ใส่ Rule ใน `local_rules.xml` (ผ่าน Wazuh UI: Server Management > Rules):
```xml
<group name="fortigate, authentication_failed,">
  <!-- Rule 100005: 5 failed logins in 60s from same IP -->
  <rule id="100005" level="12" frequency="5" timeframe="60">
    <if_matched_sid>81606</if_matched_sid>
    <same_field name="data.srcip" />
    <description>Fortigate: Multiple failed login attempts (5 times in 1 min) from IP $(data.srcip).</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>pci_dss_10.2.4, pci_dss_11.4, gdpr_IV_35.7.d, auth_access_anomalies,</group>
  </rule>
</group>
```

### 2. กำหนด Integration ใน `ossec.conf` (ผ่าน Wazuh UI: Server Management > Settings):
```xml
<integration>
  <name>custom-aegis</name>
  <hook_url>http://YOUR_MIDDLEWARE_IP:3000/api/wazuh-webhook</hook_url>
  <rule_id>100005</rule_id>
  <alert_format>json</alert_format>
</integration>
```

---

## ทดสอบส่ง Fortigate Brute-Force Alert เข้าเว็บ AEGIS Middleware

```bash
# ทดสอบส่ง Fortigate Rule 100005 Alert จำลองไปยัง AEGIS Middleware
curl -X POST http://localhost:3000/api/wazuh-webhook \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'",
    "agent": {
      "id": "000",
      "name": "wazuh-server"
    },
    "rule": {
      "id": "100005",
      "level": 12,
      "description": "Fortigate: Multiple failed login attempts (5 times in 1 min) from IP 45.74.28.231 trying user admin.",
      "groups": ["fortigate", "authentication_failed", "invalid_login", "brute_force"]
    },
    "data": {
      "srcip": "45.74.28.231",
      "dstuser": "admin",
      "devname": "TCCT-UIH_FG300E",
      "reason": "passwd_invalid",
      "status": "failed"
    }
  }'
```

คาดว่า response จะได้:
```json
{ "ok": true, "useCase": "auth_access_anomalies" }
```
และ alert นี้จะปรากฏขึ้นบน **AEGIS SOC Dashboard** ในกล่อง **Authentication & Access Anomalies** และ **Critical Alerts** (L12) ทันที!

---

## ตรวจสอบ Data Health

หลังส่ง alert เข้ามาแล้ว สามารถตรวจสอบสถานะข้อมูลได้ที่:

```bash
curl http://localhost:3000/api/data-health | python3 -m json.tool
```

ผล `status` ต่อ Use Case:
- `ready` — Completeness Score ≥ 80% → **พร้อมทำ Dashboard**
- `incomplete` — Score < 80% → ยังขาด field สำคัญ
- `awaiting-data` — ยังไม่มี alert ส่งเข้ามาเลย

---

## Log Files

| ไฟล์ | คำอธิบาย |
|------|----------|
| `/var/ossec/logs/custom-aegis.log` | Log ของ integration script (ACCEPTED/DROPPED/FAILED) |
| `/var/ossec/logs/ossec.log` | Log หลักของ Wazuh Manager |
| `/var/ossec/logs/active-responses.log` | Log ของ active response actions |
