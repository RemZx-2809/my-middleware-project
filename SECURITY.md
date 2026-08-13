# AEGIS SOC — Production Security & Hardening Guide

This document outlines security configurations, environment variables, rate limits, and network firewall rules required before deploying Aegis SOC to production.

---

## 1. Wazuh API TLS Certificate Verification (`AEGIS_CA_PATH`)

By default, self-signed certificates trigger SSL verification errors when connecting to the Wazuh Manager API.

### Production Configuration
1. Export the Wazuh Manager CA certificate from your Wazuh Manager server:
   ```bash
   # On Wazuh Manager server
   cat /var/ossec/etc/root-ca.pem
   ```
2. Save the certificate file to the middleware server (e.g. `/etc/aegis/wazuh-ca.pem`).
3. Set the environment variable when starting the server:
   ```bash
   export AEGIS_CA_PATH="/etc/aegis/wazuh-ca.pem"
   node server.js
   ```
   Or set `"caPath": "/etc/aegis/wazuh-ca.pem"` in `aegis.config.json`.

> [!WARNING]
> Setting `sslVerify: false` in the Settings UI disables TLS certificate validation. This is strictly intended for laboratory or development testing. In production, always supply `AEGIS_CA_PATH`.

---

## 2. Rate Limiting

Aegis SOC includes built-in sliding-window rate limiting per remote IP address to prevent brute-force, resource exhaustion, and spam attacks.

### Built-in Limits

| Route / Resource | Window | Maximum Requests | Behavior on Exceeded |
|---|---|---|---|
| `POST /api/wazuh-webhook` | 60 seconds | 120 reqs | `HTTP 429 Too Many Requests` + `Retry-After` header |
| `POST /api/wazuh-test` | 60 seconds | 10 reqs | `HTTP 429 Too Many Requests` |
| `POST /api/wazuh-restart` | 300 seconds | 3 reqs | `HTTP 429 Too Many Requests` |
| `PUT /api/config` | 60 seconds | 10 reqs | `HTTP 429 Too Many Requests` |
| `PUT /api/rules/*` | 60 seconds | 30 reqs | `HTTP 429 Too Many Requests` |
| `DELETE /api/rules/*`, `DELETE /api/audit-logs` | 60 seconds | 10 reqs | `HTTP 429 Too Many Requests` |

---

## 3. Admin Route IP Allowlist (`AEGIS_ADMIN_ALLOW_IPS`)

Sensitive management endpoints (`/api/config`, `/api/wazuh-restart`, rule modifications, and audit deletion) are restricted to authorized administrator IPs.

### Environment Setup
Specify allowed IPv4/IPv6 addresses or IPv4 CIDR blocks using comma separation:

```bash
export AEGIS_ADMIN_ALLOW_IPS="127.0.0.1,10.0.1.50,192.168.1.0/24"
node server.js
```

Requests from unlisted IP addresses will receive `HTTP 403 Forbidden` and log a security warning to `stdout`.

---

## 4. Firewall Rule Configuration (Network Isolation)

To secure the deployment, **direct access to the Wazuh Manager API (Port 55000)** must be restricted at the OS / network firewall so that **only the Aegis SOC middleware server IP** can communicate with it.

### Option A: Linux `ufw` (Uncomplicated Firewall)
Run on the Wazuh Manager host:
```bash
# Allow API port 55000 ONLY from the Aegis Middleware IP (e.g. 10.0.1.10)
sudo ufw allow from 10.0.1.10 to any port 55000 proto tcp comment 'Allow Aegis Middleware to Wazuh API'

# Deny all other incoming traffic to port 55000
sudo ufw deny 55000/tcp
```

### Option B: Linux `iptables`
Run on the Wazuh Manager host:
```bash
# Allow Aegis Middleware IP (10.0.1.10)
sudo iptables -A INPUT -p tcp -s 10.0.1.10 --dport 55000 -j ACCEPT

# Drop port 55000 from all other hosts
sudo iptables -A INPUT -p tcp --dport 55000 -j DROP
```

### Option C: Windows Firewall (PowerShell)
Run on Windows Wazuh host:
```powershell
New-NetFirewallRule -DisplayName "Restrict Wazuh API to Aegis Middleware" `
  -Direction Inbound `
  -LocalPort 55000 `
  -Protocol TCP `
  -RemoteAddress "10.0.1.10" `
  -Action Allow
```

---

## 5. Environment Variables Reference Summary

| Variable | Description | Example |
|---|---|---|
| `PORT` | Node HTTP server port (Default: `3000`) | `8080` |
| `AEGIS_WEBHOOK_SECRET` | Bearer token secret for `/api/wazuh-webhook` | `s3cr3t-b3ar3r-t0k3n` |
| `AEGIS_CA_PATH` | Path to Wazuh Manager CA certificate PEM file | `/etc/aegis/wazuh-ca.pem` |
| `AEGIS_ADMIN_ALLOW_IPS` | Comma-separated IP / CIDR allowlist for admin routes | `127.0.0.1,10.0.0.0/16` |
| `AEGIS_TRUSTED_PROXY` | Set to `1` if running behind an Nginx/ALB reverse proxy | `1` |
