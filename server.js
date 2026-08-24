'use strict';

/* ════════════════════════════════════════════════════════════
   AEGIS SOC Middleware — Pure Receiver
   Receives alerts via HTTP POST, stores them, broadcasts via SSE.
   No SSH pull — data is pushed in by Wazuh integrations.
════════════════════════════════════════════════════════════ */

const http         = require('http');
const https        = require('https');
const fs           = require('fs');
const path         = require('path');

const PORT        = parseInt(process.env.PORT || '3000', 10);
const STATIC_ROOT = path.resolve(__dirname);
const CONFIG_FILE = path.join(__dirname, 'aegis.config.json');
const RULES_DIR   = path.join(__dirname, 'rules');

if (!fs.existsSync(RULES_DIR)) fs.mkdirSync(RULES_DIR, { recursive: true });

const { logAudit, getAuditLogs, clearAuditLogs } = require('./services/auditLog');
const { testConnection: testRedmineConnection, createIssueFromAlert: createRedmineIssue, syncResolvedIssues: syncRedmineIssues, shouldTriggerTicket } = require('./services/redmine');

/* ════════════════════════════════════════════════════════════
   SECURITY — rate limiter
════════════════════════════════════════════════════════════ */
const _rlStore = new Map();
function rateLimit(key, windowMs, max) {
  const now  = Date.now();
  const hits  = (_rlStore.get(key) || []).filter(t => t > now - windowMs);
  hits.push(now);
  _rlStore.set(key, hits);
  if (hits.length > max) {
    return { allowed: false, retryAfter: Math.ceil((hits[0] + windowMs - now) / 1000) };
  }
  return { allowed: true };
}
setInterval(() => {
  const cutoff = Date.now() - 3600000;
  for (const [k, v] of _rlStore) {
    if (v[v.length - 1] < cutoff) _rlStore.delete(k);
  }
}, 5 * 60 * 1000).unref();

const ADMIN_IPS = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
function getRemoteIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}
function isAdminIpAllowed(ip) {
  if (ADMIN_IPS.size === 0) return true;
  return ADMIN_IPS.has(ip);
}
function denyAdminIp(res, ip) {
  console.warn(`[AEGIS] Admin action blocked for IP: ${ip}`);
  return json(res, 403, { error: 'Forbidden: Admin actions are restricted by IP allowlist.' });
}

/* ── Load persisted config ─────────────────────────────── */
let _config = {
  webhookSecret: '',
  caPath: '',
  redmineUrl: '',
  redmineApiKey: '',
  redmineProject: '',
  redmineTrackerId: '1',
  redmineTriggerMode: 'min_level',  // 'min_level' | 'custom_rules' | 'all'
  redmineMinLevel: '7',
  redmineCustomRules: '',          // comma-separated Rule IDs (e.g. 81628, 5710, 550)
  redmineDedupHours: '24',         // deduplication window in hours (0 = disable)
  redmineAutoTicket: true,
};
let _tunnelState = {
  running: false,
  startedAt: null,
};
function _loadConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      _config = { ..._config, ...JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) };
    }
  } catch (e) {
    console.warn('[AEGIS] Could not read aegis.config.json:', e.message);
  }
  if (process.env.AEGIS_WEBHOOK_SECRET) _config.webhookSecret = process.env.AEGIS_WEBHOOK_SECRET;
}
_loadConfig();

function _saveConfig() {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(_config, null, 2), 'utf8');
  } catch (e) {
    console.warn('[AEGIS] Could not save aegis.config.json:', e.message);
  }
}

/* ════════════════════════════════════════════════════════════
   IN-MEMORY ALERT STORE
════════════════════════════════════════════════════════════ */
const VALID_USE_CASES = new Set([
  'critical_alerts',
  'blind_spots_agent_health',
  'critical_file_changes',
  'auth_access_anomalies',
  'threat_intel_matches',
]);

const STORE_FILE = path.join(__dirname, 'aegis.store.json');

const store = {
  critical_alerts:          [],
  blind_spots_agent_health: [],
  critical_file_changes:    [],
  auth_access_anomalies:    [],
  threat_intel_matches:     [],
};

let _hasLoggedInitialStoreLoad = false;
function _loadStore() {
  try {
    if (fs.existsSync(STORE_FILE)) {
      const data = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
      for (const k of Object.keys(store)) {
        if (Array.isArray(data[k])) store[k] = data[k];
      }
      // Purge legacy level < 7 alerts from critical_alerts
      if (Array.isArray(store.critical_alerts)) {
        store.critical_alerts = store.critical_alerts.filter(a => {
          const level = parseInt(a?.rule?.level ?? 0, 10);
          return level >= 7;
        });
      }
      if (!_hasLoggedInitialStoreLoad) {
        console.log('[AEGIS] Loaded persisted alert store from disk');
        _hasLoggedInitialStoreLoad = true;
      }
    }
  } catch (e) {
    console.warn('[AEGIS] Could not read aegis.store.json:', e.message);
  }
}

let _saveTimer = null;
function _saveStore(immediate = false) {
  if (immediate) { _flushStore(); }
  else { clearTimeout(_saveTimer); _saveTimer = setTimeout(_flushStore, 2000); }
}
function _flushStore() {
  try {
    const tmp = STORE_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(store, null, 2), 'utf8');
    fs.renameSync(tmp, STORE_FILE);
  } catch (e) {
    console.warn('[AEGIS] Could not write aegis.store.json:', e.message);
  }
}

_loadStore();

/* ════════════════════════════════════════════════════════════
   ALERT CLASSIFICATION
════════════════════════════════════════════════════════════ */
function classifyUseCase(alert) {
  const groups = alert?.rule?.groups || [];
  const g = Array.isArray(groups) ? groups.join(' ').toLowerCase() : String(groups).toLowerCase();
  const desc = String(alert?.rule?.description || '').toLowerCase();
  const level = parseInt(alert?.rule?.level ?? 0, 10);

  // 1. File Integrity / Syscheck
  if (/syscheck|fim|file_integrity|ossec_integrity|file_monitor|inotify/.test(g) || /file added|file modified|file deleted|integrity checksum/.test(desc)) {
    return 'critical_file_changes';
  }

  // 2. Authentication & Access Anomalies
  if (/authentication|sshd|pam|login|web|win_authentication|invalid_login|brute_force|logon|rdp|ftp_auth/.test(g) || /failed login|authentication failed|invalid user|password/.test(desc)) {
    return 'auth_access_anomalies';
  }

  // 3. Threat Intel / Malware / Attacks
  if (/threat|malware|virus|yara|rootkit|trojan|ids|exploit|injection|worm|ransomware|c2|virustotal|suricata|snort/.test(g) || /attack|exploit|malware|threat|sqli|xss/.test(desc)) {
    return 'threat_intel_matches';
  }

  // 4. Blind Spots & Agent Health (Only specific agent disconnect / keepalive / health events)
  if (/agent_disconnected|agent_health|keepalive|agentless/.test(g) || /agent disconnected|agent stopped|agent not responding|keepalive/.test(desc)) {
    return 'blind_spots_agent_health';
  }

  // 5. Critical Alerts — High severity alerts or ports/network/system events (level >= 7)
  if (level >= 7) {
    return 'critical_alerts';
  }

  return null; // discard low-severity misc alerts
}

function storeAlert(alert) {
  const useCase = alert.aegis_use_case;
  if (!VALID_USE_CASES.has(useCase)) return false;
  store[useCase].unshift(alert);
  _saveStore();

  // Auto-create Redmine Issue if enabled and alert matches condition (with deduplication)
  if (!alert._backfilled && shouldTriggerTicket(alert, _config)) {
    createRedmineIssue(alert, _config).catch(err => {
      console.warn('[Redmine] Auto-ticketing error:', err.message);
    });
  }

  return true;
}

/* ════════════════════════════════════════════════════════════
   SSE
════════════════════════════════════════════════════════════ */
const _sseClients = new Set();
function sseRegister(res) { _sseClients.add(res); res.on('close', () => _sseClients.delete(res)); }
function sseBroadcast(eventName, data) {
  const payload = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of _sseClients) {
    try { res.write(payload); } catch (_) { _sseClients.delete(res); }
  }
}

/* ════════════════════════════════════════════════════════════
   MIME
════════════════════════════════════════════════════════════ */
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
};

/* ════════════════════════════════════════════════════════════
   HELPERS
════════════════════════════════════════════════════════════ */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function json(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type':  'application/json',
    'Content-Length': Buffer.byteLength(body),
    'Access-Control-Allow-Origin': '*',
  });
  res.end(body);
}

function validateBearer(req) {
  if (!_config.webhookSecret) return true;
  const auth = req.headers['authorization'] ?? '';
  return auth === `Bearer ${_config.webhookSecret}`;
}

/* ════════════════════════════════════════════════════════════
   WAZUH API TEST HELPER
════════════════════════════════════════════════════════════ */
async function testWazuhConnection(body) {
  const { baseUrl, username, password, sslVerify } = body;
  const https = require('https');
  const agent = new https.Agent({ rejectUnauthorized: sslVerify !== false });
  try {
    const authRes = await fetch(`${baseUrl}/security/user/authenticate`, {
      method: 'GET',
      headers: { Authorization: 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64') },
      agent,
      signal: AbortSignal.timeout(10000),
    });
    if (!authRes.ok) {
      const err = await authRes.json().catch(() => ({}));
      return { ok: false, error: err?.detail || `HTTP ${authRes.status}` };
    }
    const authData = await authRes.json();
    const token = authData?.data?.token;
    if (!token) return { ok: false, error: 'No token returned from Wazuh API' };
    const infoRes = await fetch(`${baseUrl}/`, { headers: { Authorization: `Bearer ${token}` }, agent, signal: AbortSignal.timeout(10000) });
    const info = await infoRes.json().catch(() => ({}));
    return { ok: true, version: info?.data?.api_version || 'unknown', token };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/* ════════════════════════════════════════════════════════════
   REQUEST ROUTER
════════════════════════════════════════════════════════════ */
const server = http.createServer(async (req, res) => {
  const url      = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;
  const method   = req.method.toUpperCase();

  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    });
    return res.end();
  }

  const remoteIp = getRemoteIp(req);

  const enforceRateLimit = (key, windowMs, max) => {
    const rl = rateLimit(key, windowMs, max);
    if (!rl.allowed) {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': String(rl.retryAfter), 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ error: 'Rate limit exceeded.', retryAfter: rl.retryAfter }));
      return false;
    }
    return true;
  };

  /* ══════════════════════════════════════════════════════════
     POST /api/wazuh-webhook
  ══════════════════════════════════════════════════════════ */
  if (pathname === '/api/wazuh-webhook' && method === 'POST') {
    if (!enforceRateLimit(`webhook:${remoteIp}`, 60000, 120)) return;
    if (!validateBearer(req)) { console.warn('[AEGIS] Webhook rejected — invalid Bearer token'); return json(res, 401, { error: 'Unauthorized' }); }

    let body;
    try { body = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: 'Invalid JSON body' }); }

    if (!body?.aegis_use_case || !VALID_USE_CASES.has(body.aegis_use_case)) {
      const classified = classifyUseCase(body);
      if (!classified) return json(res, 200, { ok: true, skipped: true, reason: 'below severity threshold' });
      body.aegis_use_case = classified;
    } else if (body.aegis_use_case === 'critical_alerts') {
      const classified = classifyUseCase(body);
      if (!classified) return json(res, 200, { ok: true, skipped: true, reason: 'below severity threshold' });
      body.aegis_use_case = classified;
    }

    if (!body.receivedAt) body.receivedAt = new Date().toISOString();
    const stored = storeAlert(body);
    if (!stored) return json(res, 400, { error: 'Failed to store alert' });
    sseBroadcast('alert', { useCase: body.aegis_use_case, alert: body });
    console.log(`[AEGIS] Webhook: ${body.aegis_use_case} | rule=${body.rule?.id} | level=${body.rule?.level} | agent=${body.agent?.name}`);
    return json(res, 200, { ok: true, useCase: body.aegis_use_case });
  }

  /* ══════════════════════════════════════════════════════════
     POST /api/bulk-ingest — push historical alerts from Wazuh side
  ══════════════════════════════════════════════════════════ */
  if (pathname === '/api/bulk-ingest' && method === 'POST') {
    if (!enforceRateLimit(`bulk:${remoteIp}`, 60000, 10)) return;
    if (!validateBearer(req)) return json(res, 401, { error: 'Unauthorized' });

    let body;
    try { body = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: 'Invalid JSON body' }); }

    const alerts = Array.isArray(body.alerts) ? body.alerts : [body];
    let accepted = 0, skipped = 0;

    for (const alert of alerts) {
      if (!alert.aegis_use_case || !VALID_USE_CASES.has(alert.aegis_use_case)) {
        const classified = classifyUseCase(alert);
        if (!classified) { skipped++; continue; }
        alert.aegis_use_case = classified;
      } else if (alert.aegis_use_case === 'critical_alerts') {
        const classified = classifyUseCase(alert);
        if (!classified) { skipped++; continue; }
        alert.aegis_use_case = classified;
      }
      if (!alert.receivedAt) alert.receivedAt = new Date().toISOString();
      alert._backfilled = true;
      storeAlert(alert);
      sseBroadcast('alert', { useCase: alert.aegis_use_case, alert });
      accepted++;
    }

    _saveStore(true);
    sseBroadcast('sync-done', { accepted, categories: Object.fromEntries(Object.entries(store).map(([k, v]) => [k, v.length])) });
    console.log(`[AEGIS] Bulk ingest: accepted=${accepted} skipped=${skipped}`);
    return json(res, 200, { ok: true, accepted, skipped });
  }

  /* ══════════════════════════════════════════════════════════
     GET /api/dashboard-data[?from=ISO&to=ISO]
  ══════════════════════════════════════════════════════════ */
  if (pathname === '/api/dashboard-data' && method === 'GET') {
    _loadStore(); // always reload from disk to reflect latest changes
    const fromParam = url.searchParams.get('from');
    const toParam   = url.searchParams.get('to');
    const fromMs = fromParam ? new Date(fromParam).getTime() : null;
    const toMs   = toParam   ? new Date(toParam).getTime()   : null;
    const hasRange = fromMs && toMs && !isNaN(fromMs) && !isNaN(toMs);

    const summary = {};
    for (const [k, v] of Object.entries(store)) {
      let filtered = v;
      if (hasRange) {
        filtered = v.filter(a => {
          const ts = a.timestamp || a.receivedAt || a['@timestamp'];
          if (!ts) return true;
          const t = new Date(ts).getTime();
          return !isNaN(t) && t >= fromMs && t <= toMs;
        });
      }
      summary[k] = { count: filtered.length, alerts: filtered };
    }
    return json(res, 200, summary);
  }

  /* ══════════════════════════════════════════════════════════
     POST/DELETE /api/clear-data — clear all stored alerts
  ══════════════════════════════════════════════════════════ */
  if ((pathname === '/api/clear-data' || pathname === '/api/dashboard-data') && (method === 'POST' || method === 'DELETE')) {
    if (!isAdminIpAllowed(remoteIp)) return denyAdminIp(res, remoteIp);
    if (!enforceRateLimit(`clear:${remoteIp}`, 60000, 5)) return;

    for (const k of Object.keys(store)) store[k] = [];
    _saveStore(true);
    sseBroadcast('sync-done', { accepted: 0, categories: Object.fromEntries(Object.entries(store).map(([k, v]) => [k, v.length])) });
    logAudit({ user: req.headers['x-aegis-user'] || 'browser', action: 'data_cleared', before: 'had data', after: 'empty' }).catch(() => {});
    console.log('[AEGIS] All alert data cleared');
    return json(res, 200, { ok: true, message: 'All alert data cleared' });
  }

  /* ══════════════════════════════════════════════════════════
     GET /api/db-stats — middleware database size & health info
  ══════════════════════════════════════════════════════════ */
  if (pathname === '/api/db-stats' && method === 'GET') {
    _loadStore();
    const getFileStat = (filePath) => {
      try {
        if (fs.existsSync(filePath)) {
          const s = fs.statSync(filePath);
          return { size: s.size, mtime: s.mtime.toISOString(), exists: true };
        }
      } catch (_) {}
      return { size: 0, mtime: null, exists: false };
    };

    const storeStat   = getFileStat(STORE_FILE);
    const configStat  = getFileStat(CONFIG_FILE);
    const auditStat   = getFileStat(path.join(__dirname, 'audit.log.ndjson'));
    const serverLog   = getFileStat(path.join(__dirname, 'server.log'));
    const serverErr   = getFileStat(path.join(__dirname, 'server.err'));

    // Per-category record counts + estimated byte size
    const categories = {};
    let totalRecords = 0;
    for (const [k, v] of Object.entries(store)) {
      const byteEst = Buffer.byteLength(JSON.stringify(v), 'utf8');
      categories[k] = { count: v.length, estimatedBytes: byteEst };
      totalRecords += v.length;
    }

    // Oldest & newest alert timestamp
    let oldestTs = null, newestTs = null;
    for (const v of Object.values(store)) {
      for (const a of v) {
        const ts = a.timestamp || a.receivedAt || a['@timestamp'];
        if (!ts) continue;
        const t = new Date(ts).getTime();
        if (isNaN(t)) continue;
        if (oldestTs === null || t < oldestTs) oldestTs = t;
        if (newestTs === null || t > newestTs) newestTs = t;
      }
    }

    return json(res, 200, {
      ok: true,
      generatedAt: new Date().toISOString(),
      store: {
        path: STORE_FILE,
        fileSize: storeStat.size,
        lastModified: storeStat.mtime,
        totalRecords,
        oldestRecord: oldestTs ? new Date(oldestTs).toISOString() : null,
        newestRecord: newestTs ? new Date(newestTs).toISOString() : null,
        categories,
      },
      files: {
        config:    { path: CONFIG_FILE, ...configStat },
        auditLog:  { path: path.join(__dirname, 'audit.log.ndjson'), ...auditStat },
        serverLog: { path: path.join(__dirname, 'server.log'), ...serverLog },
        serverErr: { path: path.join(__dirname, 'server.err'), ...serverErr },
      },
      runtime: {
        uptime: Math.floor(process.uptime()),
        memUsed: process.memoryUsage().rss,
        nodeVersion: process.version,
        platform: process.platform,
        pid: process.pid,
      },
    });
  }

  /* ══════════════════════════════════════════════════════════
     GET /api/events  (Server-Sent Events)
  ══════════════════════════════════════════════════════════ */
  if (pathname === '/api/events' && method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'Access-Control-Allow-Origin': '*' });
    res.write('event: connected\ndata: {"status":"connected"}\n\n');
    res.write(`event: snapshot\ndata: ${JSON.stringify(store)}\n\n`);
    sseRegister(res);
    const keepAlive = setInterval(() => { try { res.write(': ping\n\n'); } catch { clearInterval(keepAlive); } }, 25000);
    req.on('close', () => clearInterval(keepAlive));
    return;
  }

  /* ══════════════════════════════════════════════════════════
     PUT /api/config
  ══════════════════════════════════════════════════════════ */
  if (pathname === '/api/config' && method === 'PUT') {
    if (!isAdminIpAllowed(remoteIp)) return denyAdminIp(res, remoteIp);
    if (!enforceRateLimit(`config_put:${remoteIp}`, 60000, 10)) return;

    let body;
    try { body = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: 'Invalid JSON' }); }

    const beforeSnapshot = JSON.stringify({ webhookSecretSet: !!_config.webhookSecret });
    if (typeof body.webhookSecret === 'string') _config.webhookSecret = body.webhookSecret;
    try { fs.writeFileSync(CONFIG_FILE, JSON.stringify(_config, null, 2), 'utf8'); } catch (e) { return json(res, 500, { error: 'Could not save config', detail: e.message }); }
    const afterSnapshot = JSON.stringify({ webhookSecretSet: !!_config.webhookSecret });
    logAudit({ user: req.headers['x-aegis-user'] || 'browser', action: 'config_update', filename: 'aegis.config.json', before: beforeSnapshot, after: afterSnapshot }).catch(() => {});
    console.log('[AEGIS] Config updated');
    return json(res, 200, { ok: true });
  }

  /* ══════════════════════════════════════════════════════════
     GET /api/config
  ══════════════════════════════════════════════════════════ */
  if (pathname === '/api/config' && method === 'GET') {
    return json(res, 200, { webhookSecretSet: !!_config.webhookSecret, devMode: !_config.webhookSecret });
  }

  /* ══════════════════════════════════════════════════════════
     POST /api/wazuh-test (Backend proxy to test Wazuh API)
  ══════════════════════════════════════════════════════════ */
  if (pathname === '/api/wazuh-test' && method === 'POST') {
    let body;
    try { body = JSON.parse(await readBody(req)); } catch { return json(res, 400, { ok: false, error: 'Invalid JSON' }); }

    const { baseUrl, authMode, username, password, token, sslVerify } = body;
    if (!baseUrl) return json(res, 400, { ok: false, error: 'Manager API URL is required' });

    try {
      const targetUrl = new URL(baseUrl);
      const isHttps = targetUrl.protocol === 'https:';
      const httpModule = isHttps ? https : http;

      if (authMode === 'token') {
        const pingReq = httpModule.request({
          hostname: targetUrl.hostname,
          port: targetUrl.port || (isHttps ? 443 : 80),
          path: '/',
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token || ''}`,
            'User-Agent': 'Aegis-SOC/1.0'
          },
          rejectUnauthorized: sslVerify === true,
          timeout: 10000
        }, (testRes) => {
          let data = '';
          testRes.on('data', chunk => data += chunk);
          testRes.on('end', () => {
            if (testRes.statusCode >= 200 && testRes.statusCode < 400) {
              return json(res, 200, { ok: true, token, message: 'Token verified successfully' });
            } else {
              return json(res, 200, { ok: false, error: `Wazuh returned HTTP ${testRes.statusCode}: ${data.slice(0, 100)}` });
            }
          });
        });

        pingReq.on('error', (err) => {
          return json(res, 200, { ok: false, error: `Connection failed: ${err.message}` });
        });
        pingReq.on('timeout', () => {
          pingReq.destroy();
          return json(res, 200, { ok: false, error: 'Connection timed out after 10 seconds' });
        });
        pingReq.end();

      } else {
        const authStr = Buffer.from(`${username || ''}:${password || ''}`).toString('base64');
        const authReq = httpModule.request({
          hostname: targetUrl.hostname,
          port: targetUrl.port || (isHttps ? 443 : 80),
          path: '/security/user/authenticate',
          method: 'POST',
          headers: {
            'Authorization': `Basic ${authStr}`,
            'Content-Type': 'application/json',
            'User-Agent': 'Aegis-SOC/1.0'
          },
          rejectUnauthorized: sslVerify === true,
          timeout: 10000
        }, (authRes) => {
          let data = '';
          authRes.on('data', chunk => data += chunk);
          authRes.on('end', () => {
            try {
              const parsed = JSON.parse(data);
              if (authRes.statusCode === 200 && parsed?.data?.token) {
                return json(res, 200, { ok: true, token: parsed.data.token, message: 'Authenticated successfully' });
              } else if (authRes.statusCode === 200 && parsed?.token) {
                return json(res, 200, { ok: true, token: parsed.token, message: 'Authenticated successfully' });
              } else {
                const errMsg = parsed?.message || parsed?.error || `HTTP ${authRes.statusCode}: Authentication failed (check credentials)`;
                return json(res, 200, { ok: false, error: errMsg });
              }
            } catch (e) {
              if (authRes.statusCode === 200) {
                return json(res, 200, { ok: true, message: 'Connected successfully' });
              }
              return json(res, 200, { ok: false, error: `Wazuh returned HTTP ${authRes.statusCode}: ${data.slice(0, 150)}` });
            }
          });
        });

        authReq.on('error', (err) => {
          return json(res, 200, { ok: false, error: `Connection failed: ${err.message}` });
        });
        authReq.on('timeout', () => {
          authReq.destroy();
          return json(res, 200, { ok: false, error: 'Connection timed out after 10 seconds' });
        });
        authReq.end();
      }

    } catch (err) {
      return json(res, 200, { ok: false, error: `Invalid URL or test error: ${err.message}` });
    }
    return;
  }

  /* ══════════════════════════════════════════════════════════
     REDMINE INTEGRATION API ENDPOINTS
  ══════════════════════════════════════════════════════════ */

  /* GET /api/redmine/config */
  if (pathname === '/api/redmine/config' && method === 'GET') {
    return json(res, 200, {
      ok: true,
      config: {
        redmineUrl: _config.redmineUrl || '',
        redmineApiKey: _config.redmineApiKey ? '••••••••' + _config.redmineApiKey.slice(-4) : '',
        hasApiKey: Boolean(_config.redmineApiKey),
        redmineProject: _config.redmineProject || '',
        redmineTrackerId: _config.redmineTrackerId || '1',
        redmineTriggerMode: _config.redmineTriggerMode || 'min_level',
        redmineMinLevel: _config.redmineMinLevel || '7',
        redmineCustomRules: _config.redmineCustomRules || '',
        redmineDedupHours: _config.redmineDedupHours || '24',
        redmineAutoTicket: _config.redmineAutoTicket !== false,
      }
    });
  }

  /* PUT /api/redmine/config */
  if (pathname === '/api/redmine/config' && method === 'PUT') {
    if (!isAdminIpAllowed(remoteIp)) return denyAdminIp(res, remoteIp);
    if (!enforceRateLimit(`redmine_cfg:${remoteIp}`, 60000, 20)) return;

    let body;
    try { body = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: 'Invalid JSON body' }); }

    if (body.redmineUrl !== undefined) _config.redmineUrl = String(body.redmineUrl).trim();
    if (body.redmineApiKey !== undefined && !body.redmineApiKey.includes('••••')) {
      _config.redmineApiKey = String(body.redmineApiKey).trim();
    }
    if (body.redmineProject !== undefined) _config.redmineProject = String(body.redmineProject).trim();
    if (body.redmineTrackerId !== undefined) _config.redmineTrackerId = String(body.redmineTrackerId).trim();
    if (body.redmineTriggerMode !== undefined) _config.redmineTriggerMode = String(body.redmineTriggerMode).trim();
    if (body.redmineMinLevel !== undefined) _config.redmineMinLevel = String(body.redmineMinLevel).trim();
    if (body.redmineCustomRules !== undefined) _config.redmineCustomRules = String(body.redmineCustomRules).trim();
    if (body.redmineDedupHours !== undefined) _config.redmineDedupHours = String(body.redmineDedupHours).trim();
    if (body.redmineAutoTicket !== undefined) _config.redmineAutoTicket = Boolean(body.redmineAutoTicket);

    _saveConfig();
    logAudit({
      user: req.headers['x-aegis-user'] || 'admin',
      action: 'config_update',
      filename: 'redmine.config',
      before: 'redmine config',
      after: `Updated Redmine: URL=${_config.redmineUrl}, TriggerMode=${_config.redmineTriggerMode}, MinLevel=${_config.redmineMinLevel}, Dedup=${_config.redmineDedupHours}h, AutoTicket=${_config.redmineAutoTicket}`,
    }).catch(() => {});

    return json(res, 200, { ok: true, message: 'Redmine settings saved successfully' });
  }

  /* POST /api/redmine/test */
  if (pathname === '/api/redmine/test' && method === 'POST') {
    if (!enforceRateLimit(`redmine_test:${remoteIp}`, 60000, 15)) return;

    let body;
    try { body = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: 'Invalid JSON body' }); }

    const baseUrl = body.redmineUrl || _config.redmineUrl;
    let apiKey = body.redmineApiKey;
    if (!apiKey || apiKey.includes('••••')) apiKey = _config.redmineApiKey;

    const result = await testRedmineConnection({ baseUrl, apiKey });
    return json(res, result.ok ? 200 : 400, result);
  }

  /* POST /api/redmine/sync */
  if (pathname === '/api/redmine/sync' && method === 'POST') {
    if (!isAdminIpAllowed(remoteIp)) return denyAdminIp(res, remoteIp);
    if (!enforceRateLimit(`redmine_sync:${remoteIp}`, 60000, 10)) return;

    const result = await syncRedmineIssues(_config);
    return json(res, result.ok ? 200 : 400, result);
  }

  /* POST /api/redmine/webhook */
  if (pathname === '/api/redmine/webhook' && method === 'POST') {
    let body;
    try { body = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: 'Invalid JSON body' }); }

    const issue = body.issue || body.payload?.issue || body;
    const action = body.action || 'updated';
    const author = body.author?.name || body.journal?.user?.name || 'Redmine User';

    if (issue?.id) {
      const issueUrl = `${(_config.redmineUrl || '').replace(/\/+$/, '')}/issues/${issue.id}`;
      await logAudit({
        user: author,
        action: 'redmine_fix_synced',
        filename: `Redmine Issue #${issue.id}`,
        before: `Issue ${action}: ${issue.subject || ''}`,
        after: `Status: ${issue.status?.name || 'Updated'}\nURL: ${issueUrl}\nNotes: ${body.journal?.notes || issue.description || ''}`,
      }).catch(() => {});
      console.log(`[Redmine Webhook] Synced issue #${issue.id} (${action})`);
    }

    return json(res, 200, { ok: true, message: 'Webhook received' });
  }

  /* ══════════════════════════════════════════════════════════
     SSH TUNNEL STATUS & CONTROL ENDPOINTS
  ══════════════════════════════════════════════════════════ */
  if (pathname === '/api/tunnel') {
    if (method === 'GET') {
      return json(res, 200, { ok: true, running: _tunnelState.running, info: _tunnelState });
    }
    if (method === 'POST') {
      _tunnelState.running = true;
      _tunnelState.startedAt = new Date().toISOString();
      return json(res, 200, { ok: true, running: true, message: 'Tunnel opened' });
    }
    if (method === 'DELETE') {
      _tunnelState.running = false;
      _tunnelState.startedAt = null;
      return json(res, 200, { ok: true, running: false, message: 'Tunnel closed' });
    }
  }

  /* ══════════════════════════════════════════════════════════
     GET /api/audit-logs
  ══════════════════════════════════════════════════════════ */
  if (pathname === '/api/audit-logs' && method === 'GET') {
    const limit  = parseInt(url.searchParams.get('limit') || '200', 10);
    const user   = url.searchParams.get('user')   || '';
    const action = url.searchParams.get('action') || '';
    try {
      const logs = await getAuditLogs({ limit, user, action });
      return json(res, 200, { ok: true, count: logs.length, logs });
    } catch (e) {
      return json(res, 500, { error: 'Could not read audit logs', detail: e.message });
    }
  }

  /* POST /api/audit-logs */
  if (pathname === '/api/audit-logs' && method === 'POST') {
    let body;
    try { body = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: 'Invalid JSON body' }); }
    if (!body?.action) return json(res, 400, { error: '"action" field is required' });
    try {
      const record = await logAudit({ user: body.user || req.headers['x-aegis-user'] || 'api', action: body.action, filename: body.filename || '', before: body.before || '', after: body.after || '' });
      return json(res, 201, { ok: true, entry: record });
    } catch (e) {
      return json(res, 500, { error: 'Could not write audit log', detail: e.message });
    }
  }

  /* DELETE /api/audit-logs */
  if (pathname === '/api/audit-logs' && method === 'DELETE') {
    if (!isAdminIpAllowed(remoteIp)) return denyAdminIp(res, remoteIp);
    if (!enforceRateLimit(`audit_del:${remoteIp}`, 60000, 10)) return;
    try {
      await logAudit({ user: req.headers['x-aegis-user'] || 'browser', action: 'audit_logs_cleared', before: 'had entries', after: 'wiped' });
      await clearAuditLogs();
      return json(res, 200, { ok: true, message: 'Audit logs cleared' });
    } catch (e) {
      return json(res, 500, { error: 'Could not clear audit logs', detail: e.message });
    }
  }

  /* ══════════════════════════════════════════════════════════
     /api/rules & /rules/files — Rule file management
  ══════════════════════════════════════════════════════════ */
  if (pathname === '/rules/files' || pathname === '/api/rules/files') {
    if (method === 'GET') {
      try {
        const files = fs.readdirSync(RULES_DIR).filter(f => f.endsWith('.xml')).map(f => { const s = fs.statSync(path.join(RULES_DIR, f)); return { name: f, filename: f, size: s.size, modified: s.mtime.toISOString() }; });
        return json(res, 200, { ok: true, status: 0, count: files.length, files, data: { affected_items: files, total_affected_items: files.length } });
      } catch (e) { return json(res, 500, { error: 'Could not list rules', detail: e.message }); }
    }
  }

  if (pathname.startsWith('/api/rules') || pathname.startsWith('/rules/')) {
    const cleanPath = pathname.replace(/^\/api\/rules/, '').replace(/^\/rules/, '');
    const rawFile   = cleanPath.replace(/^\//, '');
    const fileName  = path.basename(rawFile);
    const filePath  = rawFile && rawFile !== 'files' ? path.join(RULES_DIR, fileName) : null;

    if (filePath && path.extname(fileName).toLowerCase() !== '.xml') return json(res, 400, { error: 'Only .xml rule files are supported' });

    if ((!rawFile || rawFile === 'files') && method === 'GET') {
      try {
        const files = fs.readdirSync(RULES_DIR).filter(f => f.endsWith('.xml')).map(f => { const s = fs.statSync(path.join(RULES_DIR, f)); return { name: f, filename: f, size: s.size, modified: s.mtime.toISOString() }; });
        return json(res, 200, { ok: true, status: 0, count: files.length, files, data: { affected_items: files, total_affected_items: files.length } });
      } catch (e) { return json(res, 500, { error: 'Could not list rules', detail: e.message }); }
    }

    if (filePath && method === 'GET') {
      if (!fs.existsSync(filePath)) return json(res, 404, { error: `Rule file "${fileName}" not found` });
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const bodyStr = JSON.stringify({ ok: true, filename: fileName, content });
        res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyStr), 'Access-Control-Allow-Origin': '*' });
        return res.end(bodyStr);
      } catch (e) { return json(res, 500, { error: 'Could not read rule file', detail: e.message }); }
    }

    if (filePath && method === 'PUT') {
      if (!isAdminIpAllowed(remoteIp)) return denyAdminIp(res, remoteIp);
      if (!enforceRateLimit(`rules_put:${remoteIp}`, 60000, 30)) return;
      let reqBody;
      try { reqBody = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: 'Invalid JSON body' }); }
      if (typeof reqBody?.content !== 'string') return json(res, 400, { error: '"content" (string) is required' });
      const existed = fs.existsSync(filePath);
      const before  = existed ? fs.readFileSync(filePath, 'utf8') : '';
      try { fs.writeFileSync(filePath, reqBody.content, 'utf8'); } catch (e) { return json(res, 500, { error: 'Could not write rule file', detail: e.message }); }
      logAudit({ user: req.headers['x-aegis-user'] || 'api', action: existed ? 'rule_updated' : 'rule_created', filename: fileName, before: existed ? before : '(new file)', after: reqBody.content }).catch(() => {});
      return json(res, 200, { ok: true, action: existed ? 'updated' : 'created', filename: fileName });
    }

    if (filePath && method === 'DELETE') {
      if (!isAdminIpAllowed(remoteIp)) return denyAdminIp(res, remoteIp);
      if (!enforceRateLimit(`rules_del:${remoteIp}`, 60000, 10)) return;
      if (!fs.existsSync(filePath)) return json(res, 404, { error: `Rule file "${fileName}" not found` });
      const before = fs.readFileSync(filePath, 'utf8');
      try { fs.unlinkSync(filePath); } catch (e) { return json(res, 500, { error: 'Could not delete rule file', detail: e.message }); }
      logAudit({ user: req.headers['x-aegis-user'] || 'api', action: 'rule_deleted', filename: fileName, before, after: '(deleted)' }).catch(() => {});
      return json(res, 200, { ok: true, message: `Rule file "${fileName}" deleted` });
    }

    return json(res, 405, { error: 'Method not allowed for /api/rules' });
  }

  /* ══════════════════════════════════════════════════════════
     POST /api/wazuh-test
  ══════════════════════════════════════════════════════════ */
  if (pathname === '/api/wazuh-test' && method === 'POST') {
    if (!enforceRateLimit(`test:${remoteIp}`, 60000, 10)) return;
    let body;
    try { body = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: 'Invalid JSON body' }); }
    if (!body?.baseUrl) return json(res, 400, { error: 'Missing Wazuh Manager API URL.' });
    const testResult = await testWazuhConnection(body);
    return json(res, testResult.ok ? 200 : 400, testResult);
  }

  /* ══════════════════════════════════════════════════════════
     Static file serving
  ══════════════════════════════════════════════════════════ */
  if (method !== 'GET' && method !== 'HEAD') return json(res, 405, { error: 'Method not allowed' });

  let filePath = pathname === '/' ? '/index.html' : pathname;
  filePath = path.join(STATIC_ROOT, filePath);
  if (!filePath.startsWith(STATIC_ROOT)) return json(res, 403, { error: 'Forbidden' });

  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('404 Not Found'); }
    const ext  = path.extname(filePath).toLowerCase();
    const mime = MIME[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime, 'Content-Length': stat.size, 'Cache-Control': 'no-cache' });
    if (method === 'HEAD') return res.end();
    fs.createReadStream(filePath).pipe(res);
  });
});

/* ════════════════════════════════════════════════════════════
   START
════════════════════════════════════════════════════════════ */
server.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║        AEGIS SOC — Pure Receiver Mode            ║');
  console.log('╠══════════════════════════════════════════════════╣');
  console.log(`║  Dashboard:    http://localhost:${PORT}                ║`);
  console.log(`║  Webhook:      POST /api/wazuh-webhook            ║`);
  console.log(`║  Bulk Ingest:  POST /api/bulk-ingest              ║`);
  console.log(`║  Secret:       ${_config.webhookSecret ? '*** configured ***' : 'NOT SET (dev mode)'}              ║`);
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');
});

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`[AEGIS] Port ${PORT} already in use. Try: PORT=3001 node server.js`);
  } else {
    console.error('[AEGIS] Server error:', e);
  }
  process.exit(1);
});
