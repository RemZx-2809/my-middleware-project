'use strict';

/**
 * services/redmine.js
 *
 * Redmine REST API Integration with Intelligent Deduplication:
 * - Test connection with Redmine server
 * - Auto-create issues from security alerts matching configured rules/severities
 * - Intelligent Fingerprint-based Deduplication (suppresses repeated alerts for the same device & rule/file)
 * - Sync vulnerability / file resolution history into audit log
 * - Handle incoming Redmine webhooks
 */

const http  = require('http');
const https = require('https');
const { URL } = require('url');
const { logAudit } = require('./auditLog');

/**
 * In-memory deduplication cache:
 * Map of fingerprint -> { timestamp, issueId, count, lastSubject }
 */
const _dedupCache = new Map();

/**
 * Helper to make HTTP/HTTPS request to Redmine API
 */
function _request(endpoint, { method = 'GET', baseUrl, apiKey, body = null } = {}) {
  return new Promise((resolve, reject) => {
    if (!baseUrl) return reject(new Error('Redmine base URL is required'));
    if (!apiKey)  return reject(new Error('Redmine API Key is required'));

    let fullUrl;
    try {
      fullUrl = new URL(endpoint, baseUrl.endsWith('/') ? baseUrl : baseUrl + '/');
      // Pass API key in query params as well for maximum proxy/firewall compatibility
      if (!fullUrl.searchParams.has('key')) {
        fullUrl.searchParams.set('key', apiKey);
      }
    } catch (err) {
      return reject(new Error(`Invalid Redmine URL: ${err.message}`));
    }

    const isHttps = fullUrl.protocol === 'https:';
    const client  = isHttps ? https : http;

    const payload = body ? JSON.stringify(body) : null;

    const options = {
      method,
      hostname: fullUrl.hostname,
      port: fullUrl.port || (isHttps ? 443 : 80),
      path: fullUrl.pathname + fullUrl.search,
      headers: {
        'X-Redmine-API-Key': apiKey,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'Aegis-SOC-Middleware/1.0',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
      timeout: 10000,
    };

    const req = client.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        let parsed = null;
        try {
          if (data) parsed = JSON.parse(data);
        } catch (_) {
          parsed = { raw: data };
        }

        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ status: res.statusCode, data: parsed });
        } else {
          const errMsg = parsed?.errors ? (Array.isArray(parsed.errors) ? parsed.errors.join(', ') : JSON.stringify(parsed.errors)) : `HTTP ${res.statusCode} ${res.statusMessage || ''}`;
          reject(new Error(errMsg));
        }
      });
    });

    req.on('error', err => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Redmine request timed out (10s)'));
    });

    if (payload) req.write(payload);
    req.end();
  });
}

/**
 * Generate a unique fingerprint for an alert to prevent duplicate tickets
 * Format: ruleId/desc + deviceName + targetFile/srcIp
 */
function getAlertFingerprint(alert) {
  const ruleId   = alert?.rule?.id || alert?.rule?.description || 'rule';
  const agent    = alert?.agent?.name || 'agent';
  const devname  = alert?.data?.devname || '';
  const filePath = alert?.syscheck?.path || alert?.data?.path || alert?.data?.srcip || '';
  return `${ruleId}::${agent}::${devname}::${filePath}`.toLowerCase();
}

/**
 * Check if alert should trigger Redmine auto-ticketing based on flexible rule configuration
 */
function shouldTriggerTicket(alert, config = {}) {
  if (config.redmineAutoTicket === false) return false;
  if (!config.redmineUrl || !config.redmineApiKey || !config.redmineProject) return false;

  const mode = config.redmineTriggerMode || 'min_level';
  const level = parseInt(alert?.rule?.level ?? 0, 10);
  const ruleId = String(alert?.rule?.id || '').trim();

  // Mode 1: All Rules
  if (mode === 'all') return true;

  // Mode 2: Specific Rule IDs (e.g. "81628, 5710, 550")
  if (mode === 'custom_rules') {
    const customList = (config.redmineCustomRules || '')
      .split(/[\s,]+/)
      .map(s => s.trim())
      .filter(Boolean);
    if (customList.length > 0) {
      return customList.includes(ruleId) || customList.some(pattern => String(alert?.rule?.description || '').toLowerCase().includes(pattern.toLowerCase()));
    }
  }

  // Mode 3: Minimum Severity Level threshold (default)
  const minLvl = parseInt(config.redmineMinLevel || '7', 10);
  return level >= minLvl || (alert?.aegis_use_case === 'critical_alerts' && minLvl <= 11);
}

/**
 * 1. Test Redmine Connection
 */
async function testConnection({ baseUrl, apiKey }) {
  try {
    // Attempt 1: Get current user info
    try {
      const res = await _request('users/current.json', { baseUrl, apiKey });
      const user = res.data?.user;
      return {
        ok: true,
        message: `Connected successfully as ${user?.firstname || ''} ${user?.lastname || user?.login || 'User'}`.trim(),
        user: {
          id: user?.id,
          login: user?.login,
          name: `${user?.firstname || ''} ${user?.lastname || ''}`.trim() || user?.login,
          mail: user?.mail,
        },
      };
    } catch (e1) {
      // Attempt 2: Fallback to projects.json
      const res2 = await _request('projects.json?limit=1', { baseUrl, apiKey });
      return {
        ok: true,
        message: `Connected successfully to Redmine (${res2.data?.total_count || 0} projects accessible)`,
        user: {
          name: 'Redmine API User',
        },
      };
    }
  } catch (err) {
    return {
      ok: false,
      error: err.message,
    };
  }
}

/**
 * 2. Create Redmine Issue (Supports Auto & Manual Dispatch)
 */
async function createIssueFromAlert(alert, config = {}, options = {}) {
  const baseUrl = config.redmineUrl;
  const apiKey  = config.redmineApiKey;
  const project = config.redmineProject;
  const tracker = config.redmineTrackerId || 1;

  if (!baseUrl || !apiKey || !project) {
    return { ok: false, error: 'Redmine is not fully configured (URL, API Key, Project are required)' };
  }

  const level = parseInt(alert?.rule?.level ?? 0, 10);
  const desc  = alert?.rule?.description || 'Security Alert';
  const ruleId = alert?.rule?.id || '';
  const agent = alert?.agent?.name || 'unknown-device';
  const devname = alert?.data?.devname || '';
  const targetDevice = devname ? `${agent} (${devname})` : agent;
  const filePath = alert?.syscheck?.path || alert?.data?.path || '';
  const mitre = alert?.rule?.mitre?.id || alert?.rule?.mitre?.technique?.[0] || 'N/A';
  const srcip = alert?.data?.srcip || alert?.source?.srcip || 'N/A';
  const dstip = alert?.data?.dstip || alert?.destination?.dstip || 'N/A';
  const fullLog = alert?.full_log || JSON.stringify(alert?.data || {}, null, 2);

  // ── DEDUPLICATION CHECK (Only for auto-dispatch unless bypassDedup is true) ──
  const fingerprint = getAlertFingerprint(alert);
  const dedupHours  = parseFloat(config.redmineDedupHours ?? '24');
  const existing    = _dedupCache.get(fingerprint);

  if (!options.bypassDedup && dedupHours > 0 && existing) {
    const elapsedMs = Date.now() - existing.timestamp;
    const windowMs  = dedupHours * 3600 * 1000;

    if (elapsedMs < windowMs) {
      existing.count = (existing.count || 1) + 1;
      const minsAgo = Math.round(elapsedMs / 60000);
      console.log(`[Redmine Dedup] Suppressed duplicate alert (${existing.count}x) for ${targetDevice} - Rule ${ruleId || desc} (Ticket #${existing.issueId} opened ${minsAgo}m ago)`);
      return {
        ok: true,
        skipped: true,
        reason: `Duplicate suppressed (Existing Issue #${existing.issueId} opened ${minsAgo}m ago)`,
        existingIssueId: existing.issueId,
      };
    }
  }

  // Map Wazuh severity to Redmine priority
  let defaultPriority = 3; // High
  if (level >= 14) defaultPriority = 5; // Immediate
  else if (level >= 12) defaultPriority = 4; // Urgent
  else if (level >= 7)  defaultPriority = 3; // High
  else if (level >= 4)  defaultPriority = 2; // Normal
  else defaultPriority = 1; // Low

  const priorityId = options.priorityId ? parseInt(options.priorityId, 10) : defaultPriority;
  const defaultSubject = `[L${level}] ${desc} on ${targetDevice}${filePath ? ` (${filePath})` : ''}`.slice(0, 255);
  const subject = (options.customSubject || defaultSubject).slice(0, 255);

  const notesSection = options.customNotes ? [
    `h3. 📝 SOC Analyst Investigation Notes`,
    options.customNotes,
    ``,
  ] : [];

  const isManual = !!options.isManual;
  const triggerLabel = isManual ? `Manual Dispatch by SOC Analyst (${options.userName || 'Analyst'})` : `Automatic Detection Pipeline`;

  const descriptionBody = [
    `h2. Security Incident Report (Aegis SOC Middleware)`,
    ``,
    `* *Trigger Mode:* ${triggerLabel}`,
    `* *Rule ID:* ${ruleId || 'N/A'}`,
    `* *Rule Description:* ${desc}`,
    `* *Severity Level:* Level ${level}`,
    `* *Device / Agent:* ${targetDevice}`,
    ...(filePath ? [`* *Target File / Path:* ${filePath}`] : []),
    `* *MITRE ATT&CK:* ${mitre}`,
    `* *Source IP:* ${srcip}`,
    `* *Destination IP:* ${dstip}`,
    `* *Timestamp:* ${alert?.timestamp || alert?.receivedAt || new Date().toISOString()}`,
    ``,
    ...notesSection,
    `h3. Full Alert Payload`,
    `<pre>`,
    fullLog,
    `</pre>`,
    ``,
    `_Dispatched via Aegis SOC Middleware._`
  ].join('\n');

  const payload = {
    issue: {
      project_id: project,
      tracker_id: tracker,
      priority_id: priorityId,
      subject,
      description: descriptionBody,
    },
  };

  try {
    const res = await _request('issues.json', {
      method: 'POST',
      baseUrl,
      apiKey,
      body: payload,
    });

    const issue = res.data?.issue;
    const issueId = issue?.id;
    const issueUrl = `${baseUrl.replace(/\/+$/, '')}/issues/${issueId}`;

    // Record in deduplication cache
    _dedupCache.set(fingerprint, {
      timestamp: Date.now(),
      issueId,
      count: 1,
      lastSubject: subject,
    });

    // Log to Audit Log
    await logAudit({
      user: options.userName || (isManual ? 'analyst-manual' : 'aegis-auto-ticketer'),
      action: isManual ? 'redmine_manual_dispatch' : 'redmine_issue_created',
      filename: `Redmine Issue #${issueId}`,
      before: `Alert L${level} (${ruleId || desc}): Device ${targetDevice}`,
      after: `Created Issue #${issueId}: ${subject}\nURL: ${issueUrl}`,
    }).catch(() => {});

    console.log(`[Redmine] ${isManual ? 'Manually' : 'Auto'} created Issue #${issueId} for ${targetDevice} (${subject})`);

    return {
      ok: true,
      issueId,
      issueUrl,
      subject,
    };
  } catch (err) {
    console.error('[Redmine] Failed to create issue:', err.message);
    return { ok: false, error: err.message };
  }
}

/**
 * 2b. Batch Dispatch Multiple Alerts into a Single Redmine Issue
 */
async function createBatchIssueFromAlerts(alerts = [], options = {}, config = {}) {
  const baseUrl = config.redmineUrl;
  const apiKey  = config.redmineApiKey;
  const project = config.redmineProject;
  const tracker = config.redmineTrackerId || 1;

  if (!baseUrl || !apiKey || !project) {
    return { ok: false, error: 'Redmine is not configured' };
  }
  if (!Array.isArray(alerts) || alerts.length === 0) {
    return { ok: false, error: 'No alerts provided for batch ticket' };
  }

  const highestLevel = Math.max(...alerts.map(a => parseInt(a?.rule?.level ?? 0, 10)));
  const deviceSet = new Set(alerts.map(a => a?.agent?.name || a?.data?.devname || 'device'));
  const deviceList = Array.from(deviceSet).slice(0, 3).join(', ') + (deviceSet.size > 3 ? ` (+${deviceSet.size - 3} more)` : '');

  let defaultPriority = 3;
  if (highestLevel >= 14) defaultPriority = 5;
  else if (highestLevel >= 12) defaultPriority = 4;
  else if (highestLevel >= 7)  defaultPriority = 3;
  else if (highestLevel >= 4)  defaultPriority = 2;
  else defaultPriority = 1;

  const priorityId = options.priorityId ? parseInt(options.priorityId, 10) : defaultPriority;
  const defaultSubject = `[Batch SOC] ${alerts.length} Incidents (Max L${highestLevel}) on ${deviceList}`;
  const subject = (options.customSubject || defaultSubject).slice(0, 255);

  const notesSection = options.customNotes ? [
    `h3. 📝 SOC Analyst Investigation Notes`,
    options.customNotes,
    ``,
  ] : [];

  const rows = alerts.map((a, idx) => {
    const lvl = a?.rule?.level || 0;
    const desc = a?.rule?.description || 'N/A';
    const rid = a?.rule?.id || '-';
    const host = a?.agent?.name || a?.data?.devname || '-';
    const ts = a?.timestamp || a?.receivedAt || '-';
    return `| ${idx + 1} | Level ${lvl} | ${rid} | ${desc} | ${host} | ${ts} |`;
  }).join('\n');

  const descriptionBody = [
    `h2. Batch Security Incidents Consolidated Report (Aegis SOC)`,
    ``,
    `* *Total Consolidated Alerts:* ${alerts.length}`,
    `* *Highest Severity:* Level ${highestLevel}`,
    `* *Affected Endpoints:* ${Array.from(deviceSet).join(', ')}`,
    `* *Dispatched By:* ${options.userName || 'SOC Analyst'}`,
    `* *Dispatch Time:* ${new Date().toISOString()}`,
    ``,
    ...notesSection,
    `h3. 📋 Incident Event Breakdown`,
    `| # | Level | Rule ID | Description | Host | Timestamp |`,
    rows,
    ``,
    `h3. Consolidated Raw Payloads`,
    `<pre>`,
    JSON.stringify(alerts.map(a => ({ id: a.id, rule: a.rule, agent: a.agent, data: a.data, timestamp: a.timestamp })), null, 2),
    `</pre>`,
    ``,
    `_Consolidated Batch Dispatch generated via Aegis SOC Middleware._`
  ].join('\n');

  const payload = {
    issue: {
      project_id: project,
      tracker_id: tracker,
      priority_id: priorityId,
      subject,
      description: descriptionBody,
    },
  };

  try {
    const res = await _request('issues.json', {
      method: 'POST',
      baseUrl,
      apiKey,
      body: payload,
    });

    const issue = res.data?.issue;
    const issueId = issue?.id;
    const issueUrl = `${baseUrl.replace(/\/+$/, '')}/issues/${issueId}`;

    await logAudit({
      user: options.userName || 'analyst-manual-batch',
      action: 'redmine_batch_dispatch',
      filename: `Redmine Issue #${issueId}`,
      before: `Batch selected ${alerts.length} alerts (Max Level ${highestLevel})`,
      after: `Created Batch Issue #${issueId}: ${subject}\nURL: ${issueUrl}`,
    }).catch(() => {});

    console.log(`[Redmine] Batch created Issue #${issueId} for ${alerts.length} alerts`);

    return {
      ok: true,
      issueId,
      issueUrl,
      subject,
      count: alerts.length,
    };
  } catch (err) {
    console.error('[Redmine] Failed to create batch issue:', err.message);
    return { ok: false, error: err.message };
  }
}

/**
 * 3. Sync Recent Resolved/Closed Issues from Redmine into Audit Log
 */
async function syncResolvedIssues(config = {}) {
  const baseUrl = config.redmineUrl;
  const apiKey  = config.redmineApiKey;
  const project = config.redmineProject;

  if (!baseUrl || !apiKey) {
    return { ok: false, error: 'Redmine is not configured' };
  }

  try {
    let query = 'issues.json?limit=25&sort=updated_on:desc';
    if (project) query += `&project_id=${encodeURIComponent(project)}`;

    const res = await _request(query, { baseUrl, apiKey });
    const issues = res.data?.issues || [];

    let syncedCount = 0;
    for (const is of issues) {
      const issueUrl = `${baseUrl.replace(/\/+$/, '')}/issues/${is.id}`;
      await logAudit({
        user: is.author?.name || 'redmine',
        action: 'redmine_fix_synced',
        filename: `Redmine Issue #${is.id}`,
        before: `Status: ${is.status?.name || 'Unknown'} (Priority: ${is.priority?.name || 'Normal'})`,
        after: `Subject: ${is.subject}\nUpdated: ${is.updated_on}\nURL: ${issueUrl}\nDescription:\n${is.description || ''}`,
      }).catch(() => {});
      syncedCount++;
    }

    return { ok: true, syncedCount, count: issues.length };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/**
 * Clear deduplication cache for a specific resolved issue (targetDevice, ruleId, targetFile)
 */
function clearDedupForIssue(targetDevice = '', ruleId = '', targetFile = '') {
  const dLow = String(targetDevice || '').toLowerCase();
  const rLow = String(ruleId || '').toLowerCase();
  const fLow = String(targetFile || '').toLowerCase();

  let clearedCount = 0;
  for (const [key] of _dedupCache) {
    const parts = key.split('::');
    const kRule = parts[0] || '';
    const kAgent = parts[1] || '';
    const kDev = parts[2] || '';
    const kFile = parts[3] || '';

    let match = true;
    if (rLow && kRule && !kRule.includes(rLow) && !rLow.includes(kRule)) match = false;
    if (dLow && (kAgent || kDev) && !dLow.includes(kAgent) && !kAgent.includes(dLow)) match = false;
    if (fLow && kFile && !fLow.includes(kFile) && !kFile.includes(fLow)) match = false;

    if (match) {
      _dedupCache.delete(key);
      clearedCount++;
      console.log(`[Redmine Dedup] Reset dedup key after issue resolution: ${key}`);
    }
  }
  return clearedCount;
}

/**
 * Clear all deduplication cache (useful for testing or manual reset)
 */
function clearDedupCache() {
  _dedupCache.clear();
}

module.exports = {
  testConnection,
  createIssueFromAlert,
  createBatchIssueFromAlerts,
  syncResolvedIssues,
  shouldTriggerTicket,
  clearDedupForIssue,
  clearDedupCache,
};
