'use strict';

/**
 * services/resolvedHistory.js
 *
 * Dedicated, permanent storage for Resolved Vulnerability & Closed Issue History.
 * Stores exclusively closed/resolved security issues from Redmine.
 * Persists continuously to `resolved_history.json` until manually deleted by the user.
 */

const fs   = require('fs');
const path = require('path');
const { URL } = require('url');
const http  = require('http');
const https = require('https');

const HISTORY_FILE   = path.join(__dirname, '..', 'resolved_history.json');
const TOMBSTONE_FILE = path.join(__dirname, '..', 'resolved_tombstones.json');

/* ── Lightweight UUID ─────────────────────────────────────── */
function pseudoUUID() {
  const hex = () => Math.floor(Math.random() * 0x10000).toString(16).padStart(4, '0');
  return `${hex()}${hex()}-${hex()}-4${hex().slice(1)}-${((Math.random() * 4) | 8).toString(16)}${hex().slice(1)}-${hex()}${hex()}${hex()}`;
}

/* ── In-Memory Store & Tombstones ──────────────────────────── */
let _resolvedStore = [];
let _tombstones = new Set();

function _loadTombstones() {
  try {
    if (fs.existsSync(TOMBSTONE_FILE)) {
      const raw = fs.readFileSync(TOMBSTONE_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data)) {
        _tombstones = new Set(data.map(String));
      }
    }
  } catch (_) {}
}

function _saveTombstones() {
  try {
    fs.writeFileSync(TOMBSTONE_FILE, JSON.stringify(Array.from(_tombstones), null, 2), 'utf8');
  } catch (_) {}
}

function _loadStore() {
  try {
    if (fs.existsSync(HISTORY_FILE)) {
      const raw = fs.readFileSync(HISTORY_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data)) {
        _resolvedStore = data;
        return;
      }
    }
  } catch (err) {
    console.warn('[ResolvedHistory] Could not read resolved_history.json:', err.message);
  }
}

function _saveStore() {
  try {
    const tmp = HISTORY_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(_resolvedStore, null, 2), 'utf8');
    fs.renameSync(tmp, HISTORY_FILE);
  } catch (err) {
    console.warn('[ResolvedHistory] Could not save resolved_history.json:', err.message);
  }
}

_loadStore();
_loadTombstones();

/**
 * Add or update a resolved vulnerability record
 */
async function addResolvedRecord(entry) {
  _loadStore();

  const existingIdx = _resolvedStore.findIndex(r => (entry.issueId && r.issueId === entry.issueId) || (entry.id && r.id === entry.id));

  const record = {
    id: entry.id || (entry.issueId ? `res-issue-${entry.issueId}` : pseudoUUID()),
    issueId: entry.issueId || null,
    subject: entry.subject || 'Resolved Security Issue',
    status: entry.status || 'Closed',
    statusId: entry.statusId || 5,
    priority: entry.priority || 'Normal',
    closedBy: entry.closedBy || 'Security Team',
    closedAt: entry.closedAt || new Date().toISOString(),
    targetDevice: entry.targetDevice || 'Unknown Device',
    targetFile: entry.targetFile || '',
    ruleId: entry.ruleId || '',
    resolutionNotes: entry.resolutionNotes || entry.notes || '',
    issueUrl: entry.issueUrl || '',
    description: entry.description || '',
    syncedAt: new Date().toISOString(),
  };

  if (existingIdx >= 0) {
    const existing = _resolvedStore[existingIdx];
    const hasChanged = existing.subject !== record.subject ||
                       existing.status !== record.status ||
                       existing.closedAt !== record.closedAt ||
                       existing.priority !== record.priority ||
                       existing.closedBy !== record.closedBy ||
                       existing.description !== record.description ||
                       existing.resolutionNotes !== record.resolutionNotes;
    if (hasChanged) {
      _resolvedStore[existingIdx] = { ...existing, ...record, syncedAt: new Date().toISOString() };
      _saveStore();
    }
    return _resolvedStore[existingIdx];
  } else {
    _resolvedStore.unshift(record);
    _saveStore();
    return record;
  }
}

/**
 * Retrieve all resolved vulnerability history records
 */
async function getResolvedHistory({ search = '', limit = 500 } = {}) {
  _loadStore();

  let list = [..._resolvedStore];

  if (search) {
    const q = search.toLowerCase();
    list = list.filter(r => {
      const hay = `${r.subject} ${r.targetDevice} ${r.targetFile} ${r.closedBy} ${r.ruleId} ${r.resolutionNotes} ${r.issueId || ''}`.toLowerCase();
      return hay.includes(q);
    });
  }

  // Sort newest closedAt first
  list.sort((a, b) => new Date(b.closedAt || b.syncedAt).getTime() - new Date(a.closedAt || a.syncedAt).getTime());

  return list.slice(0, limit);
}

/**
 * Delete a single record by ID
 */
async function deleteResolvedRecord(id) {
  _loadStore();
  _loadTombstones();
  const idStr = String(id);
  _tombstones.add(idStr);
  const numMatch = idStr.match(/\d+/);
  if (numMatch) {
    _tombstones.add(numMatch[0]);
    _tombstones.add(`res-redmine-${numMatch[0]}`);
  }

  const target = _resolvedStore.find(r => r.id === id || String(r.issueId) === idStr);
  if (target) {
    if (target.id) _tombstones.add(String(target.id));
    if (target.issueId) _tombstones.add(String(target.issueId));
  }
  _saveTombstones();

  const beforeLen = _resolvedStore.length;
  _resolvedStore = _resolvedStore.filter(r => r.id !== id && String(r.issueId) !== idStr);
  if (_resolvedStore.length !== beforeLen) {
    _saveStore();
    return true;
  }
  return false;
}

/**
 * Delete multiple records by list of IDs
 */
async function deleteMultipleResolvedRecords(ids = []) {
  _loadStore();
  _loadTombstones();
  const idSet = new Set(ids.map(String));
  for (const id of ids) {
    const idStr = String(id);
    _tombstones.add(idStr);
    const numMatch = idStr.match(/\d+/);
    if (numMatch) {
      _tombstones.add(numMatch[0]);
      _tombstones.add(`res-redmine-${numMatch[0]}`);
    }
  }
  for (const r of _resolvedStore) {
    if (idSet.has(String(r.id)) || (r.issueId && idSet.has(String(r.issueId)))) {
      if (r.id) _tombstones.add(String(r.id));
      if (r.issueId) _tombstones.add(String(r.issueId));
    }
  }
  _saveTombstones();
  const beforeLen = _resolvedStore.length;
  _resolvedStore = _resolvedStore.filter(r => !idSet.has(String(r.id)) && !idSet.has(String(r.issueId)));
  const deletedCount = beforeLen - _resolvedStore.length;
  if (deletedCount > 0) {
    _saveStore();
  }
  return deletedCount;
}

/**
 * Clear all resolved history records
 */
async function clearResolvedHistory() {
  _loadStore();
  _loadTombstones();
  for (const r of _resolvedStore) {
    if (r.id) _tombstones.add(String(r.id));
    if (r.issueId) _tombstones.add(String(r.issueId));
  }
  _saveTombstones();
  _resolvedStore = [];
  _saveStore();
  return true;
}

/**
 * Helper to fetch from Redmine API
 */
function _redmineRequest(endpoint, { baseUrl, apiKey }) {
  return new Promise((resolve, reject) => {
    if (!baseUrl || !apiKey) return reject(new Error('Redmine configuration missing'));

    let fullUrl;
    try {
      fullUrl = new URL(endpoint, baseUrl.endsWith('/') ? baseUrl : baseUrl + '/');
      if (!fullUrl.searchParams.has('key')) fullUrl.searchParams.set('key', apiKey);
    } catch (e) {
      return reject(e);
    }

    const isHttps = fullUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    const req = client.request({
      method: 'GET',
      hostname: fullUrl.hostname,
      port: fullUrl.port || (isHttps ? 443 : 80),
      path: fullUrl.pathname + fullUrl.search,
      headers: {
        'X-Redmine-API-Key': apiKey,
        'Accept': 'application/json',
        'User-Agent': 'Aegis-SOC/1.0',
      },
      timeout: 10000,
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed);
          } else {
            reject(new Error(parsed?.errors ? parsed.errors.join(', ') : `HTTP ${res.statusCode}`));
          }
        } catch (e) {
          reject(new Error(`Failed to parse Redmine response: ${e.message}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Redmine request timed out')); });
    req.end();
  });
}

/**
 * Sync Closed/Resolved issues from Redmine into permanent resolved history
 * If purgeCallback is provided, calls purgeCallback(closedRecord) to remove active alerts and reset dedup.
 */
async function syncClosedIssuesFromRedmine(config = {}, purgeCallback = null) {
  const baseUrl = config.redmineUrl;
  const apiKey  = config.redmineApiKey;
  const project = config.redmineProject;

  if (!baseUrl || !apiKey) {
    return { ok: false, error: 'Redmine URL and API Key are required.' };
  }

  try {
    // Redmine status_id=closed fetches all closed/resolved status tickets
    let query = 'issues.json?status_id=closed&limit=100&sort=updated_on:desc';
    if (project) query += `&project_id=${encodeURIComponent(project)}`;

    const res = await _redmineRequest(query, { baseUrl, apiKey });
    const issues = res?.issues || [];

    _loadTombstones();
    let newSavedCount = 0;
    const closedList = [];

    for (const is of issues) {
      const issueIdStr = String(is.id);
      const recordIdStr = `res-redmine-${is.id}`;
      if (_tombstones.has(issueIdStr) || _tombstones.has(recordIdStr)) {
        // Explicitly deleted by user from History — do not re-insert or resurrect
        continue;
      }
      const issueUrl = `${baseUrl.replace(/\/+$/, '')}/issues/${is.id}`;

      // Extract device and file info from description or subject if present
      let targetDevice = 'Unknown Device';
      let targetFile = '';
      let ruleId = '';

      const desc = is.description || '';
      const devMatch = desc.match(/\*Device \/ Agent:\*\s*([^\n\r]+)/i) || is.subject.match(/on\s+([a-zA-Z0-9_.-]+)/i);
      if (devMatch) targetDevice = devMatch[1].trim();

      const fileMatch = desc.match(/\*Target File \/ Path:\*\s*([^\n\r]+)/i) || is.subject.match(/\(([^)]+\.[a-zA-Z0-9_-]+)\)/i);
      if (fileMatch) targetFile = fileMatch[1].trim();

      const ruleMatch = desc.match(/\*Rule ID:\*\s*([^\n\r]+)/i) || is.subject.match(/Rule\s*#?([0-9]+)/i);
      if (ruleMatch) ruleId = ruleMatch[1].trim();

      const closedRecord = {
        id: `res-redmine-${is.id}`,
        issueId: is.id,
        subject: is.subject,
        status: is.status?.name || 'Closed',
        statusId: is.status?.id || 5,
        priority: is.priority?.name || 'Normal',
        closedBy: is.assigned_to?.name || is.author?.name || 'Redmine User',
        closedAt: is.closed_on || is.updated_on || new Date().toISOString(),
        targetDevice,
        targetFile,
        ruleId,
        resolutionNotes: is.notes || desc.slice(0, 300),
        issueUrl,
        description: desc,
      };

      const isNewClosed = !_resolvedStore.some(r => r.issueId === is.id || r.id === `res-redmine-${is.id}`);

      await addResolvedRecord(closedRecord);
      closedList.push(closedRecord);
      if (isNewClosed) newSavedCount++;

      if (isNewClosed && typeof purgeCallback === 'function') {
        try {
          purgeCallback(closedRecord);
        } catch (e) {
          console.warn('[ResolvedHistory] Purge callback error:', e.message);
        }
      }
    }

    return {
      ok: true,
      syncedCount: newSavedCount,
      totalResolved: _resolvedStore.length,
      closedRecords: closedList,
    };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

module.exports = {
  addResolvedRecord,
  getResolvedHistory,
  deleteResolvedRecord,
  deleteMultipleResolvedRecords,
  clearResolvedHistory,
  syncClosedIssuesFromRedmine,
};
