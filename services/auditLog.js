'use strict';

/**
 * services/auditLog.js
 *
 * Audit Log — zero-dependency, append-only NDJSON persistence.
 * Each entry is a single JSON line written to audit.log.ndjson
 * in the project root.
 *
 * Schema per entry:
 *   {
 *     id        : string   — pseudo-UUID v4
 *     user      : string   — who performed the action
 *     action    : string   — what was done  (e.g. "config_update", "data_cleared")
 *     filename  : string   — resource name / file path (optional)
 *     before    : string   — previous value / state (optional)
 *     after     : string   — new value / state (optional)
 *     timestamp : string   — ISO-8601 UTC date
 *   }
 */

const fs   = require('fs');
const path = require('path');

/* ── Storage file ───────────────────────────────────────────── */
const AUDIT_FILE = path.join(__dirname, '..', 'audit.log.ndjson');

/* ── Lightweight pseudo-UUID (no crypto dep needed in older Node) */
function pseudoUUID() {
  const hex = () => Math.floor(Math.random() * 0x10000).toString(16).padStart(4, '0');
  return `${hex()}${hex()}-${hex()}-4${hex().slice(1)}-${((Math.random() * 4) | 8).toString(16)}${hex().slice(1)}-${hex()}${hex()}${hex()}`;
}

/**
 * Append one audit entry to the NDJSON log file.
 *
 * @param {{ user?: string, action: string, filename?: string, before?: string, after?: string }} entry
 * @returns {Promise<object>} The written entry (with id and timestamp filled in).
 */
async function logAudit(entry) {
  const record = {
    id:        pseudoUUID(),
    user:      entry.user      || 'system',
    action:    entry.action    || 'unknown',
    filename:  entry.filename  || '',
    before:    entry.before    || '',
    after:     entry.after     || '',
    timestamp: entry.timestamp || new Date().toISOString(),
  };

  const line = JSON.stringify(record) + '\n';

  await fs.promises.appendFile(AUDIT_FILE, line, 'utf8');
  return record;
}

/**
 * Read and optionally filter audit log entries.
 *
 * @param {{ limit?: number, user?: string, action?: string }} opts
 * @returns {Promise<object[]>} Array of entries, newest-first.
 */
async function getAuditLogs({ limit = 200, user = '', action = '' } = {}) {
  let raw;
  try {
    raw = await fs.promises.readFile(AUDIT_FILE, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return []; // file not yet created
    throw err;
  }

  let entries = raw
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      try { return JSON.parse(line); } catch (_) { return null; }
    })
    .filter(Boolean)
    .reverse(); // newest-first

  if (user)   entries = entries.filter((e) => e.user   === user);
  if (action) entries = entries.filter((e) => e.action === action);

  return entries.slice(0, Math.min(limit, 1000));
}

/**
 * Permanently remove all audit log entries.
 * Creates an empty file to signal intentional clearing.
 *
 * @returns {Promise<void>}
 */
async function clearAuditLogs() {
  await fs.promises.writeFile(AUDIT_FILE, '', 'utf8');
}

module.exports = { logAudit, getAuditLogs, clearAuditLogs };
