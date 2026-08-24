/**
 * Aegis SOC — File Edit History Controller
 * Displays audit trail of file changes from /api/audit-logs.
 * Features: search, filter by action, diff viewer modal, stats.
 */

'use strict';

const FileHistoryController = (() => {

  /* ── Action badge metadata ───────────────────────────────── */
  const ACTION_META = {
    rule_created:          { label: 'Created',       cls: 'fh-badge--created',     icon: 'file-plus-2' },
    rule_updated:          { label: 'Updated',       cls: 'fh-badge--updated',     icon: 'file-pen-line' },
    rule_deleted:          { label: 'Deleted',       cls: 'fh-badge--deleted',     icon: 'file-x-2' },
    redmine_issue_created: { label: 'Redmine Issue', cls: 'fh-badge--redmine',     icon: 'ticket' },
    redmine_fix_synced:    { label: 'Redmine Fix',   cls: 'fh-badge--redmine-fix', icon: 'check-circle-2' },
    config_update:         { label: 'Config',        cls: 'fh-badge--config',      icon: 'settings-2' },
    data_cleared:          { label: 'Cleared',       cls: 'fh-badge--cleared',     icon: 'trash-2' },
    audit_logs_cleared:    { label: 'Audit Cleared', cls: 'fh-badge--cleared',     icon: 'eraser' },
  };

  const FILE_ACTIONS = new Set(['rule_created', 'rule_updated', 'rule_deleted', 'config_update', 'redmine_issue_created', 'redmine_fix_synced']);

  let _allLogs = [];
  let _loading = false;
  let _searchVal = '';
  let _actionFilter = '';

  /* ── Helpers ─────────────────────────────────────────────── */
  function _esc(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function _extractUrl(text) {
    if (!text) return null;
    const match = text.match(/https?:\/\/[^\s\n\r"']+/);
    return match ? match[0] : null;
  }

  function _fmtDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toLocaleString('th-TH', {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  }

  function _relTime(iso) {
    if (!iso) return '';
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 60000)     return 'just now';
    if (diff < 3600000)   return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000)  return `${Math.floor(diff / 3600000)}h ago`;
    return `${Math.floor(diff / 86400000)}d ago`;
  }

  function _setText(id, v) {
    const el = document.getElementById(id);
    if (el) el.textContent = v;
  }

  /* ── Stats ───────────────────────────────────────────────── */
  function _renderStats(logs) {
    const counts = { created: 0, updated: 0, deleted: 0, other: 0 };
    for (const l of logs) {
      if (l.action === 'rule_created' || l.action === 'redmine_issue_created')  counts.created++;
      else if (l.action === 'rule_updated' || l.action === 'config_update' || l.action === 'redmine_fix_synced') counts.updated++;
      else if (l.action === 'rule_deleted') counts.deleted++;
      else counts.other++;
    }
    _setText('fh-stat-total',   logs.length.toLocaleString());
    _setText('fh-stat-created', counts.created.toLocaleString());
    _setText('fh-stat-updated', counts.updated.toLocaleString());
    _setText('fh-stat-deleted', counts.deleted.toLocaleString());
    _setText('fh-stat-other',   counts.other.toLocaleString());
  }

  /* ── Row rendering ───────────────────────────────────────── */
  function _getFiltered() {
    const q = _searchVal.toLowerCase();
    return _allLogs.filter(l => {
      if (_actionFilter && l.action !== _actionFilter) return false;
      if (q) {
        const hay = `${l.filename} ${l.user} ${l.action} ${l.before} ${l.after}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }

  function _truncate(str, max = 60) {
    if (!str) return '—';
    const s = str.replace(/\s+/g, ' ').trim();
    return s.length > max ? s.slice(0, max) + '…' : s;
  }

  function _renderTable(logs) {
    const tbody = document.getElementById('fh-table-body');
    const empty  = document.getElementById('fh-empty');
    const rowCnt = document.getElementById('fh-row-count');

    if (!tbody) return;

    if (rowCnt) rowCnt.textContent = `${logs.length.toLocaleString()} ${logs.length === 1 ? 'entry' : 'entries'}`;

    if (logs.length === 0) {
      tbody.innerHTML = '';
      if (empty) empty.style.display = 'flex';
      return;
    }
    if (empty) empty.style.display = 'none';

    const hasDiff = (l) => (l.before && l.before !== '(new file)') || (l.after && l.after !== '(deleted)');

    tbody.innerHTML = logs.map((l, idx) => {
      const meta  = ACTION_META[l.action] || { label: l.action, cls: 'fh-badge--other', icon: 'activity' };
      const fname = l.filename || '—';
      const detail = _truncate(l.after || l.before, 64);
      const rel   = _relTime(l.timestamp);
      const showBtn = hasDiff(l);
      const url = _extractUrl(l.after) || _extractUrl(l.before);

      return `
        <tr class="fh-tr" data-idx="${idx}">
          <td class="fh-td fh-td--ts">
            <span class="fh-ts-main">${_fmtDate(l.timestamp)}</span>
            <span class="fh-ts-rel">${rel}</span>
          </td>
          <td class="fh-td fh-td--action">
            <span class="fh-badge ${meta.cls}">
              <i data-lucide="${meta.icon}"></i>
              ${_esc(meta.label)}
            </span>
          </td>
          <td class="fh-td fh-td--file">
            <span class="fh-file-chip" title="${_esc(fname)}">
              <i data-lucide="${l.action.startsWith('redmine') ? 'ticket' : 'file-code-2'}"></i>
              ${_esc(fname)}
            </span>
            ${url ? `<a href="${_esc(url)}" target="_blank" rel="noopener" class="fh-ext-link" title="Open in Redmine" onclick="event.stopPropagation();"><i data-lucide="external-link"></i></a>` : ''}
          </td>
          <td class="fh-td fh-td--user">
            <span class="fh-user-chip">
              <i data-lucide="user-round"></i>
              ${_esc(l.user || '—')}
            </span>
          </td>
          <td class="fh-td fh-td--detail">
            <span class="fh-detail-text" title="${_esc(l.after || l.before || '')}">${_esc(detail)}</span>
          </td>
          <td class="fh-td fh-td--expand">
            ${showBtn ? `<button class="fh-expand-btn" data-idx="${idx}" title="View diff" aria-label="View change details"><i data-lucide="eye"></i></button>` : ''}
          </td>
        </tr>
      `;
    }).join('');

    if (typeof lucide !== 'undefined') lucide.createIcons();

    // Wire expand buttons
    tbody.querySelectorAll('.fh-expand-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const idx = parseInt(btn.getAttribute('data-idx'), 10);
        const filtered = _getFiltered();
        if (filtered[idx]) _openDiff(filtered[idx]);
      });
    });

    // Also row click to expand
    tbody.querySelectorAll('.fh-tr').forEach(tr => {
      tr.addEventListener('click', () => {
        const idx = parseInt(tr.getAttribute('data-idx'), 10);
        const filtered = _getFiltered();
        if (filtered[idx] && (filtered[idx].before || filtered[idx].after)) {
          _openDiff(filtered[idx]);
        }
      });
    });
  }

  /* ── Diff Modal ──────────────────────────────────────────── */
  function _openDiff(entry) {
    const modal    = document.getElementById('fh-diff-modal');
    const fileEl   = document.getElementById('fh-diff-filename');
    const metaEl   = document.getElementById('fh-diff-meta');
    const beforeEl = document.getElementById('fh-diff-before');
    const afterEl  = document.getElementById('fh-diff-after');

    if (!modal) return;

    const url = _extractUrl(entry.after) || _extractUrl(entry.before);
    let titleHtml = _esc(entry.filename || 'Change Details');
    if (url) {
      titleHtml += ` <a href="${_esc(url)}" target="_blank" rel="noopener" class="fh-modal-ext-btn"><i data-lucide="external-link"></i> Open in Redmine</a>`;
    }

    if (fileEl) fileEl.innerHTML = titleHtml;
    if (metaEl) metaEl.textContent = `${entry.action} · ${_fmtDate(entry.timestamp)} · by ${entry.user}`;
    if (beforeEl) beforeEl.textContent = entry.before || '(empty)';
    if (afterEl)  afterEl.textContent  = entry.after  || '(empty)';

    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  function _closeDiff() {
    const modal = document.getElementById('fh-diff-modal');
    if (modal) modal.style.display = 'none';
    document.body.style.overflow = '';
  }

  /* ── Main load ───────────────────────────────────────────── */
  async function load() {
    if (_loading) return;
    _loading = true;

    const btn     = document.getElementById('fh-refresh-btn');
    const loading = document.getElementById('fh-loading');
    const empty   = document.getElementById('fh-empty');
    const tbody   = document.getElementById('fh-table-body');

    if (btn)     btn.classList.add('spinning');
    if (loading) { loading.style.display = 'flex'; }
    if (empty)   empty.style.display = 'none';
    if (tbody)   tbody.innerHTML = '';

    const limit  = document.getElementById('fh-filter-limit')?.value || '200';
    const action = document.getElementById('fh-filter-action')?.value || '';

    try {
      const params = new URLSearchParams({ limit });
      if (action) params.set('action', action);

      const res  = await fetch(`/api/audit-logs?${params}`);
      const data = await res.json();

      if (!data.ok) throw new Error('API error');

      _allLogs = data.logs || [];
      _renderStats(_allLogs);
      const filtered = _getFiltered();
      _renderTable(filtered);

      const lu = document.getElementById('fh-last-updated');
      if (lu) lu.textContent = `Updated: ${new Date().toLocaleTimeString('th-TH')}`;

    } catch (err) {
      console.error('[FileHistory] load failed:', err);
      if (empty) { empty.style.display = 'flex'; empty.querySelector('span').textContent = 'Failed to load history'; }
    } finally {
      _loading = false;
      if (btn)     btn.classList.remove('spinning');
      if (loading) loading.style.display = 'none';
    }
  }

  /* ── Clear all history ───────────────────────────────────── */
  async function _clearHistory() {
    if (!confirm('Clear all audit history? This cannot be undone.')) return;
    try {
      const res = await fetch('/api/audit-logs', { method: 'DELETE' });
      const d   = await res.json();
      if (d.ok) {
        _allLogs = [];
        _renderStats([]);
        _renderTable([]);
        const lu = document.getElementById('fh-last-updated');
        if (lu) lu.textContent = 'Cleared';
      }
    } catch (e) {
      alert('Failed to clear history: ' + e.message);
    }
  }

  /* ── Search + filter debounce ────────────────────────────── */
  let _debounce = null;
  function _onSearch(val) {
    _searchVal = val;
    clearTimeout(_debounce);
    _debounce = setTimeout(() => _renderTable(_getFiltered()), 200);
  }

  /* ── Init ────────────────────────────────────────────────── */
  function init() {
    // Refresh button
    document.getElementById('fh-refresh-btn')?.addEventListener('click', load);

    // Search
    document.getElementById('fh-search')?.addEventListener('input', (e) => _onSearch(e.target.value));

    // Action filter dropdown
    document.getElementById('fh-filter-action')?.addEventListener('change', (e) => {
      _actionFilter = e.target.value;
      _renderTable(_getFiltered());
    });

    // Limit filter
    document.getElementById('fh-filter-limit')?.addEventListener('change', () => load());

    // Clear button
    document.getElementById('fh-clear-btn')?.addEventListener('click', _clearHistory);

    // Diff modal close
    document.getElementById('fh-diff-close')?.addEventListener('click', _closeDiff);
    document.getElementById('fh-diff-backdrop')?.addEventListener('click', _closeDiff);

    // Escape closes modal
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        const modal = document.getElementById('fh-diff-modal');
        if (modal && modal.style.display !== 'none') _closeDiff();
      }
    });
  }

  return { init, load };
})();

window.FileHistoryController = FileHistoryController;
