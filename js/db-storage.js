/**
 * Aegis SOC — Database Storage Controller
 * Displays middleware data store usage, file sizes, and runtime info.
 */

'use strict';

const DbStorageController = (() => {
  let _loading = false;

  /* ── Category display metadata ──────────────────────────── */
  const CATEGORY_META = {
    critical_alerts:          { label: 'Critical Alerts',               color: '#f4576a' },
    blind_spots_agent_health: { label: 'Device Names',                  color: '#f97316' },
    critical_file_changes:    { label: 'Critical File & System Changes', color: '#f5b94d' },
    auth_access_anomalies:    { label: 'Access Anomalies',              color: '#22d3ee' },
    threat_intel_matches:     { label: 'Threat Intelligence Matches',   color: '#a78bfa' },
  };

  const FILE_META = {
    config:    { label: 'Config File',    icon: 'settings-2',      color: '#22d3ee' },
    auditLog:  { label: 'Audit Log',      icon: 'file-clock',      color: '#f5b94d' },
    serverLog: { label: 'Server Log',     icon: 'terminal-square', color: '#2dd4a7' },
    serverErr: { label: 'Error Log',      icon: 'bug',             color: '#f4576a' },
  };

  /* ── Helpers ─────────────────────────────────────────────── */
  function _fmtBytes(bytes) {
    if (bytes === 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
    return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
  }

  function _fmtUptime(sec) {
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  function _fmtDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return '—';
    return d.toLocaleString('th-TH', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  }

  function _setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  /* ── Render helpers ──────────────────────────────────────── */
  function _renderKpis(data) {
    _setText('db-kpi-store-size',     _fmtBytes(data.store?.fileSize ?? 0));
    _setText('db-kpi-total-records',  (data.store?.totalRecords ?? 0).toLocaleString());
    _setText('db-kpi-mem',            _fmtBytes(data.runtime?.memUsed ?? 0));
    _setText('db-kpi-uptime',         _fmtUptime(data.runtime?.uptime ?? 0));
  }

  function _renderCategoryBars(categories) {
    const container = document.getElementById('db-category-bars');
    if (!container) return;

    const totalRecords = Object.values(categories).reduce((s, c) => s + c.count, 0);
    const totalBytes   = Object.values(categories).reduce((s, c) => s + c.estimatedBytes, 0);

    if (totalRecords === 0) {
      container.innerHTML = `<div class="db-empty-state"><i data-lucide="inbox"></i><span>No records stored</span></div>`;
      if (typeof lucide !== 'undefined') lucide.createIcons();
      return;
    }

    container.innerHTML = Object.entries(categories).map(([key, cat]) => {
      const meta = CATEGORY_META[key] || { label: key, color: '#94a3b8' };
      const pctCount = totalRecords > 0 ? ((cat.count / totalRecords) * 100).toFixed(1) : 0;
      const pctBytes = totalBytes  > 0 ? ((cat.estimatedBytes / totalBytes) * 100).toFixed(1) : 0;
      return `
        <div class="db-bar-row">
          <div class="db-bar-label-row">
            <span class="db-bar-dot" style="background:${meta.color};"></span>
            <span class="db-bar-name">${meta.label}</span>
            <span class="db-bar-count">${cat.count.toLocaleString()} records</span>
            <span class="db-bar-size">${_fmtBytes(cat.estimatedBytes)}</span>
          </div>
          <div class="db-bar-track">
            <div class="db-bar-fill" style="width:${pctCount}%; background:${meta.color};" title="${pctCount}%"></div>
          </div>
          <div class="db-bar-pct">${pctCount}%</div>
        </div>
      `;
    }).join('');

    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  function _renderFileList(files) {
    const container = document.getElementById('db-file-list');
    if (!container) return;

    container.innerHTML = Object.entries(files).map(([key, file]) => {
      const meta = FILE_META[key] || { label: key, icon: 'file', color: '#94a3b8' };
      const sizeStr = file.exists ? _fmtBytes(file.size) : 'Not found';
      const modStr  = file.exists && file.mtime ? _fmtDate(file.mtime) : '—';
      const statusClass = file.exists ? (file.size > 0 ? 'db-file-ok' : 'db-file-empty') : 'db-file-missing';
      return `
        <div class="db-file-row ${statusClass}">
          <div class="db-file-icon" style="color:${meta.color};"><i data-lucide="${meta.icon}"></i></div>
          <div class="db-file-info">
            <span class="db-file-label">${meta.label}</span>
            <span class="db-file-mtime">${modStr}</span>
          </div>
          <div class="db-file-size">${sizeStr}</div>
        </div>
      `;
    }).join('');

    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  function _renderTimeline(data) {
    _setText('db-oldest-ts', _fmtDate(data.store?.oldestRecord));
    _setText('db-newest-ts', _fmtDate(data.store?.newestRecord));

    const pathEl = document.getElementById('db-store-path');
    if (pathEl) pathEl.textContent = data.store?.path ?? '—';

    // Animated gradient bar
    const bar = document.getElementById('db-timeline-bar');
    if (bar) {
      const hasData = data.store?.oldestRecord && data.store?.newestRecord;
      bar.style.opacity = hasData ? '1' : '0.3';
    }
  }

  function _renderRuntime(runtime) {
    const container = document.getElementById('db-runtime-grid');
    if (!container) return;

    const items = [
      { label: 'Node.js Version', value: runtime?.nodeVersion ?? '—',          icon: 'code-2' },
      { label: 'Platform',        value: runtime?.platform ?? '—',              icon: 'monitor' },
      { label: 'Process ID',      value: runtime?.pid?.toString() ?? '—',       icon: 'activity' },
      { label: 'Uptime',          value: _fmtUptime(runtime?.uptime ?? 0),      icon: 'timer' },
      { label: 'Memory (RSS)',     value: _fmtBytes(runtime?.memUsed ?? 0),      icon: 'memory-stick' },
    ];

    container.innerHTML = items.map(item => `
      <div class="db-runtime-item">
        <div class="db-runtime-icon"><i data-lucide="${item.icon}"></i></div>
        <div class="db-runtime-info">
          <span class="db-runtime-label">${item.label}</span>
          <span class="db-runtime-value">${item.value}</span>
        </div>
      </div>
    `).join('');

    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  function _renderLastUpdated(iso) {
    const el = document.getElementById('db-last-updated');
    if (!el) return;
    const d = new Date(iso);
    el.textContent = `Updated: ${d.toLocaleTimeString('th-TH')}`;
  }

  /* ── Main load ───────────────────────────────────────────── */
  async function load() {
    if (_loading) return;
    _loading = true;

    const btn = document.getElementById('db-refresh-btn');
    if (btn) btn.classList.add('spinning');

    try {
      const res  = await fetch('/api/db-stats');
      const data = await res.json();

      if (!data.ok) throw new Error('API returned error');

      _renderKpis(data);
      _renderCategoryBars(data.store?.categories ?? {});
      _renderFileList(data.files ?? {});
      _renderTimeline(data);
      _renderRuntime(data.runtime);
      _renderLastUpdated(data.generatedAt);

    } catch (err) {
      console.error('[DbStorage] Failed to load stats:', err);
    } finally {
      _loading = false;
      if (btn) btn.classList.remove('spinning');
    }
  }

  function init() {
    const btn = document.getElementById('db-refresh-btn');
    if (btn) btn.addEventListener('click', load);
  }

  return { init, load };
})();

window.DbStorageController = DbStorageController;
