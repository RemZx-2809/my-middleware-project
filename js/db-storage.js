/**
 * Aegis SOC — Database Storage & Cleanup Controller
 * Displays middleware data store usage, file sizes, runtime info,
 * and provides full storage management (quick cleaning, custom pruning,
 * 30-day/monthly filters, category selection, and log truncation).
 */

'use strict';

const DbStorageController = (() => {
  let _loading = false;
  let _currentStats = null;
  let _activeDays = 30; // 7, 30, 90, 180, 'custom', 'all'
  let _pendingCleanupPayload = null;

  /* ── Category display metadata ──────────────────────────── */
  const CATEGORY_META = {
    critical_alerts:          { label: 'Critical Alerts',                color: '#f4576a' },
    blind_spots_agent_health: { label: 'Device Names',                   color: '#f97316' },
    critical_file_changes:    { label: 'Critical File & System Changes', color: '#f5b94d' },
    auth_access_anomalies:    { label: 'Access Anomalies',               color: '#22d3ee' },
    threat_intel_matches:     { label: 'Threat Intelligence Matches',    color: '#a78bfa' },
  };

  const FILE_META = {
    config:    { label: 'Config File',    icon: 'settings-2',      color: '#22d3ee', canClean: false },
    auditLog:  { label: 'Audit Log',      icon: 'file-clock',      color: '#f5b94d', canClean: true, logKey: 'auditLog' },
    serverLog: { label: 'Server Log',     icon: 'terminal-square', color: '#2dd4a7', canClean: true, logKey: 'serverLog' },
    serverErr: { label: 'Error Log',      icon: 'bug',             color: '#f4576a', canClean: true, logKey: 'serverErr' },
  };

  /* ── Helpers ─────────────────────────────────────────────── */
  function _fmtBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
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

  function _showToast(type, title, body) {
    if (typeof Toast !== 'undefined' && Toast.show) {
      Toast.show({ type, title, body, duration: 4500 });
    } else {
      console.log(`[Toast] [${type}] ${title}: ${body}`);
    }
  }

  /* ── Render helpers ──────────────────────────────────────── */
  function _renderKpis(data) {
    _setText('db-kpi-store-size',    _fmtBytes(data.store?.fileSize ?? 0));
    _setText('db-kpi-total-records', (data.store?.totalRecords ?? 0).toLocaleString());
    _setText('db-kpi-mem',           _fmtBytes(data.runtime?.memUsed ?? 0));
    _setText('db-kpi-uptime',        _fmtUptime(data.runtime?.uptime ?? 0));
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
      return `
        <div class="db-bar-row">
          <div class="db-bar-label-row">
            <span class="db-bar-dot" style="background:${meta.color};"></span>
            <span class="db-bar-name">${meta.label}</span>
            <span class="db-bar-count">${cat.count.toLocaleString()} records</span>
            <span class="db-bar-size">${_fmtBytes(cat.estimatedBytes)}</span>
            <button class="db-cat-clean-btn" data-cat="${key}" title="Clean ${meta.label}">
              <i data-lucide="trash-2"></i>
            </button>
          </div>
          <div class="db-bar-track">
            <div class="db-bar-fill" style="width:${pctCount}%; background:${meta.color};" title="${pctCount}%"></div>
          </div>
          <div class="db-bar-pct">${pctCount}%</div>
        </div>
      `;
    }).join('');

    // Attach individual category clean buttons
    container.querySelectorAll('.db-cat-clean-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const catKey = btn.getAttribute('data-cat');
        _openQuickCleanForCategory(catKey);
      });
    });

    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  function _renderFileList(files) {
    const container = document.getElementById('db-file-list');
    if (!container) return;

    let totalLogBytes = 0;
    if (files.serverLog?.exists) totalLogBytes += (files.serverLog.size || 0);
    if (files.serverErr?.exists) totalLogBytes += (files.serverErr.size || 0);
    _setText('badge-size-logs', _fmtBytes(totalLogBytes));

    container.innerHTML = Object.entries(files).map(([key, file]) => {
      const meta = FILE_META[key] || { label: key, icon: 'file', color: '#94a3b8', canClean: false };
      const sizeStr = file.exists ? _fmtBytes(file.size) : 'Not found';
      const modStr  = file.exists && file.mtime ? _fmtDate(file.mtime) : '—';
      const statusClass = file.exists ? (file.size > 0 ? 'db-file-ok' : 'db-file-empty') : 'db-file-missing';
      const cleanBtnHtml = (meta.canClean && file.exists && file.size > 0)
        ? `<button class="db-file-purge-btn" data-log="${meta.logKey}" title="Clear ${meta.label}">
             <i data-lucide="eraser"></i>
           </button>`
        : '';

      return `
        <div class="db-file-row ${statusClass}">
          <div class="db-file-icon" style="color:${meta.color};"><i data-lucide="${meta.icon}"></i></div>
          <div class="db-file-info">
            <span class="db-file-label">${meta.label}</span>
            <span class="db-file-mtime">${modStr}</span>
          </div>
          <div class="db-file-size">${sizeStr}</div>
          ${cleanBtnHtml}
        </div>
      `;
    }).join('');

    container.querySelectorAll('.db-file-purge-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const logKey = btn.getAttribute('data-log');
        _openQuickCleanForLog(logKey);
      });
    });

    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  function _renderTimeline(data) {
    _setText('db-oldest-ts', _fmtDate(data.store?.oldestRecord));
    _setText('db-newest-ts', _fmtDate(data.store?.newestRecord));

    const ingestSinceEl = document.getElementById('db-ingest-since-display');
    if (ingestSinceEl) {
      const isAuto = !data.ingestSince || data.ingestSince === 'auto';
      const dateStr = _fmtDate(data.effectiveIngestSince || data.ingestSince);
      ingestSinceEl.textContent = isAuto ? `${dateStr} (เริ่มนับจากเวลาเปิดระบบใช้งาน)` : `${dateStr} เป็นต้นไป`;
    }

    const pathEl = document.getElementById('db-store-path');
    if (pathEl) pathEl.textContent = data.store?.path ?? '—';

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
      { label: 'Node.js Version', value: runtime?.nodeVersion ?? '—',     icon: 'code-2' },
      { label: 'Platform',        value: runtime?.platform ?? '—',         icon: 'monitor' },
      { label: 'Process ID',      value: runtime?.pid?.toString() ?? '—',  icon: 'activity' },
      { label: 'Uptime',          value: _fmtUptime(runtime?.uptime ?? 0), icon: 'timer' },
      { label: 'Memory (RSS)',    value: _fmtBytes(runtime?.memUsed ?? 0), icon: 'memory-stick' },
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

  /* ── Quick Clean Pre-Calculations ────────────────────────── */
  async function _updateQuickPresetBadges() {
    try {
      // 30 days
      const r30 = await _calcDryRun({ olderThanDays: 30, categories: 'all' });
      _setText('badge-count-30d', `${r30.deletedCount.toLocaleString()} records (~${_fmtBytes(r30.bytesFreedEst)})`);

      // 7 days
      const r7 = await _calcDryRun({ olderThanDays: 7, categories: 'all' });
      _setText('badge-count-7d', `${r7.deletedCount.toLocaleString()} records (~${_fmtBytes(r7.bytesFreedEst)})`);

      // 90 days
      const r90 = await _calcDryRun({ olderThanDays: 90, categories: 'all' });
      _setText('badge-count-90d', `${r90.deletedCount.toLocaleString()} records (~${_fmtBytes(r90.bytesFreedEst)})`);
    } catch (_) {}
  }

  /* ── API Dry Run & Execution ─────────────────────────────── */
  async function _calcDryRun(payload) {
    const res = await fetch('/api/db/clean', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...payload, dryRun: true }),
    });
    return await res.json();
  }

  async function _executeClean(payload) {
    const res = await fetch('/api/db/clean', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...payload, dryRun: false }),
    });
    return await res.json();
  }

  /* ── Form Payload Extractor ──────────────────────────────── */
  function _getCustomFormPayload() {
    const payload = {};

    // 1. Time Horizon
    if (_activeDays === 'all') {
      payload.clearAll = true;
    } else if (_activeDays === 'custom') {
      const dateInput = document.getElementById('db-custom-date-input');
      if (dateInput && dateInput.value) {
        payload.beforeDate = new Date(dateInput.value).toISOString();
      } else {
        payload.olderThanDays = 30; // fallback
      }
    } else if (typeof _activeDays === 'number') {
      payload.olderThanDays = _activeDays;
    }

    // 2. Categories
    const catCheckboxes = document.querySelectorAll('#db-category-checkboxes input[name="db_cat"]:checked');
    const allCatCheckboxes = document.querySelectorAll('#db-category-checkboxes input[name="db_cat"]');
    if (catCheckboxes.length === allCatCheckboxes.length) {
      payload.categories = 'all';
    } else {
      payload.categories = Array.from(catCheckboxes).map(cb => cb.value);
    }

    // 3. Logs
    const logCheckboxes = document.querySelectorAll('input[name="db_log"]:checked');
    payload.cleanLogs = Array.from(logCheckboxes).map(cb => cb.value);

    return payload;
  }

  /* ── Live Impact Preview Calculator ──────────────────────── */
  async function _recalculateImpact() {
    const previewPrimary = document.getElementById('db-impact-primary');
    const previewSecondary = document.getElementById('db-impact-secondary');
    if (previewPrimary) previewPrimary.textContent = 'Calculating…';

    try {
      const payload = _getCustomFormPayload();
      const data = await _calcDryRun(payload);

      if (!data.ok) throw new Error(data.error || 'Preview failed');

      if (previewPrimary) {
        previewPrimary.textContent = `${data.deletedCount.toLocaleString()} records targeted (~${_fmtBytes(data.bytesFreedEst)} space to be freed)`;
      }
      if (previewSecondary) {
        const timeDesc = _activeDays === 'all'
          ? 'Scope: All records in selected categories'
          : (payload.beforeDate ? `Scope: Records before ${new Date(payload.beforeDate).toLocaleDateString('th-TH')}` : `Scope: Older than ${_activeDays} days`);
        const logsDesc = (payload.cleanLogs && payload.cleanLogs.length > 0) ? ` + ${payload.cleanLogs.length} log files` : '';
        previewSecondary.textContent = `${timeDesc}${logsDesc} | Retaining: ${data.remainingTotal.toLocaleString()} records`;
      }
    } catch (err) {
      if (previewPrimary) previewPrimary.textContent = 'Preview error';
      if (previewSecondary) previewSecondary.textContent = err.message;
    }
  }

  /* ── Confirmation Modal ──────────────────────────────────── */
  function _openModal(payload, summaryInfo) {
    _pendingCleanupPayload = payload;
    const modal = document.getElementById('db-clean-modal');
    if (!modal) return;

    _setText('db-modal-summary-time',  summaryInfo.timeText);
    _setText('db-modal-summary-cats',  summaryInfo.catsText);
    _setText('db-modal-summary-logs',  summaryInfo.logsText);
    _setText('db-modal-summary-count', summaryInfo.countText);
    _setText('db-modal-summary-bytes', summaryInfo.bytesText);

    modal.style.display = 'flex';
    modal.classList.add('modal-open');
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  function _closeModal() {
    const modal = document.getElementById('db-clean-modal');
    if (modal) {
      modal.style.display = 'none';
      modal.classList.remove('modal-open');
    }
    _pendingCleanupPayload = null;
  }

  /* ── Trigger Actions ─────────────────────────────────────── */
  async function _openQuickClean(days, label) {
    try {
      const payload = { olderThanDays: days, categories: 'all' };
      const preview = await _calcDryRun(payload);
      _openModal(payload, {
        timeText: `Older than ${days} days (${label})`,
        catsText: 'All 5 Categories',
        logsText: 'None',
        countText: `${preview.deletedCount.toLocaleString()} alerts`,
        bytesText: `~${_fmtBytes(preview.bytesFreedEst)}`,
      });
    } catch (err) {
      _showToast('error', 'Preview Error', err.message);
    }
  }

  async function _openQuickCleanForCategory(catKey) {
    const meta = CATEGORY_META[catKey] || { label: catKey };
    try {
      const payload = { olderThanDays: 30, categories: [catKey] };
      const preview = await _calcDryRun(payload);
      _openModal(payload, {
        timeText: 'Older than 30 days (Last Month)',
        catsText: meta.label,
        logsText: 'None',
        countText: `${preview.deletedCount.toLocaleString()} alerts`,
        bytesText: `~${_fmtBytes(preview.bytesFreedEst)}`,
      });
    } catch (err) {
      _showToast('error', 'Preview Error', err.message);
    }
  }

  async function _openQuickCleanForLog(logKey) {
    const meta = FILE_META[logKey] || { label: logKey };
    try {
      const payload = { cleanLogs: [logKey] };
      const preview = await _calcDryRun(payload);
      _openModal(payload, {
        timeText: 'All existing log content',
        catsText: 'None',
        logsText: meta.label,
        countText: '0 records (Log file only)',
        bytesText: `~${_fmtBytes(preview.bytesFreedEst)}`,
      });
    } catch (err) {
      _showToast('error', 'Preview Error', err.message);
    }
  }

  async function _openQuickCleanAllLogs() {
    try {
      const payload = { cleanLogs: ['serverLog', 'serverErr'] };
      const preview = await _calcDryRun(payload);
      _openModal(payload, {
        timeText: 'All existing server log content',
        catsText: 'None',
        logsText: 'Server Log + Error Log',
        countText: '0 records (Logs only)',
        bytesText: `~${_fmtBytes(preview.bytesFreedEst)}`,
      });
    } catch (err) {
      _showToast('error', 'Preview Error', err.message);
    }
  }

  async function _confirmAndExecuteCleanup() {
    if (!_pendingCleanupPayload) return;

    const confirmBtn = document.getElementById('db-clean-modal-confirm');
    if (confirmBtn) {
      confirmBtn.disabled = true;
      confirmBtn.innerHTML = '<i data-lucide="loader-2"></i> Cleaning…';
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    try {
      const res = await _executeClean(_pendingCleanupPayload);
      if (!res.ok) throw new Error(res.error || 'Cleanup execution failed');

      _closeModal();
      _showToast('ok', 'Storage Cleaned Successfully', `Deleted ${res.deletedCount.toLocaleString()} records, freed ~${_fmtBytes(res.bytesFreedEst)}.`);

      // Reload database stats & refresh views
      await load();
      if (window.TopChartsController && typeof window.TopChartsController.renderFromStore === 'function') {
        window.TopChartsController.renderFromStore();
      }
    } catch (err) {
      _showToast('error', 'Cleanup Failed', err.message);
    } finally {
      if (confirmBtn) {
        confirmBtn.disabled = false;
        confirmBtn.innerHTML = '<i data-lucide="trash-2"></i> Confirm &amp; Delete Data';
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }
    }
  }

  /* ── Setup Event Listeners ───────────────────────────────── */
  function _setupListeners() {
    // Refresh button
    const refreshBtn = document.getElementById('db-refresh-btn');
    if (refreshBtn) refreshBtn.addEventListener('click', load);

    // Quick cleanup cards
    const q30 = document.getElementById('btn-quick-clean-30d');
    if (q30) q30.addEventListener('click', () => _openQuickClean(30, 'เดือนที่แล้ว / 30 วัน'));

    const q7 = document.getElementById('btn-quick-clean-7d');
    if (q7) q7.addEventListener('click', () => _openQuickClean(7, '7 วันที่แล้ว'));

    const q90 = document.getElementById('btn-quick-clean-90d');
    if (q90) q90.addEventListener('click', () => _openQuickClean(90, '3 เดือนที่แล้ว'));

    const qLogs = document.getElementById('btn-quick-clean-logs');
    if (qLogs) qLogs.addEventListener('click', _openQuickCleanAllLogs);

    // Time pills
    const pillsWrap = document.getElementById('db-time-pills');
    const customDateWrap = document.getElementById('db-custom-date-wrap');
    const customDateInput = document.getElementById('db-custom-date-input');

    // Default datetime-local value to 30 days ago
    if (customDateInput) {
      const d = new Date();
      d.setDate(d.getDate() - 30);
      customDateInput.value = d.toISOString().slice(0, 16);
      customDateInput.addEventListener('change', _recalculateImpact);
    }

    if (pillsWrap) {
      pillsWrap.querySelectorAll('.db-time-pill').forEach(pill => {
        pill.addEventListener('click', () => {
          pillsWrap.querySelectorAll('.db-time-pill').forEach(p => p.classList.remove('active'));
          pill.classList.add('active');

          const daysAttr = pill.getAttribute('data-days');
          if (daysAttr === 'custom') {
            _activeDays = 'custom';
            if (customDateWrap) customDateWrap.style.display = 'block';
          } else if (daysAttr === 'all') {
            _activeDays = 'all';
            if (customDateWrap) customDateWrap.style.display = 'none';
          } else {
            _activeDays = parseInt(daysAttr, 10);
            if (customDateWrap) customDateWrap.style.display = 'none';
          }
          _recalculateImpact();
        });
      });
    }

    // Toggle All Categories
    const toggleAllBtn = document.getElementById('db-toggle-all-cats');
    if (toggleAllBtn) {
      toggleAllBtn.addEventListener('click', () => {
        const checkboxes = document.querySelectorAll('#db-category-checkboxes input[name="db_cat"]');
        const someUnchecked = Array.from(checkboxes).some(cb => !cb.checked);
        checkboxes.forEach(cb => cb.checked = someUnchecked);
        toggleAllBtn.textContent = someUnchecked ? 'Deselect All' : 'Select All';
        _recalculateImpact();
      });
    }

    // Checkboxes change listeners
    document.querySelectorAll('#view-storage input[type="checkbox"]').forEach(cb => {
      cb.addEventListener('change', _recalculateImpact);
    });

    // Preview & Execute buttons
    const previewBtn = document.getElementById('db-preview-clean-btn');
    if (previewBtn) previewBtn.addEventListener('click', _recalculateImpact);

    const executeBtn = document.getElementById('db-execute-clean-btn');
    if (executeBtn) {
      executeBtn.addEventListener('click', async () => {
        const payload = _getCustomFormPayload();
        try {
          const preview = await _calcDryRun(payload);
          const timeText = _activeDays === 'all'
            ? 'All Time Records (ล้างทั้งหมด)'
            : (payload.beforeDate ? `Before ${new Date(payload.beforeDate).toLocaleString('th-TH')}` : `Older than ${_activeDays} days`);

          const catsText = payload.categories === 'all'
            ? 'All Categories'
            : payload.categories.map(c => CATEGORY_META[c]?.label || c).join(', ');

          const logsText = (payload.cleanLogs && payload.cleanLogs.length > 0)
            ? payload.cleanLogs.map(l => FILE_META[l]?.label || l).join(', ')
            : 'None';

          _openModal(payload, {
            timeText,
            catsText: catsText || 'None',
            logsText,
            countText: `${preview.deletedCount.toLocaleString()} records`,
            bytesText: `~${_fmtBytes(preview.bytesFreedEst)}`,
          });
        } catch (err) {
          _showToast('error', 'Execution Error', err.message);
        }
      });
    }

    // Modal close & backdrop
    const modalClose = document.getElementById('db-clean-modal-close');
    const modalCancel = document.getElementById('db-clean-modal-cancel');
    const modalBackdrop = document.getElementById('db-clean-modal-backdrop');
    const modalConfirm = document.getElementById('db-clean-modal-confirm');

    if (modalClose) modalClose.addEventListener('click', _closeModal);
    if (modalCancel) modalCancel.addEventListener('click', _closeModal);
    if (modalBackdrop) modalBackdrop.addEventListener('click', _closeModal);
    if (modalConfirm) modalConfirm.addEventListener('click', _confirmAndExecuteCleanup);

    // Edit Ingestion Activation Timestamp
    const editIngestBtn = document.getElementById('db-edit-ingest-since-btn');
    if (editIngestBtn) {
      editIngestBtn.addEventListener('click', async () => {
        const currentVal = _currentStats?.ingestSince || '2026-08-25T06:00:00+07:00';
        const newVal = prompt('Enter activation start date & time (ISO format e.g. 2026-08-25T06:00:00+07:00):\n(ระบุวันและเวลาเริ่มต้นรับข้อมูล):', currentVal);
        if (!newVal || newVal.trim() === currentVal.trim()) return;

        try {
          const parsed = new Date(newVal.trim());
          if (isNaN(parsed.getTime())) {
            alert('Invalid Date/Time format. Please use ISO format e.g. 2026-08-25T06:00:00+07:00');
            return;
          }

          const res = await fetch('/api/config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ingestSince: newVal.trim() })
          });
          const data = await res.json();
          if (data.ok) {
            _showToast('ok', 'Activation Time Updated', `Alerts will now be accepted from ${newVal.trim()} onwards.`);
            await load();
          } else {
            throw new Error(data.error || 'Failed to update config');
          }
        } catch (e) {
          _showToast('error', 'Update Failed', e.message);
        }
      });
    }

    // ESC key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        const modal = document.getElementById('db-clean-modal');
        if (modal && modal.style.display !== 'none') _closeModal();
      }
    });
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
      _currentStats = data;

      _renderKpis(data);
      _renderCategoryBars(data.store?.categories ?? {});
      _renderFileList(data.files ?? {});
      _renderTimeline(data);
      _renderRuntime(data.runtime);
      _renderLastUpdated(data.generatedAt);

      // Trigger quick preset and impact calculations
      _updateQuickPresetBadges();
      _recalculateImpact();

    } catch (err) {
      console.error('[DbStorage] Failed to load stats:', err);
    } finally {
      _loading = false;
      if (btn) btn.classList.remove('spinning');
    }
  }

  function init() {
    _setupListeners();
  }

  return { init, load };
})();

window.DbStorageController = DbStorageController;
