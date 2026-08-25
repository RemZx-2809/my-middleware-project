/**
 * Aegis SOC — Resolved Vulnerabilities History Controller
 * Manages permanent history of closed and resolved security issues from Redmine.
 * Features: live search, priority filter, sync from Redmine, multi-select checkboxes,
 * batch bulk delete, detail inspection modal, and statistics.
 */

'use strict';

const FileHistoryController = (() => {

  /* ── Priority badge styling ──────────────────────────────── */
  const PRIORITY_META = {
    Immediate: { label: 'Immediate', cls: 'fh-prio--immediate', icon: 'flame' },
    Urgent:    { label: 'Urgent',    cls: 'fh-prio--urgent',    icon: 'alert-triangle' },
    High:      { label: 'High',      cls: 'fh-prio--high',      icon: 'alert-circle' },
    Normal:    { label: 'Normal',    cls: 'fh-prio--normal',    icon: 'info' },
    Low:       { label: 'Low',       cls: 'fh-prio--low',       icon: 'arrow-down' },
  };

  let _allRecords = [];
  let _loading = false;
  let _searchVal = '';
  let _priorityFilter = '';
  const _selectedIds = new Set();

  /* ── Helpers ─────────────────────────────────────────────── */
  function _esc(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function _fmtDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toLocaleString('th-TH', {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
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

  function _showToast(type, title, body) {
    if (typeof Toast !== 'undefined' && Toast.show) {
      Toast.show({ type, title, body, duration: 4000 });
    }
  }

  /* ── Stats ───────────────────────────────────────────────── */
  function _renderStats(records) {
    let critCount = 0;
    const deviceSet = new Set();
    let fileCount = 0;
    let monthCount = 0;

    const now = new Date();
    const curYear = now.getFullYear();
    const curMonth = now.getMonth();

    for (const r of records) {
      const prio = (r.priority || '').toLowerCase();
      if (prio.includes('immediate') || prio.includes('urgent') || prio.includes('high')) {
        critCount++;
      }
      if (r.targetDevice && r.targetDevice !== 'Unknown Device') {
        deviceSet.add(r.targetDevice);
      }
      if (r.targetFile) {
        fileCount++;
      }
      if (r.closedAt) {
        const d = new Date(r.closedAt);
        if (d.getFullYear() === curYear && d.getMonth() === curMonth) {
          monthCount++;
        }
      }
    }

    _setText('fh-stat-total',   records.length.toLocaleString());
    _setText('fh-stat-crit',    critCount.toLocaleString());
    _setText('fh-stat-devices', deviceSet.size.toLocaleString());
    _setText('fh-stat-files',   fileCount.toLocaleString());
    _setText('fh-stat-month',   monthCount.toLocaleString());
  }

  /* ── Filter ──────────────────────────────────────────────── */
  function _getFiltered() {
    const q = _searchVal.toLowerCase();
    return _allRecords.filter(r => {
      if (_priorityFilter && r.priority !== _priorityFilter) return false;
      if (q) {
        const hay = `${r.subject} ${r.targetDevice} ${r.targetFile} ${r.closedBy} ${r.ruleId} ${r.resolutionNotes} ${r.issueId || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }

  function _truncate(str, max = 70) {
    if (!str) return '—';
    const s = str.replace(/\s+/g, ' ').trim();
    return s.length > max ? s.slice(0, max) + '…' : s;
  }

  /* ── Batch Selection UI Update ───────────────────────────── */
  function _updateBatchBar(filtered) {
    const batchBar = document.getElementById('fh-batch-bar');
    const selCountEl = document.getElementById('fh-selected-count');
    const selBtnCountEl = document.getElementById('fh-selected-btn-count');
    const checkAll = document.getElementById('fh-check-all');

    const count = _selectedIds.size;

    if (batchBar) {
      batchBar.style.display = count > 0 ? 'flex' : 'none';
    }
    if (selCountEl) selCountEl.textContent = count.toLocaleString();
    if (selBtnCountEl) selBtnCountEl.textContent = count.toLocaleString();

    if (checkAll && filtered) {
      if (filtered.length === 0) {
        checkAll.checked = false;
        checkAll.indeterminate = false;
      } else {
        const visibleSelectedCount = filtered.filter(r => _selectedIds.has(r.id)).length;
        checkAll.checked = visibleSelectedCount > 0 && visibleSelectedCount === filtered.length;
        checkAll.indeterminate = visibleSelectedCount > 0 && visibleSelectedCount < filtered.length;
      }
    }
  }

  /* ── Table Rendering ─────────────────────────────────────── */
  function _renderTable() {
    const tbody   = document.getElementById('fh-table-body');
    const emptyEl = document.getElementById('fh-empty');
    const countEl = document.getElementById('fh-row-count');
    if (!tbody) return;

    const filtered = _getFiltered();

    if (countEl) {
      countEl.textContent = `${filtered.length} resolved issue${filtered.length === 1 ? '' : 's'}`;
    }

    if (filtered.length === 0) {
      tbody.innerHTML = '';
      if (emptyEl) emptyEl.style.display = 'flex';
      _updateBatchBar(filtered);
      return;
    }

    if (emptyEl) emptyEl.style.display = 'none';

    tbody.innerHTML = filtered.map((r, idx) => {
      const isChecked = _selectedIds.has(r.id);
      const prioMeta = PRIORITY_META[r.priority] || { label: r.priority || 'Normal', cls: 'fh-prio--normal', icon: 'info' };
      const issueLink = r.issueUrl
        ? `<a href="${_esc(r.issueUrl)}" target="_blank" rel="noopener" class="fh-issue-chip" title="Open Ticket in Redmine" onclick="event.stopPropagation();">
             <i data-lucide="ticket"></i>
             <span>#${r.issueId || '—'}</span>
           </a>`
        : `<span class="fh-issue-chip"><i data-lucide="ticket"></i> #${r.issueId || '—'}</span>`;

      const targetDevice = r.targetDevice ? `<span class="fh-dev-badge"><i data-lucide="server"></i> ${_esc(r.targetDevice)}</span>` : '';
      const targetFile = r.targetFile ? `<span class="fh-file-path" title="${_esc(r.targetFile)}"><i data-lucide="file-code-2"></i> ${_esc(_truncate(r.targetFile, 25))}</span>` : '';

      return `
        <tr class="fh-tr ${isChecked ? 'fh-tr--selected' : ''}" data-idx="${idx}" data-id="${_esc(r.id)}">
          <td class="fh-td fh-td--check" onclick="event.stopPropagation();">
            <input type="checkbox" class="fh-row-check fh-custom-checkbox" data-id="${_esc(r.id)}" ${isChecked ? 'checked' : ''} />
          </td>
          <td class="fh-td fh-td--ts">
            <span class="fh-ts-main">${_fmtDate(r.closedAt)}</span>
            <span class="fh-ts-rel">${_relTime(r.closedAt)}</span>
          </td>
          <td class="fh-td fh-td--issue">
            ${issueLink}
            <span class="fh-prio-badge ${prioMeta.cls}">
              <i data-lucide="${prioMeta.icon}"></i>
              ${_esc(prioMeta.label)}
            </span>
          </td>
          <td class="fh-td fh-td--subject">
            <span class="fh-subject-text" title="${_esc(r.subject)}">${_esc(r.subject)}</span>
            ${r.ruleId ? `<span class="fh-rule-tag">Rule #${_esc(r.ruleId)}</span>` : ''}
          </td>
          <td class="fh-td fh-td--target">
            <div class="fh-target-wrap">
              ${targetDevice}
              ${targetFile}
            </div>
          </td>
          <td class="fh-td fh-td--user">
            <span class="fh-user-chip"><i data-lucide="user-check"></i> ${_esc(r.closedBy || 'Admin')}</span>
          </td>
          <td class="fh-td fh-td--detail">
            <span class="fh-detail-text" title="${_esc(r.resolutionNotes)}">${_esc(_truncate(r.resolutionNotes, 65))}</span>
          </td>
          <td class="fh-td fh-td--actions" onclick="event.stopPropagation();">
            <div class="fh-actions-wrap">
              <button class="fh-action-btn fh-action-btn--view" data-idx="${idx}" title="View Details">
                <i data-lucide="eye"></i>
              </button>
              <button class="fh-action-btn fh-action-btn--del" data-id="${_esc(r.id)}" title="Delete Record">
                <i data-lucide="trash-2"></i>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Row Checkbox Listeners
    tbody.querySelectorAll('.fh-row-check').forEach(cb => {
      cb.addEventListener('change', (e) => {
        const id = cb.getAttribute('data-id');
        if (cb.checked) {
          _selectedIds.add(id);
        } else {
          _selectedIds.delete(id);
        }
        const row = cb.closest('tr');
        if (row) row.classList.toggle('fh-tr--selected', cb.checked);
        _updateBatchBar(filtered);
      });
    });

    // Row Click Listeners (opens modal unless clicking interactive elements)
    tbody.querySelectorAll('.fh-tr').forEach(row => {
      row.addEventListener('click', (e) => {
        if (e.target.closest('input[type="checkbox"]') || e.target.closest('button') || e.target.closest('a')) {
          return;
        }
        const idx = parseInt(row.getAttribute('data-idx'), 10);
        _openDetail(filtered[idx]);
      });
    });

    // View button
    tbody.querySelectorAll('.fh-action-btn--view').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const idx = parseInt(btn.getAttribute('data-idx'), 10);
        _openDetail(filtered[idx]);
      });
    });

    // Delete single button
    tbody.querySelectorAll('.fh-action-btn--del').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const id = btn.getAttribute('data-id');
        if (confirm('Delete this resolved vulnerability record? (ลบประวัติรายการนี้หรือไม่?)')) {
          await _deleteRecord(id);
        }
      });
    });

    _updateBatchBar(filtered);
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  /* ── Detail Modal ────────────────────────────────────────── */
  function _openDetail(record) {
    if (!record) return;

    const modal    = document.getElementById('fh-diff-modal');
    const titleEl  = document.getElementById('fh-diff-filename');
    const metaEl   = document.getElementById('fh-diff-meta');
    const beforeEl = document.getElementById('fh-diff-before');
    const afterEl  = document.getElementById('fh-diff-after');

    if (!modal) return;

    let titleHtml = _esc(record.subject);
    if (record.issueUrl) {
      titleHtml += ` <a href="${_esc(record.issueUrl)}" target="_blank" rel="noopener" class="fh-modal-ext-btn"><i data-lucide="external-link"></i> Open in Redmine</a>`;
    }

    if (titleEl)  titleEl.innerHTML = titleHtml;
    if (metaEl) {
      metaEl.textContent = `Issue #${record.issueId || 'N/A'} • Closed by ${record.closedBy || 'Admin'} on ${_fmtDate(record.closedAt)} (${record.priority || 'Normal'} Priority)`;
    }

    const beforeText = [
      `TARGET DEVICE:  ${record.targetDevice || 'Unknown'}`,
      `TARGET FILE:    ${record.targetFile || 'None specified'}`,
      `RULE ID:        ${record.ruleId || 'None'}`,
      ``,
      `--- VULNERABILITY / ALERT PAYLOAD ---`,
      record.description || 'No additional raw alert description available.'
    ].join('\n');

    const afterText = [
      `STATUS:         ${record.status || 'Closed'}`,
      `RESOLVED BY:    ${record.closedBy || 'Admin'}`,
      `CLOSED AT:      ${_fmtDate(record.closedAt)}`,
      ``,
      `--- RESOLUTION & FIX NOTES ---`,
      record.resolutionNotes || 'Marked as resolved and closed.'
    ].join('\n');

    if (beforeEl) beforeEl.textContent = beforeText;
    if (afterEl)  afterEl.textContent  = afterText;

    modal.style.display = 'flex';
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  function _closeDetail() {
    const modal = document.getElementById('fh-diff-modal');
    if (modal) modal.style.display = 'none';
  }

  /* ── API Calls ───────────────────────────────────────────── */
  async function _deleteRecord(id) {
    try {
      const res = await fetch(`/api/resolved-history?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
      const data = await res.json();
      if (data.ok) {
        _selectedIds.delete(id);
        _showToast('ok', 'Record Deleted', 'Resolved vulnerability record removed.');
        await load();
      } else {
        throw new Error(data.error || 'Failed to delete');
      }
    } catch (err) {
      _showToast('error', 'Delete Error', err.message);
    }
  }

  async function _deleteSelectedRecords() {
    const ids = Array.from(_selectedIds);
    if (ids.length === 0) return;

    if (!confirm(`Delete ${ids.length} selected resolved vulnerability records?\n(ต้องการลบ ${ids.length} รายการที่เลือกไว้หรือไม่?)`)) {
      return;
    }

    const delBtn = document.getElementById('fh-delete-selected-btn');
    if (delBtn) {
      delBtn.disabled = true;
      delBtn.innerHTML = '<i data-lucide="loader-2"></i> Deleting…';
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    try {
      const res = await fetch('/api/resolved-history', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids }),
      });
      const data = await res.json();

      if (data.ok) {
        _selectedIds.clear();
        _showToast('ok', 'Selected Records Deleted', `Successfully removed ${data.deletedCount || ids.length} records.`);
        await load();
      } else {
        throw new Error(data.error || 'Failed to delete selected items');
      }
    } catch (err) {
      _showToast('error', 'Batch Delete Failed', err.message);
    } finally {
      if (delBtn) {
        delBtn.disabled = false;
        delBtn.innerHTML = '<i data-lucide="trash-2"></i> Delete Selected (<span id="fh-selected-btn-count">0</span>)';
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }
    }
  }

  async function _clearAll() {
    if (!confirm('Are you sure you want to clear ALL resolved vulnerabilities history?\n(คุณแน่ใจหรือไม่ว่าต้องการล้างประวัติช่องโหว่ที่ปิดแล้วทั้งหมด?)')) {
      return;
    }
    try {
      const res = await fetch('/api/resolved-history', { method: 'DELETE' });
      const data = await res.json();
      if (data.ok) {
        _selectedIds.clear();
        _showToast('ok', 'History Cleared', 'All resolved vulnerability history wiped.');
        await load();
      } else {
        throw new Error(data.error || 'Failed to clear');
      }
    } catch (err) {
      _showToast('error', 'Clear Error', err.message);
    }
  }

  async function _syncFromRedmine() {
    const btn = document.getElementById('fh-sync-redmine-btn');
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i data-lucide="loader-2"></i> Syncing…';
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    try {
      const res = await fetch('/api/resolved-history/sync', { method: 'POST' });
      const data = await res.json();
      if (data.ok) {
        _showToast('ok', 'Redmine Sync Completed', `Synced ${data.syncedCount || 0} closed issues from Redmine.`);
        await load();
      } else {
        throw new Error(data.error || 'Sync failed');
      }
    } catch (err) {
      _showToast('error', 'Sync Failed', err.message);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="refresh-cw"></i> Sync from Redmine';
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }
    }
  }

  /* ── Main Load ───────────────────────────────────────────── */
  async function load() {
    if (_loading) return;
    _loading = true;

    const refreshBtn = document.getElementById('fh-refresh-btn');
    const loadingEl  = document.getElementById('fh-loading');
    const emptyEl    = document.getElementById('fh-empty');
    const tbody      = document.getElementById('fh-table-body');

    if (refreshBtn) refreshBtn.classList.add('spinning');
    if (loadingEl)  loadingEl.style.display = 'flex';
    if (emptyEl)    emptyEl.style.display   = 'none';
    if (tbody)      tbody.innerHTML         = '';

    try {
      const res  = await fetch('/api/resolved-history?limit=500');
      const data = await res.json();

      if (!data.ok) throw new Error(data.error || 'API error');

      _allRecords = Array.isArray(data.records) ? data.records : [];
      _renderStats(_allRecords);
      _renderTable();

      const lastUpdatedEl = document.getElementById('fh-last-updated');
      if (lastUpdatedEl) {
        lastUpdatedEl.textContent = `Updated: ${new Date().toLocaleTimeString('th-TH')}`;
      }

    } catch (err) {
      console.error('[ResolvedHistory] Load failed:', err);
      if (tbody) tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--crit);padding:30px;">Failed to load resolved history: ${_esc(err.message)}</td></tr>`;
    } finally {
      _loading = false;
      if (refreshBtn) refreshBtn.classList.remove('spinning');
      if (loadingEl)  loadingEl.style.display = 'none';
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }
  }

  /* ── Init ────────────────────────────────────────────────── */
  function init() {
    // Search input
    const searchInput = document.getElementById('fh-search');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        _searchVal = e.target.value.trim();
        _renderTable();
      });
    }

    // Priority filter
    const prioSelect = document.getElementById('fh-filter-priority');
    if (prioSelect) {
      prioSelect.addEventListener('change', (e) => {
        _priorityFilter = e.target.value;
        _renderTable();
      });
    }

    // Check all checkbox
    const checkAll = document.getElementById('fh-check-all');
    if (checkAll) {
      checkAll.addEventListener('change', (e) => {
        const filtered = _getFiltered();
        if (checkAll.checked) {
          filtered.forEach(r => _selectedIds.add(r.id));
        } else {
          filtered.forEach(r => _selectedIds.delete(r.id));
        }
        _renderTable();
      });
    }

    // Delete selected button
    const deleteSelectedBtn = document.getElementById('fh-delete-selected-btn');
    if (deleteSelectedBtn) {
      deleteSelectedBtn.addEventListener('click', _deleteSelectedRecords);
    }

    // Deselect all button
    const deselectBtn = document.getElementById('fh-deselect-all-btn');
    if (deselectBtn) {
      deselectBtn.addEventListener('click', () => {
        _selectedIds.clear();
        _renderTable();
      });
    }

    // Refresh button
    const refreshBtn = document.getElementById('fh-refresh-btn');
    if (refreshBtn) refreshBtn.addEventListener('click', load);

    // Sync button
    const syncBtn = document.getElementById('fh-sync-redmine-btn');
    if (syncBtn) syncBtn.addEventListener('click', _syncFromRedmine);

    // Clear all button
    const clearBtn = document.getElementById('fh-clear-btn');
    if (clearBtn) clearBtn.addEventListener('click', _clearAll);

    // Modal close handlers
    const modalClose = document.getElementById('fh-diff-close');
    const modalBackdrop = document.getElementById('fh-diff-backdrop');
    if (modalClose) modalClose.addEventListener('click', _closeDetail);
    if (modalBackdrop) modalBackdrop.addEventListener('click', _closeDetail);

    // ESC closes modal
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') _closeDetail();
    });
  }

  return { init, load };
})();

window.FileHistoryController = FileHistoryController;
