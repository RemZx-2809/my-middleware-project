/**
 * Aegis SOC — Kibana / OpenSearch / Wazuh Discover Controller
 * 
 * Manages the Discover log explorer view:
 * - Search query & DQL input filtering
 * - Active filter pills (e.g. manager.name: wazuh-server)
 * - 30-minute time-series histogram chart
 * - Hits toolbar (Count, Date Range, Export, Columns, Density, Reset view, Full screen)
 * - Log events table with custom columns, severity level badges, clickable rule IDs
 * - Expandable document details drawer (Key-Value table & Formatted JSON viewer)
 * - Pagination controls (15 rows/page, page numbers)
 */

'use strict';

const DiscoverController = (() => {
  let _allLogs = [];
  let _activeFilters = {
    search: '',
    fieldFilters: {},
  };

  let _pagination = {
    currentPage: 1,
    rowsPerPage: 15,
  };

  let _visibleColumns = ['timestamp', 'agent.name', 'rule.description', 'rule.level', 'rule.id'];
  let _density = 'normal'; // 'normal' | 'compact' | 'expanded'
  let _sortConfig = { field: 'timestamp', direction: 'desc' };

  let _expandedRowId = null;
  let _activeDrawerTab = {}; // map of row index -> 'table' | 'json'
  let _selectedLogIds = new Set();
  let _discoverZoomRange = null; // Local zoom range for Discover only

  function init() {
    _bindEvents();
    fetchDataAndRender();

    // Listen to global Aegis events
    window.addEventListener('aegis:data-updated', fetchDataAndRender);
    window.addEventListener('aegis:alerts-ingested', fetchDataAndRender);
    window.addEventListener('resize', _debounce(renderHistogram, 150));
  }

  function _bindEvents() {
    // Search bar
    const searchInput = document.getElementById('discover-search-input');
    if (searchInput) {
      searchInput.addEventListener('input', _debounce((e) => {
        _activeFilters.search = e.target.value.trim();
        _pagination.currentPage = 1;
        renderAll();
      }, 200));

      searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          _activeFilters.search = searchInput.value.trim();
          _pagination.currentPage = 1;
          fetchDataAndRender(true);
        }
      });
    }

    // Refresh button
    const refreshBtn = document.getElementById('discover-refresh-btn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', (e) => {
        e.preventDefault();
        fetchDataAndRender(true);
      });
    }

    // TimeRange & Show dates buttons in search bar
    const trBtn = document.getElementById('discover-timerange-btn');
    if (trBtn) {
      trBtn.addEventListener('click', toggleTimeRangePopover);
    }

    const showDatesBtn = document.getElementById('discover-show-dates-btn');
    if (showDatesBtn) {
      showDatesBtn.textContent = '~ a day ago \u2192 now';
      showDatesBtn.addEventListener('click', toggleDatesPopover);
    }

    // Export Formatted button
    const exportBtn = document.getElementById('discover-export-btn');
    if (exportBtn) {
      exportBtn.addEventListener('click', openExportModal);
    }

    // Reset View button
    const resetBtn = document.getElementById('discover-reset-btn');
    if (resetBtn) {
      resetBtn.addEventListener('click', resetView);
    }

    // Rows per page select
    const rowsSelect = document.getElementById('discover-rows-select');
    if (rowsSelect) {
      rowsSelect.addEventListener('change', (e) => {
        _pagination.rowsPerPage = parseInt(e.target.value, 10) || 15;
        _pagination.currentPage = 1;
        renderTableAndPagination();
      });
    }

    // Fields button
    const fieldsBtn = document.getElementById('discover-fields-btn');
    if (fieldsBtn) fieldsBtn.addEventListener('click', openFieldsModal);

    // Columns button
    const colsBtn = document.getElementById('discover-columns-btn');
    if (colsBtn) colsBtn.addEventListener('click', openColumnsModal);

    // Density button
    const densityBtn = document.getElementById('discover-density-btn');
    if (densityBtn) densityBtn.addEventListener('click', toggleDensity);

    // Sort button
    const sortBtn = document.getElementById('discover-sort-btn');
    if (sortBtn) sortBtn.addEventListener('click', openSortModal);

    // Fullscreen button
    const fsBtn = document.getElementById('discover-fullscreen-btn');
    if (fsBtn) fsBtn.addEventListener('click', toggleFullscreen);
  }

  async function fetchDataAndRender(showFeedback = false) {
    const refreshBtn = document.getElementById('discover-refresh-btn');
    const refreshIcon = refreshBtn ? refreshBtn.querySelector('svg, i') : null;
    if (refreshIcon) refreshIcon.classList.add('spinning');
    if (refreshBtn) refreshBtn.disabled = true;

    try {
      const searchInput = document.getElementById('discover-search-input');
      if (searchInput) {
        _activeFilters.search = searchInput.value.trim();
      }

      let url = '/api/dashboard-data';
      if (window.TimeRangePicker && window.TimeRangePicker.getRange) {
        const r = window.TimeRangePicker.getRange();
        if (r && r.from && r.to) {
          url += `?from=${r.from.toISOString()}&to=${r.to.toISOString()}`;
          const timeLabel = document.getElementById('discover-time-label');
          if (timeLabel && window.TimeRangePicker.getLabel) {
            timeLabel.textContent = window.TimeRangePicker.getLabel();
          }
        }
      }

      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      const flat = [];
      for (const [k, v] of Object.entries(data)) {
        if (v && Array.isArray(v.alerts)) {
          flat.push(...v.alerts);
        }
      }

      _allLogs = flat || [];
      renderAll();

      if (showFeedback && window.Toast) {
        window.Toast.show({
          type: 'success',
          title: 'Refreshed',
          body: `Loaded ${_allLogs.length.toLocaleString()} events successfully`,
          duration: 2000
        });
      }
    } catch (e) {
      console.warn('[Discover] Error fetching logs:', e.message);
      _allLogs = [];
      renderAll();

      if (showFeedback && window.Toast) {
        window.Toast.show({
          type: 'error',
          title: 'Fetch Error',
          body: `Could not load logs: ${e.message}`,
          duration: 2500
        });
      }
    } finally {
      setTimeout(() => {
        if (refreshIcon) refreshIcon.classList.remove('spinning');
        if (refreshBtn) refreshBtn.disabled = false;
      }, 350);
    }
  }

  let _groupDuplicates = true;

  function toggleGroupDuplicates() {
    _groupDuplicates = !_groupDuplicates;
    const btn = document.getElementById('discover-dedup-btn');
    if (btn) {
      btn.classList.toggle('active', _groupDuplicates);
      const lbl = document.getElementById('discover-dedup-label');
      if (lbl) lbl.textContent = _groupDuplicates ? 'Group Duplicates' : 'All Events';
    }
    _pagination.currentPage = 1;
    renderAll();
    if (window.Toast) {
      window.Toast.show({
        type: 'info',
        title: _groupDuplicates ? 'Deduplication Active' : 'Showing All Events',
        body: _groupDuplicates ? 'Repeated alerts on the same device & rule/file are grouped' : 'Displaying all raw occurrences',
        duration: 2000,
      });
    }
  }

  function _applyDeduplication(logs) {
    if (!_groupDuplicates) return logs;

    const groupMap = new Map();
    for (const log of logs) {
      const agent = log?.agent?.name || log?.manager?.name || 'agent';
      const ruleId = log?.rule?.id || log?.rule?.description || 'rule';
      const fileOrTarget = log?.syscheck?.path || log?.data?.path || log?.data?.srcip || log?.location || '';
      const key = `${agent}::${ruleId}::${fileOrTarget}`.toLowerCase();

      if (!groupMap.has(key)) {
        groupMap.set(key, {
          ...log,
          _repeatCount: 1,
        });
      } else {
        const existing = groupMap.get(key);
        existing._repeatCount = (existing._repeatCount || 1) + 1;

        // Keep the latest timestamp as the display timestamp
        const existTime = new Date(existing.timestamp || existing.receivedAt || 0).getTime();
        const thisTime = new Date(log.timestamp || log.receivedAt || 0).getTime();
        if (thisTime > existTime) {
          existing.timestamp = log.timestamp;
          existing.receivedAt = log.receivedAt;
          existing.rule = log.rule;
          existing.full_log = log.full_log;
          existing.previous_output = log.previous_output;
        }
      }
    }
    return Array.from(groupMap.values());
  }

  function getFilteredLogs() {
    let logs = _allLogs;

    // Discover-specific Zoom Range (Isolated to Discover, doesn't modify Dashboard)
    if (_discoverZoomRange && _discoverZoomRange.from && _discoverZoomRange.to) {
      const fromMs = _discoverZoomRange.from.getTime();
      const toMs = _discoverZoomRange.to.getTime();
      logs = logs.filter(a => {
        const ts = a.timestamp || a.receivedAt || a['@timestamp'];
        if (!ts) return true;
        const t = new Date(ts).getTime();
        return !isNaN(t) && t >= fromMs && t <= toMs;
      });
    } else if (window.TimeRangePicker && window.TimeRangePicker.getRange) {
      // Global Time Range Filter
      const r = window.TimeRangePicker.getRange();
      if (r && r.from && r.to) {
        const fromMs = r.from.getTime();
        const toMs = r.to.getTime();
        logs = logs.filter(a => {
          const ts = a.timestamp || a.receivedAt || a['@timestamp'];
          if (!ts) return true;
          const t = new Date(ts).getTime();
          return !isNaN(t) && t >= fromMs && t <= toMs;
        });
      }
    }

    // Text Search Filter
    if (_activeFilters.search) {
      const q = _activeFilters.search.toLowerCase();
      logs = logs.filter(l => {
        const desc = (l?.rule?.description || '').toLowerCase();
        const ag = (l?.agent?.name || '').toLowerCase();
        const id = String(l?.rule?.id || '');
        const full = (l?.full_log || '').toLowerCase();
        return desc.includes(q) || ag.includes(q) || id.includes(q) || full.includes(q);
      });
    }

    // Field Filters (e.g. manager.name: wazuh-server, agent.name, rule.level)
    for (const [f, v] of Object.entries(_activeFilters.fieldFilters)) {
      if (!v) continue;
      if (f === 'agent.name' || f === 'manager.name') {
        logs = logs.filter(l => (l?.agent?.name || l?.manager?.name || 'wazuh-server') === String(v));
      } else if (f === 'rule.level') {
        logs = logs.filter(l => String(l?.rule?.level) === String(v));
      } else if (f === 'rule.id') {
        logs = logs.filter(l => String(l?.rule?.id) === String(v));
      }
    }

    return _applyDeduplication(logs);
  }

  function renderAll() {
    renderFilterPills();
    renderHistogram();
    renderHitsHeader();
    renderTableAndPagination();
  }

  /* ── FILTER PILLS ───────────────────────────────────────── */
  function renderFilterPills() {
    const row = document.getElementById('discover-filter-row');
    if (!row) return;

    const entries = Object.entries(_activeFilters.fieldFilters);
    if (entries.length === 0) {
      row.innerHTML = '';
      row.style.display = 'none';
      return;
    }

    row.style.display = 'flex';
    let pillsHtml = entries.map(([field, val]) => `
      <div class="filter-pill" data-field="${field}">
        <input type="checkbox" class="filter-pill-chk" checked title="Toggle filter" onchange="DiscoverController.toggleFieldFilter('${field}')" />
        <span class="filter-pill-text">${field}: ${val}</span>
        <div class="filter-pill-actions">
          <button class="filter-pill-btn" title="Remove filter" onclick="DiscoverController.removeFieldFilter('${field}')">&times;</button>
        </div>
      </div>
    `).join('');

    row.innerHTML = pillsHtml;
  }

  function toggleFieldFilter(field) {
    if (_activeFilters.fieldFilters[field]) {
      delete _activeFilters.fieldFilters[field];
    }
    renderAll();
  }

  function removeFieldFilter(field) {
    delete _activeFilters.fieldFilters[field];
    renderAll();
  }

  function addFieldFilter(field, val) {
    _activeFilters.fieldFilters[field] = val;
    renderAll();
  }

  function openAddFilterModal() {
    if (window.TopChartsController && window.TopChartsController.openFilterModalForField) {
      window.TopChartsController.openFilterModalForField('agent.name', 'wazuh-server');
    }
  }

  /* ── HISTOGRAM CHART ────────────────────────────────────── */
  function renderHistogram() {
    const container = document.getElementById('discover-histogram-wrap');
    if (!container) return;

    const filtered = getFilteredLogs();
    const totalCount = filtered.length;

    // Time window calculation
    let rangeStart = null;
    let rangeEnd = null;

    if (window.TimeRangePicker && window.TimeRangePicker.getRange) {
      const r = window.TimeRangePicker.getRange();
      if (r && r.from && r.to) {
        rangeStart = r.from.getTime();
        rangeEnd = r.to.getTime();
      }
    }

    if (!rangeStart || !rangeEnd) {
      const times = filtered.map(l => new Date(l.timestamp || l.receivedAt).getTime()).filter(t => !isNaN(t)).sort((a, b) => a - b);
      if (times.length > 0) {
        rangeStart = times[0];
        rangeEnd = times[times.length - 1];
      } else {
        const now = Date.now();
        rangeStart = now - 24 * 3600 * 1000;
        rangeEnd = now;
      }
    }

    const duration = Math.max(60000, rangeEnd - rangeStart);
    const numBuckets = 48;
    const bucketMs = duration / numBuckets;

    // Dynamic interval description
    let intervalLabel = '30 minutes';
    if (bucketMs < 1000) intervalLabel = 'second';
    else if (bucketMs < 60000) intervalLabel = `${Math.round(bucketMs / 1000)} seconds`;
    else if (bucketMs < 3600000) intervalLabel = `${Math.round(bucketMs / 60000)} minutes`;
    else if (bucketMs < 86400000) intervalLabel = `${Math.round(bucketMs / 3600000)} hours`;
    else intervalLabel = `${Math.round(bucketMs / 86400000)} days`;

    const buckets = Array.from({ length: numBuckets }, (_, i) => ({
      index: i,
      start: rangeStart + i * bucketMs,
      end: rangeStart + (i + 1) * bucketMs,
      count: 0,
    }));

    filtered.forEach(l => {
      const t = new Date(l.timestamp || l.receivedAt).getTime();
      if (isNaN(t)) return;
      const offset = t - rangeStart;
      if (offset >= 0 && offset <= duration) {
        const idx = Math.min(numBuckets - 1, Math.max(0, Math.floor(offset / bucketMs)));
        buckets[idx].count++;
      }
    });

    const width = container.clientWidth || 900;
    const height = 195;
    const padL = 46;
    const padR = 30;
    const padT = 14;
    const padB = 46;

    const chartW = width - padL - padR;
    const chartH = height - padT - padB;

    const maxCount = Math.max(20, ...buckets.map(b => b.count));
    const maxY = Math.ceil(maxCount / 10) * 10;
    const barW = Math.max(2, (chartW / numBuckets) - 2);

    // Render Grid & Y-Ticks
    const ticks = [0, maxY * 0.33, maxY * 0.66, maxY].map(v => Math.round(v));
    let gridHtml = '';
    let yTicksHtml = '';

    ticks.forEach(tVal => {
      const y = padT + chartH - (tVal / maxY) * chartH;
      gridHtml += `<line class="histogram-grid-line" x1="${padL}" y1="${y}" x2="${padL + chartW}" y2="${y}" />`;
      yTicksHtml += `<text class="histogram-axis-text" x="${padL - 6}" y="${y + 4}" text-anchor="end">${tVal}</text>`;
    });

    // Render Bars
    let barsHtml = '';
    buckets.forEach((b, i) => {
      const x = padL + i * (chartW / numBuckets) + 1;
      const h = (b.count / maxY) * chartH;
      const y = padT + chartH - h;
      const startDateStr = new Date(b.start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      barsHtml += `
        <rect class="histogram-bar"
              x="${x}" y="${y}" width="${barW}" height="${Math.max(1, h)}"
              data-count="${b.count}" data-time="${startDateStr}"
              onmouseenter="DiscoverController.showBarTooltip(event, '${startDateStr}', ${b.count})"
              onmouseleave="DiscoverController.hideBarTooltip()"
              onclick="DiscoverController.zoomToBucket(${b.start}, ${b.end})" />
      `;
    });

    // Render X Ticks with boundary-safe anchors
    let xTicksHtml = '';
    const xStepCount = 6;
    for (let i = 0; i < xStepCount; i++) {
      const bIdx = Math.floor((i / (xStepCount - 1)) * (numBuckets - 1));
      const t = new Date(buckets[bIdx].start);
      const timeStr = t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const x = padL + bIdx * (chartW / numBuckets);
      const anchor = (i === 0) ? 'start' : (i === xStepCount - 1 ? 'end' : 'middle');
      xTicksHtml += `<text class="histogram-axis-text" x="${x}" y="${padT + chartH + 17}" text-anchor="${anchor}">${timeStr}</text>`;
    }

    const isZoomed = duration < 24 * 3600 * 1000 - 60000;

    container.innerHTML = `
      <div class="discover-histogram-header">
        <div class="discover-histogram-title">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
          <span>Event Timeline Histogram</span>
          ${isZoomed ? '<span class="discover-histogram-zoom-badge"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="11" y1="8" x2="11" y2="14"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg> Zoomed View</span>' : ''}
        </div>
        <div class="discover-histogram-controls">
          <button class="hist-zoom-btn" title="Zoom in to center (2x)" onclick="DiscoverController.zoomIn()">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="11" y1="8" x2="11" y2="14"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg>
            Zoom In
          </button>
          <button class="hist-zoom-btn" title="Zoom out (2x)" onclick="DiscoverController.zoomOut()">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg>
            Zoom Out
          </button>
          <button class="hist-zoom-btn" title="Zoom to fit all events" onclick="DiscoverController.zoomFitHits()">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="3"></circle></svg>
            Fit Hits
          </button>
          <button class="hist-zoom-btn" title="Reset Zoom to full time range" onclick="DiscoverController.resetZoom()">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path><path d="M3 3v5h5"></path></svg>
            Reset
          </button>
        </div>
      </div>
      <svg class="histogram-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" onmouseleave="DiscoverController.hideBarTooltip()">
        <g>${gridHtml}</g>
        <g>${yTicksHtml}</g>
        <g>${barsHtml}</g>
        <g>${xTicksHtml}</g>
        <text class="histogram-axis-text" x="${12}" y="${padT + chartH / 2}" transform="rotate(-90 12 ${padT + chartH / 2})" text-anchor="middle">Count</text>
        <text class="histogram-axis-text" x="${padL + chartW / 2}" y="${padT + chartH + 32}" text-anchor="middle">timestamp per ${intervalLabel}</text>
      </svg>
    `;
  }

  /* ── HITS HEADER & TOOLBAR ─────────────────────────────── */
  function renderHitsHeader() {
    const hitsCountEl = document.getElementById('discover-hits-count');
    const hitsSubEl   = document.getElementById('discover-hits-sub');

    const filtered = getFilteredLogs();
    const groupCount = filtered.length;
    const totalRawCount = filtered.reduce((sum, l) => sum + (l._repeatCount || 1), 0);

    if (hitsCountEl) {
      if (_groupDuplicates && totalRawCount !== groupCount) {
        hitsCountEl.innerHTML = `${totalRawCount.toLocaleString()} <span class="hits-label">hits</span> <span style="font-size:12px; font-weight:400; color:#94a3b8; margin-left:4px;">(${groupCount} grouped)</span> <svg class="hits-info-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
      } else {
        hitsCountEl.innerHTML = `${groupCount.toLocaleString()} <span class="hits-label">hits</span> <svg class="hits-info-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
      }
    }

    if (hitsSubEl) {
      let fromStr = '';
      let toStr   = '';

      if (_discoverZoomRange && _discoverZoomRange.from && _discoverZoomRange.to) {
        fromStr = _formatKibanaDate(_discoverZoomRange.from);
        toStr   = _formatKibanaDate(_discoverZoomRange.to);
      } else if (window.TimeRangePicker && window.TimeRangePicker.getRange) {
        const r = window.TimeRangePicker.getRange();
        if (r && r.from && r.to) {
          fromStr = _formatKibanaDate(r.from);
          toStr   = _formatKibanaDate(r.to);
        }
      }

      if (!fromStr || !toStr) {
        const times = filtered.map(l => new Date(l.timestamp || l.receivedAt).getTime()).filter(t => !isNaN(t)).sort((a, b) => a - b);
        if (times.length > 0) {
          fromStr = _formatKibanaDate(new Date(times[0]));
          toStr   = _formatKibanaDate(new Date(times[times.length - 1]));
        } else {
          fromStr = _formatKibanaDate(new Date(Date.now() - 24 * 3600 * 1000));
          toStr   = _formatKibanaDate(new Date());
        }
      }
      hitsSubEl.textContent = `${fromStr} - ${toStr}`;
    }
  }

  function _formatKibanaDate(d) {
    if (!d || isNaN(new Date(d).getTime())) return '';
    const dateObj = new Date(d);
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const m = months[dateObj.getMonth()];
    const day = dateObj.getDate().toString().padStart(2, '0');
    const y = dateObj.getFullYear();
    const hh = dateObj.getHours().toString().padStart(2, '0');
    const mm = dateObj.getMinutes().toString().padStart(2, '0');
    const ss = dateObj.getSeconds().toString().padStart(2, '0');
    const ms = dateObj.getMilliseconds().toString().padStart(3, '0');
    return `${m} ${day}, ${y} @ ${hh}:${mm}:${ss}.${ms}`;
  }

  function _formatShortTimestamp(ts) {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const m = months[d.getMonth()];
    const day = d.getDate().toString().padStart(2, '0');
    const y = d.getFullYear();
    const hh = d.getHours().toString().padStart(2, '0');
    const mm = d.getMinutes().toString().padStart(2, '0');
    const ss = d.getSeconds().toString().padStart(2, '0');
    const ms = d.getMilliseconds().toString().padStart(3, '0');
    return `${m} ${day}, ${y} @ ${hh}:${mm}:${ss}.${ms}`;
  }

  function getSortedLogs(logs) {
    if (!_sortConfig || !_sortConfig.field) return logs;
    const { field, direction } = _sortConfig;
    const isAsc = direction === 'asc';

    return [...logs].sort((a, b) => {
      let valA = _extractFieldValue(a, field);
      let valB = _extractFieldValue(b, field);

      if (field === 'timestamp' || field === '@timestamp') {
        const tA = new Date(valA).getTime() || 0;
        const tB = new Date(valB).getTime() || 0;
        return isAsc ? tA - tB : tB - tA;
      }

      if (field === 'rule.level') {
        const lA = parseInt(valA ?? 0, 10);
        const lB = parseInt(valB ?? 0, 10);
        return isAsc ? lA - lB : lB - lA;
      }

      if (valA === undefined || valA === null) valA = '';
      if (valB === undefined || valB === null) valB = '';

      const strA = String(valA).toLowerCase();
      const strB = String(valB).toLowerCase();
      return isAsc ? strA.localeCompare(strB) : strB.localeCompare(strA);
    });
  }

  /* ── LOG TABLE & PAGINATION ────────────────────────────── */
  function renderTableAndPagination() {
    const thead = document.querySelector('#discover-table thead');
    const tbody = document.getElementById('discover-table-tbody');
    const pagNav = document.getElementById('discover-pag-nav');
    if (!tbody) return;

    const logs = getSortedLogs(getFilteredLogs());
    const totalCount = logs.length;
    const { currentPage, rowsPerPage } = _pagination;
    const totalPages = Math.max(1, Math.ceil(totalCount / rowsPerPage));

    const startIdx = (currentPage - 1) * rowsPerPage;
    const pageLogs = logs.slice(startIdx, startIdx + rowsPerPage);

    // Render Table Headers dynamically according to _visibleColumns
    if (thead) {
      const allChecked = pageLogs.length > 0 && pageLogs.every(l => _selectedLogIds.has(String(l.id || l._id || l.timestamp)));
      thead.innerHTML = `
        <tr>
          <th style="width: 36px; text-align: center;">
            <input type="checkbox" id="discover-select-all" class="fh-custom-checkbox" ${allChecked ? 'checked' : ''} onchange="DiscoverController.toggleSelectAll(this.checked)" title="Select all on this page" />
          </th>
          <th style="width: 36px; text-align: center;"></th>
          ${_visibleColumns.map(col => {
            const isSorted = _sortConfig.field === col;
            const arrow = isSorted ? (_sortConfig.direction === 'asc' ? ' &uarr;' : ' &darr;') : '';
            return `
              <th style="cursor: pointer;" onclick="DiscoverController.sortByColumn('${col}')" title="Click to sort by ${col}">
                <span class="th-content">
                  ${col}${arrow}
                </span>
              </th>
            `;
          }).join('')}
          <th style="width: 110px; text-align: center;">Redmine</th>
        </tr>
      `;
    }

    if (pageLogs.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="${_visibleColumns.length + 3}" style="text-align:center; padding: 32px; color: var(--text-lo);">
            No matching log entries found for current filter.
          </td>
        </tr>
      `;
      if (pagNav) pagNav.innerHTML = '';
      return;
    }

    let rowsHtml = '';
    pageLogs.forEach((log, idx) => {
      const globalIdx = startIdx + idx;
      const isExpanded = _expandedRowId === globalIdx;
      const logId = String(log.id || log._id || log.timestamp || globalIdx);
      const isSelected = _selectedLogIds.has(logId);

      let cellsHtml = '';
      _visibleColumns.forEach(col => {
        const val = _extractFieldValue(log, col);
        if (col === 'timestamp') {
          cellsHtml += `<td class="cell-ts" title="${val}">${_formatShortTimestamp(val)}</td>`;
        } else if (col === 'rule.level') {
          const ruleLvl = parseInt(val ?? 4, 10);
          let lvlClass = 'rule-level-badge--lvl4';
          if (ruleLvl >= 12) lvlClass = 'rule-level-badge--lvl12';
          else if (ruleLvl >= 11) lvlClass = 'rule-level-badge--lvl11';
          else if (ruleLvl >= 7) lvlClass = 'rule-level-badge--lvl7';
          cellsHtml += `<td style="text-align:center;"><span class="rule-level-badge ${lvlClass}">${ruleLvl}</span></td>`;
        } else if (col === 'rule.id') {
          cellsHtml += `<td><a class="rule-id-link" onclick="DiscoverController.filterByRuleId('${val}')">${val}</a></td>`;
        } else if (col === 'agent.name') {
          cellsHtml += `<td class="cell-agent">${val}</td>`;
        } else if (col === 'rule.description') {
          const repeatBadge = (log._repeatCount && log._repeatCount > 1)
            ? `<span class="badge-repeat-count" title="Repeated ${log._repeatCount} times on ${log?.agent?.name || 'device'}">(${log._repeatCount}x)</span> `
            : '';
          cellsHtml += `<td class="cell-desc">${repeatBadge}${_escapeHtml(val)}</td>`;
        } else {
          cellsHtml += `<td style="font-family:var(--font-mono); font-size:12px; color:#cbd5e1;">${_escapeHtml(String(val))}</td>`;
        }
      });

      const ticketBadge = log.redmine_ticket
        ? `<a href="${log.redmine_ticket.url}" target="_blank" class="redmine-ticket-badge" title="Ticket #${log.redmine_ticket.id} (${log.redmine_ticket.status || 'Open'})" onclick="event.stopPropagation()">🎟️ #${log.redmine_ticket.id}</a>`
        : `<button class="btn-dispatch-ticket" title="Dispatch incident to Redmine" onclick="event.stopPropagation(); window.RedmineDispatchController && RedmineDispatchController.openSingleModal(DiscoverController.getLogById('${logId}'))"><i data-lucide="ticket"></i> Dispatch</button>`;

      rowsHtml += `
        <tr class="discover-row ${isExpanded ? 'doc-row--active' : ''} ${isSelected ? 'row--selected' : ''}" id="doc-row-${globalIdx}">
          <td style="width: 36px; text-align: center;" onclick="event.stopPropagation()">
            <input type="checkbox" class="log-row-checkbox fh-custom-checkbox" value="${logId}" ${isSelected ? 'checked' : ''} onchange="DiscoverController.toggleSelectRow('${logId}', this.checked)" />
          </td>
          <td style="width: 36px; text-align: center;">
            <button class="btn-expand-doc ${isExpanded ? 'open' : ''}"
                    title="Inspect document"
                    onclick="DiscoverController.toggleRowExpand(${globalIdx})">
              <svg style="width:14px;height:14px;color:#0077c8;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="11" cy="11" r="8"></circle>
                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                <line x1="11" y1="8" x2="11" y2="14"></line>
                <line x1="8" y1="11" x2="14" y2="11"></line>
              </svg>
            </button>
          </td>
          ${cellsHtml}
          <td style="text-align: center;" onclick="event.stopPropagation()">
            ${ticketBadge}
          </td>
        </tr>
      `;
    });

    tbody.innerHTML = rowsHtml;
    if (typeof lucide !== 'undefined') lucide.createIcons();

    // Render Pagination Buttons
    if (pagNav) {
      let navHtml = `
        <button class="pag-btn" ${currentPage === 1 ? 'disabled' : ''} onclick="DiscoverController.setPage(1)" title="First page">&laquo;</button>
        <button class="pag-btn" ${currentPage === 1 ? 'disabled' : ''} onclick="DiscoverController.setPage(${currentPage - 1})" title="Previous page">&lt;</button>
      `;

      const maxBtns = 5;
      let startP = Math.max(1, currentPage - 2);
      let endP = Math.min(totalPages, startP + maxBtns - 1);
      if (endP - startP < maxBtns - 1) startP = Math.max(1, endP - maxBtns + 1);

      if (startP > 1) {
        navHtml += `<button class="pag-btn" onclick="DiscoverController.setPage(1)">1</button>`;
        if (startP > 2) {
          navHtml += `<span style="color:var(--text-lo); padding:0 4px;">...</span>`;
        }
      }

      for (let p = startP; p <= endP; p++) {
        if (p === 1 && startP > 1) continue;
        if (p === totalPages && endP < totalPages) continue;
        navHtml += `
          <button class="pag-btn ${p === currentPage ? 'active' : ''}" onclick="DiscoverController.setPage(${p})">${p}</button>
        `;
      }

      if (endP < totalPages) {
        if (endP < totalPages - 1) {
          navHtml += `<span style="color:var(--text-lo); padding:0 4px;">...</span>`;
        }
        navHtml += `<button class="pag-btn" onclick="DiscoverController.setPage(${totalPages})">${totalPages}</button>`;
      }

      navHtml += `
        <button class="pag-btn" ${currentPage === totalPages ? 'disabled' : ''} onclick="DiscoverController.setPage(${currentPage + 1})" title="Next page">&gt;</button>
        <button class="pag-btn" ${currentPage === totalPages ? 'disabled' : ''} onclick="DiscoverController.setPage(${totalPages})" title="Last page">&raquo;</button>
      `;

      pagNav.innerHTML = navHtml;
    }
  }

  function toggleDensity() {
    if (_density === 'normal') _density = 'compact';
    else if (_density === 'compact') _density = 'expanded';
    else _density = 'normal';

    const label = document.getElementById('discover-density-label');
    if (label) {
      label.textContent = `Density: ${_density.charAt(0).toUpperCase() + _density.slice(1)}`;
    }

    const table = document.getElementById('discover-table');
    if (table) {
      table.classList.remove('density-compact', 'density-normal', 'density-expanded');
      table.classList.add(`density-${_density}`);
    }

    if (window.Toast && typeof window.Toast.show === 'function') {
      window.Toast.show({
        type: 'info',
        title: 'Table Density Changed',
        body: `Row spacing set to ${_density}`,
        duration: 2000
      });
    }
  }

  let _isDiscoverFullscreen = false;

  function toggleFullscreen() {
    _isDiscoverFullscreen = !_isDiscoverFullscreen;
    const discoverView = document.getElementById('view-discover');
    const btn = document.getElementById('discover-fullscreen-btn');

    if (!discoverView) return;

    if (_isDiscoverFullscreen) {
      discoverView.classList.add('discover--fullscreen-table');
      if (btn) {
        btn.innerHTML = `
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline-block;vertical-align:middle;margin-right:4px;">
            <path d="M8 3v3a2 2 0 0 1-2 2H3"/><path d="M21 8h-3a2 2 0 0 1-2-2V3"/>
            <path d="M3 16h3a2 2 0 0 1 2 2v3"/><path d="M16 21v-3a2 2 0 0 1 2-2h3"/>
          </svg>
          Exit full screen`;
      }
      document.addEventListener('keydown', _handleFsEsc);
    } else {
      discoverView.classList.remove('discover--fullscreen-table');
      if (btn) {
        btn.innerHTML = `
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline-block;vertical-align:middle;margin-right:4px;">
            <path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/>
            <path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/>
          </svg>
          Full screen`;
      }
      document.removeEventListener('keydown', _handleFsEsc);
    }
  }

  function _handleFsEsc(e) {
    if (e.key === 'Escape' && _isDiscoverFullscreen) {
      toggleFullscreen();
    }
  }


  function getSortedLogs(logs) {
    const list = [...logs];
    const { field, direction } = _sortConfig;
    const factor = direction === 'asc' ? 1 : -1;

    list.sort((a, b) => {
      let va = _extractFieldValue(a, field);
      let vb = _extractFieldValue(b, field);

      if (field === 'timestamp') {
        const da = new Date(va).getTime() || 0;
        const db = new Date(vb).getTime() || 0;
        return (da - db) * factor;
      }
      if (field === 'rule.level') {
        const na = parseInt(va ?? 0, 10);
        const nb = parseInt(vb ?? 0, 10);
        return (na - nb) * factor;
      }

      va = String(va ?? '').toLowerCase();
      vb = String(vb ?? '').toLowerCase();
      return va.localeCompare(vb) * factor;
    });

    return list;
  }

  function _extractFieldValue(log, path) {
    if (!log) return '';
    if (path === 'timestamp') return log.timestamp || log.receivedAt || '';
    if (path === 'agent.name') return log?.agent?.name || log?.manager?.name || 'wazuh-server';
    if (path === 'agent.id') return log?.agent?.id || '000';
    if (path === 'agent.ip') return log?.agent?.ip || log?.data?.srcip || '127.0.0.1';
    if (path === 'rule.description') return log?.rule?.description || log?.full_log || '';
    if (path === 'rule.level') return log?.rule?.level ?? 4;
    if (path === 'rule.id') return log?.rule?.id || '81606';
    if (path === 'rule.mitre.id') {
      const ids = log?.rule?.mitre?.id || log?.rule?.mitre?.tactic || '';
      return Array.isArray(ids) ? ids.join(', ') : String(ids);
    }
    if (path === 'rule.groups') {
      const g = log?.rule?.groups || [];
      return Array.isArray(g) ? g.join(', ') : String(g);
    }
    if (path === 'data.srcip') return log?.data?.srcip || log?.srcip || '—';
    if (path === 'data.dstip') return log?.data?.dstip || log?.dstip || '—';
    if (path === 'manager.name') return log?.manager?.name || 'wazuh-server';
    if (path === 'location') return log?.location || '/var/log/messages';
    if (path === 'decoder.name') return log?.decoder?.name || 'syslog';
    if (path === 'syscheck.path' || path === 'file' || path === 'targetFile' || path === 'data.path') {
      return log?.syscheck?.path || log?.data?.path || log?.filename || log?.syscheck?.file || '—';
    }
    return log[path] || '—';
  }

  function openSortModal() {
    let modal = document.getElementById('discover-sort-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'discover-sort-modal';
      modal.className = 'discover-modal-backdrop';
      document.body.appendChild(modal);
    }

    modal.innerHTML = `
      <div class="discover-modal-card" style="max-width: 420px;">
        <div class="discover-modal-header">
          <h3>Sort Options</h3>
          <button class="discover-modal-close" onclick="DiscoverController.closeSortModal()">&times;</button>
        </div>
        <div class="discover-modal-body">
          <div style="display:flex; flex-direction:column; gap:12px;">
            <label style="color:#94a3b8; font-size:12px; font-weight:600;">Sort By Field</label>
            <select id="modal-sort-field" class="int-select" style="background:#080c14; color:#ffffff; border:1px solid rgba(255,255,255,0.15); border-radius:6px; padding:8px 12px;">
              <option value="timestamp" ${_sortConfig.field === 'timestamp' ? 'selected' : ''}>timestamp (Event Time)</option>
              <option value="rule.level" ${_sortConfig.field === 'rule.level' ? 'selected' : ''}>rule.level (Severity Level)</option>
              <option value="rule.id" ${_sortConfig.field === 'rule.id' ? 'selected' : ''}>rule.id (Rule Identifier)</option>
              <option value="agent.name" ${_sortConfig.field === 'agent.name' ? 'selected' : ''}>agent.name (Agent Host)</option>
            </select>

            <label style="color:#94a3b8; font-size:12px; font-weight:600; margin-top:8px;">Direction</label>
            <div style="display:flex; gap:10px;">
              <label style="display:flex; align-items:center; gap:6px; color:#e2e8f0; font-size:13px; cursor:pointer;">
                <input type="radio" name="sort-dir" value="desc" ${_sortConfig.direction === 'desc' ? 'checked' : ''} />
                Descending (Newest / Highest first &darr;)
              </label>
            </div>
            <div style="display:flex; gap:10px;">
              <label style="display:flex; align-items:center; gap:6px; color:#e2e8f0; font-size:13px; cursor:pointer;">
                <input type="radio" name="sort-dir" value="asc" ${_sortConfig.direction === 'asc' ? 'checked' : ''} />
                Ascending (Oldest / Lowest first &uarr;)
              </label>
            </div>
          </div>
        </div>
        <div class="discover-modal-footer">
          <button class="btn-kibana" onclick="DiscoverController.closeSortModal()">Cancel</button>
          <button class="btn-kibana btn-kibana--primary" onclick="DiscoverController.applySortModal()">Apply Sort</button>
        </div>
      </div>
    `;

    modal.style.display = 'flex';
  }

  function closeSortModal() {
    const modal = document.getElementById('discover-sort-modal');
    if (modal) modal.style.display = 'none';
  }

  function applySortModal() {
    const fieldSel = document.getElementById('modal-sort-field');
    const dirSel = document.querySelector('input[name="sort-dir"]:checked');

    if (fieldSel && dirSel) {
      _sortConfig.field = fieldSel.value;
      _sortConfig.direction = dirSel.value;

      const label = document.getElementById('discover-sort-label');
      if (label) {
        label.textContent = `${_sortConfig.field} ${_sortConfig.direction === 'desc' ? '↓' : '↑'}`;
      }

      closeSortModal();
      renderTableAndPagination();
    }
  }

  function sortByColumn(col) {
    if (_sortConfig.field === col) {
      _sortConfig.direction = _sortConfig.direction === 'asc' ? 'desc' : 'asc';
    } else {
      _sortConfig.field = col;
      _sortConfig.direction = 'desc';
    }

    const label = document.getElementById('discover-sort-label');
    if (label) {
      label.textContent = `${_sortConfig.field} ${_sortConfig.direction === 'desc' ? '↓' : '↑'}`;
    }

    renderTableAndPagination();
  }

  let _columnsPopoverOpen = false;

  function toggleColumnsPopover(e) {
    if (e) e.stopPropagation();
    const btn = document.getElementById('discover-columns-btn');
    let popover = document.getElementById('discover-columns-popover');

    if (_columnsPopoverOpen && popover && popover.style.display !== 'none') {
      closeColumnsModal();
      return;
    }

    if (!popover) {
      popover = document.createElement('div');
      popover.id = 'discover-columns-popover';
      popover.className = 'discover-columns-popover';
      document.body.appendChild(popover);
    }

    _renderColumnsPopoverContent(popover);

    if (btn) {
      const rect = btn.getBoundingClientRect();
      const popW = 180;
      const left = Math.max(10, Math.min(window.innerWidth - popW - 10, rect.left + (rect.width / 2) - 42));
      const top = rect.bottom + 8;

      popover.style.left = `${left}px`;
      popover.style.top = `${top}px`;
      btn.classList.add('active');
    }

    popover.style.display = 'block';
    _columnsPopoverOpen = true;

    const _handleOutsideClick = (ev) => {
      if (popover && !popover.contains(ev.target) && (!btn || !btn.contains(ev.target))) {
        closeColumnsModal();
        document.removeEventListener('click', _handleOutsideClick);
      }
    };

    setTimeout(() => {
      document.addEventListener('click', _handleOutsideClick);
    }, 10);
  }

  function _renderColumnsPopoverContent(popover) {
    if (!popover) return;
    popover.innerHTML = `
      <div class="discover-columns-popover-arrow"></div>
      <div class="discover-columns-popover-list" id="discover-columns-list">
        ${_visibleColumns.map((col, idx) => `
          <div class="discover-col-item ${idx === 0 ? 'selected' : ''}" data-col="${col}" data-index="${idx}" draggable="true" tabindex="0">
            <span class="discover-col-name">${col}</span>
            <span class="discover-col-handle" title="Drag to reorder">
              <svg width="14" height="10" viewBox="0 0 14 10" fill="none" stroke="#64748b" stroke-width="1.5" stroke-linecap="round">
                <line x1="1" y1="3" x2="13" y2="3"></line>
                <line x1="1" y1="7" x2="13" y2="7"></line>
              </svg>
            </span>
          </div>
        `).join('')}
      </div>
    `;

    const items = popover.querySelectorAll('.discover-col-item');
    let draggedItem = null;

    items.forEach(item => {
      item.addEventListener('click', (e) => {
        e.stopPropagation();
        items.forEach(i => i.classList.remove('selected'));
        item.classList.add('selected');
      });

      item.addEventListener('dragstart', (e) => {
        draggedItem = item;
        item.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', item.getAttribute('data-index'));
      });

      item.addEventListener('dragend', () => {
        item.classList.remove('dragging');
        items.forEach(i => i.classList.remove('drag-over'));
        draggedItem = null;
      });

      item.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        if (draggedItem && draggedItem !== item) {
          item.classList.add('drag-over');
        }
      });

      item.addEventListener('dragleave', () => {
        item.classList.remove('drag-over');
      });

      item.addEventListener('drop', (e) => {
        e.preventDefault();
        item.classList.remove('drag-over');
        if (!draggedItem || draggedItem === item) return;

        const fromIdx = parseInt(draggedItem.getAttribute('data-index'), 10);
        const toIdx = parseInt(item.getAttribute('data-index'), 10);

        if (!isNaN(fromIdx) && !isNaN(toIdx) && fromIdx !== toIdx) {
          const movedCol = _visibleColumns.splice(fromIdx, 1)[0];
          _visibleColumns.splice(toIdx, 0, movedCol);

          _renderColumnsPopoverContent(popover);
          renderTableAndPagination();
        }
      });
    });
  }

  function openColumnsModal(e) {
    toggleColumnsPopover(e);
  }

  function closeColumnsModal() {
    const popover = document.getElementById('discover-columns-popover');
    if (popover) popover.style.display = 'none';
    const btn = document.getElementById('discover-columns-btn');
    if (btn) btn.classList.remove('active');
    _columnsPopoverOpen = false;
  }

  function resetDefaultColumns() {
    _visibleColumns = ['timestamp', 'agent.name', 'rule.description', 'rule.level', 'rule.id'];
    const popover = document.getElementById('discover-columns-popover');
    if (popover) _renderColumnsPopoverContent(popover);
    renderTableAndPagination();
  }

  function applyColumnsModal() {
    closeColumnsModal();
    renderTableAndPagination();
  }

  const ALL_AVAILABLE_FIELDS = [
    'timestamp',
    'agent.name',
    '@timestamp',
    '@version',
    'GeoLocation.area_code',
    'GeoLocation.city_name',
    'GeoLocation.continent_code',
    'GeoLocation.coordinates',
    'GeoLocation.country_code2',
    'GeoLocation.country_code3',
    'GeoLocation.country_name',
    'GeoLocation.dma_code',
    'GeoLocation.ip',
    'GeoLocation.latitude',
    'GeoLocation.location',
    'GeoLocation.longitude',
    'GeoLocation.postal_code',
    'GeoLocation.real_region_name',
    'GeoLocation.region_name',
    'GeoLocation.timezone',
    '_index',
    'agent.id',
    'agent.ip',
    'data.srcip',
    'data.dstip',
    'data.srcport',
    'data.dstport',
    'data.user',
    'data.action',
    'data.protocol',
    'rule.id',
    'rule.level',
    'rule.description',
    'rule.groups',
    'rule.mitre.id',
    'rule.mitre.tactic',
    'rule.mitre.technique',
    'rule.pci_dss',
    'rule.gdpr',
    'rule.hipaa',
    'rule.nist_800_53',
    'rule.tsc',
    'manager.name',
    'full_log',
    'decoder.name',
    'location',
    'input.type',
    'host.name',
    'host.ip',
    'host.os.name',
    'host.architecture',
    'process.name',
    'process.pid',
    'process.executable',
    'process.parent.name',
    'user.name',
    'user.domain',
    'user.id',
    'network.transport',
    'network.direction',
    'network.bytes',
    'syslog.facility',
    'syslog.severity',
    'syslog.program',
    'file.path',
    'file.name',
    'file.size',
    'file.hash.sha256',
    'file.hash.md5',
    'vulnerability.cve',
    'vulnerability.severity',
    'vulnerability.package.name',
    'vulnerability.package.version',
    'cloud.provider',
    'cloud.region',
    'cloud.instance.id',
    'event.dataset',
    'event.module',
    'event.action',
    'event.outcome',
    'event.category',
    'event.type',
    'event.severity',
    'observer.type',
    'observer.vendor',
    'labels',
    'tags',
    'rule.firedtimes',
    'rule.mail',
    'aegis_use_case',
  ];

  let _fieldsPopoverOpen = false;
  let _fieldsSearchQuery = '';

  function toggleFieldsPopover(e) {
    if (e) e.stopPropagation();
    const btn = document.getElementById('discover-fields-btn');
    let popover = document.getElementById('discover-fields-popover');

    if (_fieldsPopoverOpen && popover && popover.style.display !== 'none') {
      closeFieldsModal();
      return;
    }

    if (!popover) {
      popover = document.createElement('div');
      popover.id = 'discover-fields-popover';
      popover.className = 'discover-fields-popover';
      document.body.appendChild(popover);
    }

    _fieldsSearchQuery = '';
    _renderFieldsPopoverContent(popover);

    if (btn) {
      const rect = btn.getBoundingClientRect();
      const popW = 320;
      const popH = 430;
      const left = Math.max(10, Math.min(window.innerWidth - popW - 10, rect.left));
      
      const arrow = popover.querySelector('.discover-fields-popover-arrow');

      if (rect.top - popH > 10) {
        // Place ABOVE button
        popover.style.top = `${rect.top - popH - 8}px`;
        popover.style.left = `${left}px`;
        if (arrow) {
          arrow.className = 'discover-fields-popover-arrow arrow-bottom';
          arrow.style.left = `${Math.min(popW - 20, Math.max(16, rect.left - left + 24))}px`;
        }
      } else {
        // Place BELOW button
        popover.style.top = `${rect.bottom + 8}px`;
        popover.style.left = `${left}px`;
        if (arrow) {
          arrow.className = 'discover-fields-popover-arrow arrow-top';
          arrow.style.left = `${Math.min(popW - 20, Math.max(16, rect.left - left + 24))}px`;
        }
      }
      btn.classList.add('active');
    }

    popover.style.display = 'flex';
    _fieldsPopoverOpen = true;

    const searchInput = popover.querySelector('.fields-popover-search');
    if (searchInput) {
      setTimeout(() => searchInput.focus(), 50);
    }

    const _handleOutsideClick = (ev) => {
      if (popover && !popover.contains(ev.target) && (!btn || !btn.contains(ev.target))) {
        closeFieldsModal();
        document.removeEventListener('click', _handleOutsideClick);
      }
    };

    setTimeout(() => {
      document.addEventListener('click', _handleOutsideClick);
    }, 10);
  }

  function _renderFieldsPopoverContent(popover) {
    if (!popover) return;
    const q = _fieldsSearchQuery.toLowerCase().trim();

    const filtered = ALL_AVAILABLE_FIELDS.filter(f => {
      if (!q) return true;
      return f.toLowerCase().includes(q);
    });

    popover.innerHTML = `
      <div class="discover-fields-popover-arrow arrow-bottom"></div>
      <div class="fields-popover-search-wrap">
        <input type="text" class="fields-popover-search" placeholder="Search" value="${_fieldsSearchQuery}" />
      </div>
      <div class="fields-popover-list">
        ${filtered.map(f => {
          const isActive = _visibleColumns.includes(f) || (f === '@timestamp' || f === '@version');
          return `
            <div class="fields-popover-item ${isActive ? 'active' : ''}" data-field="${f}">
              <div class="field-switch-track">
                <span class="field-switch-knob"></span>
              </div>
              <span class="field-item-name" title="${f}">${f}</span>
            </div>
          `;
        }).join('')}
      </div>
    `;

    const searchInput = popover.querySelector('.fields-popover-search');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        _fieldsSearchQuery = e.target.value;
        const listEl = popover.querySelector('.fields-popover-list');
        if (listEl) {
          const newFiltered = ALL_AVAILABLE_FIELDS.filter(f => f.toLowerCase().includes(_fieldsSearchQuery.toLowerCase().trim()));
          listEl.innerHTML = newFiltered.map(f => {
            const isActive = _visibleColumns.includes(f) || (f === '@timestamp' || f === '@version');
            return `
              <div class="fields-popover-item ${isActive ? 'active' : ''}" data-field="${f}">
                <div class="field-switch-track">
                  <span class="field-switch-knob"></span>
                </div>
                <span class="field-item-name" title="${f}">${f}</span>
              </div>
            `;
          }).join('');
          _bindFieldItemClicks(popover);
        }
      });
    }

    _bindFieldItemClicks(popover);
  }

  function _bindFieldItemClicks(popover) {
    if (!popover) return;
    popover.querySelectorAll('.fields-popover-item').forEach(item => {
      item.addEventListener('click', (e) => {
        e.stopPropagation();
        const field = item.getAttribute('data-field');
        if (!field) return;

        if (_visibleColumns.includes(field)) {
          if (_visibleColumns.length > 1) {
            _visibleColumns = _visibleColumns.filter(c => c !== field);
            item.classList.remove('active');
          }
        } else {
          _visibleColumns.push(field);
          item.classList.add('active');
        }

        const colsPopover = document.getElementById('discover-columns-popover');
        if (colsPopover && typeof _renderColumnsPopoverContent === 'function') {
          _renderColumnsPopoverContent(colsPopover);
        }

        renderTableAndPagination();
      });
    });
  }

  function openFieldsModal(e) {
    toggleFieldsPopover(e);
  }

  function closeFieldsModal() {
    const popover = document.getElementById('discover-fields-popover');
    if (popover) popover.style.display = 'none';
    const btn = document.getElementById('discover-fields-btn');
    if (btn) btn.classList.remove('active');
    _fieldsPopoverOpen = false;
  }

  function filterFieldsList(query) {
    _fieldsSearchQuery = query || '';
    const popover = document.getElementById('discover-fields-popover');
    if (popover) _renderFieldsPopoverContent(popover);
  }

  function addFieldAsColumn(key) {
    if (!_visibleColumns.includes(key)) {
      _visibleColumns.push(key);
      renderTableAndPagination();
    }
  }

  /* ── DISCOVER SORT POPOVER ────────────────────────────── */
  let _sortPopoverOpen = false;

  function _getFieldTypeIcon(field) {
    if (!field) return 'a';
    if (field.includes('time') || field.includes('date')) return 't';
    if (field.includes('level') || field.includes('id') || field.includes('port') || field.includes('count') || field.includes('code')) return '#';
    return 't';
  }

  function toggleSortPopover(e) {
    if (e) e.stopPropagation();
    const btn = document.getElementById('discover-sort-btn');
    let popover = document.getElementById('discover-sort-popover');

    if (_sortPopoverOpen && popover && popover.style.display !== 'none') {
      closeSortModal();
      return;
    }

    if (!popover) {
      popover = document.createElement('div');
      popover.id = 'discover-sort-popover';
      popover.className = 'discover-sort-popover';
      document.body.appendChild(popover);
    }

    _renderSortPopoverContent(popover);

    if (btn) {
      const rect = btn.getBoundingClientRect();
      const popW = 330;
      const left = Math.max(10, Math.min(window.innerWidth - popW - 10, rect.left + (rect.width / 2) - 42));
      const top = rect.bottom + 8;

      popover.style.left = `${left}px`;
      popover.style.top = `${top}px`;
      btn.classList.add('active');
    }

    popover.style.display = 'flex';
    _sortPopoverOpen = true;

    const _handleOutsideClick = (ev) => {
      if (popover && !popover.contains(ev.target) && (!btn || !btn.contains(ev.target))) {
        closeSortModal();
        document.removeEventListener('click', _handleOutsideClick);
      }
    };

    setTimeout(() => {
      document.addEventListener('click', _handleOutsideClick);
    }, 10);
  }

  function _renderSortPopoverContent(popover) {
    if (!popover) return;
    const hasField = Boolean(_sortConfig && _sortConfig.field);
    const fieldName = hasField ? _sortConfig.field : 'timestamp';
    const isAsc = _sortConfig && _sortConfig.direction === 'asc';
    const typeIcon = _getFieldTypeIcon(fieldName);

    popover.innerHTML = `
      <div class="discover-sort-popover-arrow"></div>
      ${hasField ? `
        <div class="sort-item-card">
          <button class="sort-remove-btn" id="sort-btn-remove" title="Remove sort field">&times;</button>
          <span class="sort-type-badge">${typeIcon}</span>
          <span class="sort-field-name" title="${fieldName}">${fieldName}</span>
          <div class="sort-dir-group">
            <button class="sort-dir-btn ${isAsc ? 'active' : ''}" id="sort-btn-asc">A-Z</button>
            <button class="sort-dir-btn ${!isAsc ? 'active' : ''}" id="sort-btn-desc">Z-A</button>
          </div>
          <span class="sort-drag-handle">
            <svg width="14" height="10" viewBox="0 0 14 10" fill="none" stroke="#64748b" stroke-width="1.5" stroke-linecap="round">
              <line x1="1" y1="3" x2="13" y2="3"></line>
              <line x1="1" y1="7" x2="13" y2="7"></line>
            </svg>
          </span>
        </div>
      ` : `
        <div style="font-size:12.5px; color:#94a3b8; padding:6px 4px; text-align:center;">No fields currently sorted</div>
      `}
      <div class="sort-popover-footer">
        <button class="sort-action-link" id="sort-btn-pick">
          Pick fields to sort by <svg width="10" height="6" viewBox="0 0 10 6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M1 1l4 4 4-4"/></svg>
        </button>
        <button class="sort-action-link" id="sort-btn-clear">Clear sorting</button>
        <div class="sort-field-dropdown" id="sort-field-dropdown">
          ${ALL_AVAILABLE_FIELDS.slice(0, 30).map(f => `
            <div class="sort-field-option" data-field="${f}">
              <span class="sort-type-badge">${_getFieldTypeIcon(f)}</span>
              <span>${f}</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;

    const removeBtn = popover.querySelector('#sort-btn-remove');
    if (removeBtn) {
      removeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        clearSorting();
      });
    }

    const ascBtn = popover.querySelector('#sort-btn-asc');
    if (ascBtn) {
      ascBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        setSortDirection('asc');
      });
    }

    const descBtn = popover.querySelector('#sort-btn-desc');
    if (descBtn) {
      descBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        setSortDirection('desc');
      });
    }

    const clearBtn = popover.querySelector('#sort-btn-clear');
    if (clearBtn) {
      clearBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        clearSorting();
      });
    }

    const pickBtn = popover.querySelector('#sort-btn-pick');
    const dropdown = popover.querySelector('#sort-field-dropdown');
    if (pickBtn && dropdown) {
      pickBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
      });

      dropdown.querySelectorAll('.sort-field-option').forEach(opt => {
        opt.addEventListener('click', (e) => {
          e.stopPropagation();
          const f = opt.getAttribute('data-field');
          if (f) {
            setSortField(f);
            dropdown.style.display = 'none';
          }
        });
      });
    }
  }

  function setSortDirection(dir) {
    if (!_sortConfig.field) _sortConfig.field = 'timestamp';
    _sortConfig.direction = dir;
    _updateSortLabel();
    const popover = document.getElementById('discover-sort-popover');
    if (popover) _renderSortPopoverContent(popover);
    renderTableAndPagination();
  }

  function setSortField(f) {
    _sortConfig.field = f;
    if (!_sortConfig.direction) _sortConfig.direction = 'desc';
    _updateSortLabel();
    const popover = document.getElementById('discover-sort-popover');
    if (popover) _renderSortPopoverContent(popover);
    renderTableAndPagination();
  }

  function clearSorting() {
    _sortConfig = { field: null, direction: 'desc' };
    _updateSortLabel();
    const popover = document.getElementById('discover-sort-popover');
    if (popover) _renderSortPopoverContent(popover);
    renderTableAndPagination();
  }

  function _updateSortLabel() {
    const label = document.getElementById('discover-sort-label');
    if (label) {
      label.textContent = _sortConfig && _sortConfig.field ? '1 fields sorted' : '0 fields sorted';
    }
  }

  function openSortModal(e) {
    toggleSortPopover(e);
  }

  function closeSortModal() {
    const popover = document.getElementById('discover-sort-popover');
    if (popover) popover.style.display = 'none';
    const btn = document.getElementById('discover-sort-btn');
    if (btn) btn.classList.remove('active');
    _sortPopoverOpen = false;
  }

  function sortByColumn(col) {
    if (_sortConfig.field === col) {
      _sortConfig.direction = _sortConfig.direction === 'asc' ? 'desc' : 'asc';
    } else {
      _sortConfig.field = col;
      _sortConfig.direction = 'desc';
    }
    _updateSortLabel();
    const popover = document.getElementById('discover-sort-popover');
    if (popover) _renderSortPopoverContent(popover);
    renderTableAndPagination();
  }

  /* ── DISCOVER SHOW DATES POPOVER ────────────────────────── */
  let _datesPopoverOpen = false;
  const TIME_SLOTS = [
    '00:00', '00:30', '01:00', '01:30', '02:00', '02:30', '03:00', '03:30',
    '04:00', '04:30', '05:00', '05:30', '06:00', '06:30', '07:00', '07:30',
    '08:00', '08:30', '09:00', '09:30', '10:00', '10:30', '11:00', '11:30',
    '12:00', '12:30', '13:00', '13:30', '14:00', '14:30', '15:00', '15:30',
    '16:00', '16:30', '17:00', '17:30', '18:00', '18:30', '19:00', '19:30',
    '20:00', '20:30', '21:00', '21:30', '22:00', '22:30', '23:00', '23:30'
  ];

  let _datesState = {
    tab: 'absolute',
    relNum: 1,
    relUnit: 'd',
    relRound: false,
    calYear: 2026,
    calMonth: 7, // August (0-indexed)
    selectedDay: 23,
    selectedTime: '10:00',
    exactMs: '10:14:19.615'
  };

  function toggleDatesPopover(e) {
    if (e) e.stopPropagation();
    const btn = document.getElementById('discover-show-dates-btn');
    let popover = document.getElementById('discover-dates-popover');

    if (_datesPopoverOpen && popover && popover.style.display !== 'none') {
      closeDatesModal();
      return;
    }

    if (!popover) {
      popover = document.createElement('div');
      popover.id = 'discover-dates-popover';
      popover.className = 'discover-dates-popover';
      document.body.appendChild(popover);
    }

    _renderDatesPopoverContent(popover);

    if (btn) {
      const rect = btn.getBoundingClientRect();
      const popW = 380;
      const left = Math.max(10, Math.min(window.innerWidth - popW - 10, rect.left + (rect.width / 2) - 60));
      const top = rect.bottom + 8;

      popover.style.left = `${left}px`;
      popover.style.top = `${top}px`;
      btn.classList.add('active');
    }

    popover.style.display = 'flex';
    _datesPopoverOpen = true;

    const _handleOutsideClick = (ev) => {
      if (popover && !popover.contains(ev.target) && (!btn || !btn.contains(ev.target))) {
        closeDatesModal();
        document.removeEventListener('click', _handleOutsideClick);
      }
    };

    setTimeout(() => {
      document.addEventListener('click', _handleOutsideClick);
    }, 10);
  }

  function _computeRelativeMs(num, unit) {
    const n = Math.max(1, parseInt(num, 10) || 1);
    switch (unit) {
      case 's': return n * 1000;
      case 'm': return n * 60 * 1000;
      case 'h': return n * 60 * 60 * 1000;
      case 'd': return n * 24 * 60 * 60 * 1000;
      case 'w': return n * 7 * 24 * 60 * 60 * 1000;
      case 'M': return n * 30 * 24 * 60 * 60 * 1000;
      case 'y': return n * 365 * 24 * 60 * 60 * 1000;
      default: return n * 24 * 60 * 60 * 1000;
    }
  }

  function _buildCalendarHtml(year, month, selectedDay) {
    const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
    const firstDayIndex = new Date(year, month, 1).getDay();
    const lastDate = new Date(year, month + 1, 0).getDate();
    const prevMonthLastDate = new Date(year, month, 0).getDate();

    let rowsHtml = '';
    let dayCounter = 1;
    let nextMonthDay = 1;

    for (let r = 0; r < 6; r++) {
      let cellsHtml = '';
      for (let d = 0; d < 7; d++) {
        const cellIndex = r * 7 + d;
        if (cellIndex < firstDayIndex) {
          const prevDay = prevMonthLastDate - (firstDayIndex - cellIndex - 1);
          cellsHtml += `<td><div class="dates-cal-day muted" data-action="prev-month-day">${prevDay}</div></td>`;
        } else if (dayCounter <= lastDate) {
          const isSelected = dayCounter === selectedDay;
          const isToday = (dayCounter === 24 && month === 7 && year === 2026);
          cellsHtml += `<td><div class="dates-cal-day ${isSelected ? 'selected' : ''} ${isToday ? 'today' : ''}" data-day="${dayCounter}">${dayCounter}</div></td>`;
          dayCounter++;
        } else {
          cellsHtml += `<td><div class="dates-cal-day muted" data-action="next-month-day">${nextMonthDay}</div></td>`;
          nextMonthDay++;
        }
      }
      rowsHtml += `<tr>${cellsHtml}</tr>`;
      if (dayCounter > lastDate && r >= 4) break;
    }

    return `
      <div class="dates-cal-wrap">
        <div class="dates-cal-header">
          <button class="dates-cal-nav-btn" id="dates-cal-prev">&lt;</button>
          <div class="dates-cal-title">${monthNames[month]} <span>${year}</span></div>
          <button class="dates-cal-nav-btn" id="dates-cal-next">&gt;</button>
        </div>
        <table class="dates-cal-table">
          <thead>
            <tr>
              <th>SU</th><th>MO</th><th>TU</th><th>WE</th><th>TH</th><th>FR</th><th>SA</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml}
          </tbody>
        </table>
      </div>
    `;
  }

  function _renderDatesPopoverContent(popover) {
    if (!popover) return;
    const { tab, relNum, relUnit, relRound, calYear, calMonth, selectedDay, selectedTime } = _datesState;
    const now = Date.now();

    let startFormatted = '';
    if (tab === 'relative') {
      const durationMs = _computeRelativeMs(relNum, relUnit);
      let startDate = new Date(now - durationMs);
      if (relRound && relUnit === 'd') {
        startDate = new Date(startDate.getFullYear(), startDate.getMonth(), startDate.getDate(), 0, 0, 0, 0);
      }
      startFormatted = _formatKibanaDate(startDate);
    } else {
      const [hStr, mStr] = (selectedTime || '10:00').split(':');
      const h = parseInt(hStr || '10', 10);
      const m = parseInt(mStr || '00', 10);
      const sDate = new Date(calYear, calMonth, selectedDay, h, m, 19, 615);
      startFormatted = _formatKibanaDate(sDate);
    }

    popover.innerHTML = `
      <div class="discover-dates-popover-arrow"></div>
      <div class="dates-tabs-header">
        <button class="dates-tab-btn ${tab === 'absolute' ? 'active' : ''}" data-tab="absolute">Absolute</button>
        <button class="dates-tab-btn ${tab === 'relative' ? 'active' : ''}" data-tab="relative">Relative</button>
        <button class="dates-tab-btn ${tab === 'now' ? 'active' : ''}" data-tab="now">Now</button>
      </div>

      ${tab === 'absolute' ? `
        <div class="dates-tab-content">
          <div class="dates-abs-grid">
            ${_buildCalendarHtml(calYear, calMonth, selectedDay)}
            <div class="dates-time-col" id="dates-time-list">
              ${TIME_SLOTS.map(t => `
                <div class="dates-time-item ${t === selectedTime ? 'selected' : ''}" data-time="${t}">${t}</div>
              `).join('')}
            </div>
          </div>

          <div class="dates-preview-box">
            <span class="dates-preview-label">Start date</span>
            <span class="dates-preview-val" id="dates-preview-text">${startFormatted}</span>
          </div>
        </div>
      ` : tab === 'relative' ? `
        <div class="dates-tab-content">
          <div class="dates-inputs-row">
            <input type="number" id="dates-rel-num" class="dates-num-input" value="${relNum}" min="1" />
            <select id="dates-rel-unit" class="dates-unit-select">
              <option value="s" ${relUnit === 's' ? 'selected' : ''}>Seconds ago</option>
              <option value="m" ${relUnit === 'm' ? 'selected' : ''}>Minutes ago</option>
              <option value="h" ${relUnit === 'h' ? 'selected' : ''}>Hours ago</option>
              <option value="d" ${relUnit === 'd' ? 'selected' : ''}>Days ago</option>
              <option value="w" ${relUnit === 'w' ? 'selected' : ''}>Weeks ago</option>
              <option value="M" ${relUnit === 'M' ? 'selected' : ''}>Months ago</option>
              <option value="y" ${relUnit === 'y' ? 'selected' : ''}>Years ago</option>
            </select>
          </div>

          <div class="dates-round-row" id="dates-round-toggle">
            <div class="dates-round-switch ${relRound ? 'active' : ''}">
              <span class="dates-round-knob">${relRound ? '' : '&times;'}</span>
            </div>
            <span>Round to the day</span>
          </div>

          <div class="dates-preview-box">
            <span class="dates-preview-label">Start date</span>
            <span class="dates-preview-val" id="dates-preview-text">${startFormatted}</span>
          </div>
        </div>
      ` : `
        <div class="dates-tab-content">
          <p style="font-size:12.5px; color:#475569; margin:0 0 8px 0;">Set end time relative to right now:</p>
          <button class="btn-kibana btn-kibana--primary" id="dates-now-apply">Set to now</button>
        </div>
      `}
    `;

    // Tab buttons
    popover.querySelectorAll('.dates-tab-btn').forEach(tabBtn => {
      tabBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        _datesState.tab = tabBtn.getAttribute('data-tab');
        _renderDatesPopoverContent(popover);
      });
    });

    // Absolute Calendar navigation & selection
    if (tab === 'absolute') {
      const prevMonthBtn = popover.querySelector('#dates-cal-prev');
      const nextMonthBtn = popover.querySelector('#dates-cal-next');

      if (prevMonthBtn) {
        prevMonthBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          if (_datesState.calMonth === 0) {
            _datesState.calMonth = 11;
            _datesState.calYear--;
          } else {
            _datesState.calMonth--;
          }
          _renderDatesPopoverContent(popover);
        });
      }

      if (nextMonthBtn) {
        nextMonthBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          if (_datesState.calMonth === 11) {
            _datesState.calMonth = 0;
            _datesState.calYear++;
          } else {
            _datesState.calMonth++;
          }
          _renderDatesPopoverContent(popover);
        });
      }

      popover.querySelectorAll('.dates-cal-day[data-day]').forEach(dayEl => {
        dayEl.addEventListener('click', (e) => {
          e.stopPropagation();
          const d = parseInt(dayEl.getAttribute('data-day'), 10);
          if (!isNaN(d)) {
            _datesState.selectedDay = d;
            _applyAbsoluteChange();
          }
        });
      });

      popover.querySelectorAll('.dates-time-item').forEach(tEl => {
        tEl.addEventListener('click', (e) => {
          e.stopPropagation();
          const t = tEl.getAttribute('data-time');
          if (t) {
            _datesState.selectedTime = t;
            _applyAbsoluteChange();
          }
        });
      });

      // Scroll selected time into view
      const selectedTimeEl = popover.querySelector('.dates-time-item.selected');
      if (selectedTimeEl) {
        setTimeout(() => {
          selectedTimeEl.scrollIntoView({ block: 'center', behavior: 'smooth' });
        }, 50);
      }
    }

    // Relative handlers
    if (tab === 'relative') {
      const numInput = popover.querySelector('#dates-rel-num');
      const unitSelect = popover.querySelector('#dates-rel-unit');
      const roundToggle = popover.querySelector('#dates-round-toggle');

      if (numInput) numInput.addEventListener('input', _applyRelativeChange);
      if (unitSelect) unitSelect.addEventListener('change', _applyRelativeChange);
      if (roundToggle) {
        roundToggle.addEventListener('click', (e) => {
          e.stopPropagation();
          _datesState.relRound = !_datesState.relRound;
          _renderDatesPopoverContent(popover);
          _applyRelativeChange();
        });
      }
    }

    const _applyAbsoluteChange = () => {
      const [hStr, mStr] = (_datesState.selectedTime || '10:00').split(':');
      const h = parseInt(hStr || '10', 10);
      const m = parseInt(mStr || '00', 10);
      const sDate = new Date(_datesState.calYear, _datesState.calMonth, _datesState.selectedDay, h, m, 19, 615);
      const formatted = _formatKibanaDate(sDate);

      const previewText = popover.querySelector('#dates-preview-text');
      if (previewText) previewText.textContent = formatted;

      if (window.TimeRangePicker && typeof window.TimeRangePicker.setAbsolute === 'function') {
        window.TimeRangePicker.setAbsolute(sDate, new Date());
      }

      const btn = document.getElementById('discover-show-dates-btn');
      if (btn) {
        btn.textContent = `${formatted} \u2192 now`;
      }

      _renderDatesPopoverContent(popover);
      fetchDataAndRender();
    };

    const _applyRelativeChange = () => {
      const numInput = popover.querySelector('#dates-rel-num');
      const unitSelect = popover.querySelector('#dates-rel-unit');

      _datesState.relNum = Math.max(1, parseInt(numInput?.value || 1, 10));
      _datesState.relUnit = unitSelect?.value || 'd';
      
      const newDurationMs = _computeRelativeMs(_datesState.relNum, _datesState.relUnit);
      let sDate = new Date(Date.now() - newDurationMs);
      if (_datesState.relRound && _datesState.relUnit === 'd') {
        sDate = new Date(sDate.getFullYear(), sDate.getMonth(), sDate.getDate(), 0, 0, 0, 0);
      }

      const previewText = popover.querySelector('#dates-preview-text');
      if (previewText) previewText.textContent = _formatKibanaDate(sDate);

      if (window.TimeRangePicker && typeof window.TimeRangePicker.setAbsolute === 'function') {
        window.TimeRangePicker.setAbsolute(sDate, new Date());
      }

      const btn = document.getElementById('discover-show-dates-btn');
      if (btn) {
        btn.textContent = `~ ${_datesState.relNum === 1 ? 'a' : _datesState.relNum} ${_datesState.relUnit === 'd' ? 'day' : _datesState.relUnit === 'h' ? 'hour' : _datesState.relUnit === 'm' ? 'minute' : 'day'}${_datesState.relNum > 1 ? 's' : ''} ago \u2192 now`;
      }

      fetchDataAndRender();
    };

    const nowApply = popover.querySelector('#dates-now-apply');
    if (nowApply) {
      nowApply.addEventListener('click', (e) => {
        e.stopPropagation();
        closeDatesModal();
        fetchDataAndRender();
      });
    }
  }

  function closeDatesModal() {
    const popover = document.getElementById('discover-dates-popover');
    if (popover) popover.style.display = 'none';
    const btn = document.getElementById('discover-show-dates-btn');
    if (btn) btn.classList.remove('active');
    _datesPopoverOpen = false;
  }

  /* ── DISCOVER TIME RANGE QUICK SELECT POPOVER ───────────── */
  let _timeRangePopoverOpen = false;
  let _trAutoRefreshTimer = null;
  let _trAutoRefreshSeconds = 0;

  const RECENT_RANGES = [
    { label: 'Aug 24, 2026 @ 10:26:43.203 to Aug 24, 2026 @ 10:26:44.203', from: new Date(Date.now() - 60000), to: new Date() },
    { label: 'Last 24 hours', from: new Date(Date.now() - 24 * 3600 * 1000), to: new Date() },
    { label: 'Aug 23, 2026 @ 09:00:00.000 to Aug 23, 2026 @ 09:30:00.000', from: new Date(Date.now() - 26 * 3600 * 1000), to: new Date(Date.now() - 25.5 * 3600 * 1000) },
    { label: 'Aug 18, 2026 @ 19:08:45.500 to Aug 18, 2026 @ 19:38:45.500', from: new Date(Date.now() - 6 * 24 * 3600 * 1000), to: new Date(Date.now() - 5.9 * 24 * 3600 * 1000) }
  ];

  function toggleTimeRangePopover(e) {
    if (e) e.stopPropagation();
    const btn = document.getElementById('discover-timerange-btn');
    let popover = document.getElementById('discover-timerange-popover');

    if (_timeRangePopoverOpen && popover && popover.style.display !== 'none') {
      closeTimeRangeModal();
      return;
    }

    if (!popover) {
      popover = document.createElement('div');
      popover.id = 'discover-timerange-popover';
      popover.className = 'discover-timerange-popover';
      document.body.appendChild(popover);
    }

    _renderTimeRangePopoverContent(popover);

    if (btn) {
      const rect = btn.getBoundingClientRect();
      const popW = 380;
      const left = Math.max(10, Math.min(window.innerWidth - popW - 10, rect.left));
      const top = rect.bottom + 8;

      popover.style.left = `${left}px`;
      popover.style.top = `${top}px`;
      btn.classList.add('active');
    }

    popover.style.display = 'flex';
    _timeRangePopoverOpen = true;

    const _handleOutsideClick = (ev) => {
      if (popover && !popover.contains(ev.target) && (!btn || !btn.contains(ev.target))) {
        closeTimeRangeModal();
        document.removeEventListener('click', _handleOutsideClick);
      }
    };

    setTimeout(() => {
      document.addEventListener('click', _handleOutsideClick);
    }, 10);
  }

  function _renderTimeRangePopoverContent(popover) {
    if (!popover) return;

    popover.innerHTML = `
      <div class="discover-timerange-popover-arrow"></div>

      <!-- 1. Quick select -->
      <div>
        <div class="tr-sec-header">
          <span>Quick select</span>
          <div class="tr-sec-nav">
            <button class="tr-sec-nav-btn" id="tr-nav-prev" title="Previous period">&lt;</button>
            <button class="tr-sec-nav-btn" id="tr-nav-next" title="Next period">&gt;</button>
          </div>
        </div>
        <div class="tr-ctrl-row">
          <select id="tr-quick-dir" class="tr-select tr-select-dir">
            <option value="last" selected>Last</option>
            <option value="next">Next</option>
          </select>
          <input type="number" id="tr-quick-num" class="tr-input" value="24" min="1" />
          <select id="tr-quick-unit" class="tr-select" style="flex:1;">
            <option value="s">seconds</option>
            <option value="m">minutes</option>
            <option value="h" selected>hours</option>
            <option value="d">days</option>
            <option value="w">weeks</option>
            <option value="M">months</option>
            <option value="y">years</option>
          </select>
          <button class="tr-apply-btn" id="tr-quick-apply">Apply</button>
        </div>
      </div>

      <div class="tr-divider"></div>

      <!-- 2. Commonly used -->
      <div>
        <div class="tr-sec-header">Commonly used</div>
        <div class="tr-common-grid">
          <a class="tr-link" data-range="today">Today</a>
          <a class="tr-link" data-range="24h">Last 24 hours</a>
          <a class="tr-link" data-range="this-week">This week</a>
          <a class="tr-link" data-range="7d">Last 7 days</a>
          <a class="tr-link" data-range="15m">Last 15 minutes</a>
          <a class="tr-link" data-range="30d">Last 30 days</a>
          <a class="tr-link" data-range="30m">Last 30 minutes</a>
          <a class="tr-link" data-range="90d">Last 90 days</a>
          <a class="tr-link" data-range="1h">Last 1 hour</a>
          <a class="tr-link" data-range="1y">Last 1 year</a>
        </div>
      </div>

      <div class="tr-divider"></div>

      <!-- 3. Recently used date ranges -->
      <div>
        <div class="tr-sec-header">Recently used date ranges</div>
        <div class="tr-recent-list">
          ${RECENT_RANGES.map((r, i) => `
            <a class="tr-link tr-recent-link" data-idx="${i}" title="${r.label}">${r.label}</a>
          `).join('')}
        </div>
      </div>

      <div class="tr-divider"></div>

      <!-- 4. Refresh every -->
      <div>
        <div class="tr-sec-header">Refresh every</div>
        <div class="tr-ctrl-row">
          <input type="number" id="tr-refresh-num" class="tr-input" value="${_trAutoRefreshSeconds || 0}" min="0" />
          <select id="tr-refresh-unit" class="tr-select" style="flex:1;">
            <option value="1">seconds</option>
            <option value="60">minutes</option>
            <option value="3600">hours</option>
          </select>
          <button class="tr-start-btn ${_trAutoRefreshTimer ? 'running' : ''}" id="tr-refresh-start">
            ${_trAutoRefreshTimer ? '&#9632; Pause' : '&#9655; Start'}
          </button>
        </div>
      </div>
    `;

    // Navigation buttons
    const prevBtn = popover.querySelector('#tr-nav-prev');
    const nextBtn = popover.querySelector('#tr-nav-next');
    if (prevBtn) {
      prevBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const trPrev = document.getElementById('tr-prev');
        if (trPrev) trPrev.click();
        fetchDataAndRender(true);
      });
    }
    if (nextBtn) {
      nextBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const trNext = document.getElementById('tr-next');
        if (trNext) trNext.click();
        fetchDataAndRender(true);
      });
    }

    // Apply quick select
    const applyBtn = popover.querySelector('#tr-quick-apply');
    if (applyBtn) {
      applyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const num = parseInt(popover.querySelector('#tr-quick-num')?.value || 24, 10);
        const unit = popover.querySelector('#tr-quick-unit')?.value || 'h';
        const ms = _computeRelativeMs(num, unit);
        const fromDate = new Date(Date.now() - ms);
        const toDate = new Date();
        const unitLabel = unit === 'h' ? 'hours' : unit === 'm' ? 'minutes' : unit === 'd' ? 'days' : 'hours';
        const label = `Last ${num} ${unitLabel}`;

        _applyTimeRangeSelection(fromDate, toDate, label);
        closeTimeRangeModal();
      });
    }

    // Commonly used links
    popover.querySelectorAll('.tr-common-grid .tr-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.stopPropagation();
        const code = link.getAttribute('data-range');
        const text = link.textContent.trim();
        let fromDate = new Date();
        let toDate = new Date();

        if (code === '15m') fromDate = new Date(Date.now() - 15 * 60 * 1000);
        else if (code === '30m') fromDate = new Date(Date.now() - 30 * 60 * 1000);
        else if (code === '1h') fromDate = new Date(Date.now() - 60 * 60 * 1000);
        else if (code === '24h') fromDate = new Date(Date.now() - 24 * 3600 * 1000);
        else if (code === '7d') fromDate = new Date(Date.now() - 7 * 24 * 3600 * 1000);
        else if (code === '30d') fromDate = new Date(Date.now() - 30 * 24 * 3600 * 1000);
        else if (code === '90d') fromDate = new Date(Date.now() - 90 * 24 * 3600 * 1000);
        else if (code === '1y') fromDate = new Date(Date.now() - 365 * 24 * 3600 * 1000);
        else if (code === 'today') {
          fromDate = new Date();
          fromDate.setHours(0, 0, 0, 0);
        } else if (code === 'this-week') {
          fromDate = new Date();
          fromDate.setDate(fromDate.getDate() - fromDate.getDay());
          fromDate.setHours(0, 0, 0, 0);
        }

        _applyTimeRangeSelection(fromDate, toDate, text);
        closeTimeRangeModal();
      });
    });

    // Recent links
    popover.querySelectorAll('.tr-recent-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.stopPropagation();
        const idx = parseInt(link.getAttribute('data-idx'), 10);
        const r = RECENT_RANGES[idx];
        if (r) {
          _applyTimeRangeSelection(r.from, r.to, r.label);
          closeTimeRangeModal();
        }
      });
    });

    // Auto-refresh Start / Pause
    const startBtn = popover.querySelector('#tr-refresh-start');
    if (startBtn) {
      startBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (_trAutoRefreshTimer) {
          clearInterval(_trAutoRefreshTimer);
          _trAutoRefreshTimer = null;
          _trAutoRefreshSeconds = 0;
          if (window.Toast) window.Toast.show({ type: 'info', title: 'Auto-refresh', body: 'Paused auto refresh' });
        } else {
          const num = parseInt(popover.querySelector('#tr-refresh-num')?.value || 10, 10);
          const mult = parseInt(popover.querySelector('#tr-refresh-unit')?.value || 1, 10);
          const secs = Math.max(1, num * mult);
          _trAutoRefreshSeconds = secs;
          _trAutoRefreshTimer = setInterval(() => {
            fetchDataAndRender(false);
          }, secs * 1000);
          if (window.Toast) window.Toast.show({ type: 'success', title: 'Auto-refresh', body: `Refreshing every ${secs}s` });
        }
        _renderTimeRangePopoverContent(popover);
      });
    }
  }

  function _applyTimeRangeSelection(from, to, label) {
    const labelEl = document.getElementById('discover-time-label');
    if (labelEl) labelEl.textContent = label;

    if (window.TimeRangePicker && typeof window.TimeRangePicker.setAbsolute === 'function') {
      window.TimeRangePicker.setAbsolute(from, to);
    }

    const showDatesBtn = document.getElementById('discover-show-dates-btn');
    if (showDatesBtn) {
      showDatesBtn.textContent = `${_fmtDateShort(from)} \u2192 ${_fmtDateShort(to)}`;
    }

    fetchDataAndRender(true);
  }

  function closeTimeRangeModal() {
    const popover = document.getElementById('discover-timerange-popover');
    if (popover) popover.style.display = 'none';
    const btn = document.getElementById('discover-timerange-btn');
    if (btn) btn.classList.remove('active');
    _timeRangePopoverOpen = false;
  }

  function openExportModal() {
    let modal = document.getElementById('discover-export-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'discover-export-modal';
      modal.className = 'discover-modal-backdrop';
      document.body.appendChild(modal);
    }

    const filtered = getFilteredLogs();
    const count = filtered.length;

    modal.innerHTML = `
      <div class="discover-modal-card" style="max-width: 440px;">
        <div class="discover-modal-header">
          <h3>Export Formatted Events</h3>
          <button class="discover-modal-close" onclick="DiscoverController.closeExportModal()">&times;</button>
        </div>
        <div class="discover-modal-body">
          <p style="font-size:13px; color:#cbd5e1; margin-bottom:16px;">
            Exporting <strong>${count.toLocaleString()}</strong> matching log events in current time window.
          </p>
          <div style="display:flex; flex-direction:column; gap:10px;">
            <button class="btn-kibana" style="justify-content:flex-start; padding:10px 14px;" onclick="DiscoverController.exportLogs('json')">
              <i data-lucide="file-code" style="width:16px;height:16px;color:#38bdf8;"></i>
              <div>
                <strong style="color:#ffffff;display:block;">JSON Format (.json)</strong>
                <span style="font-size:11px;color:#94a3b8;">Full raw Wazuh & Elastic event documents</span>
              </div>
            </button>
            <button class="btn-kibana" style="justify-content:flex-start; padding:10px 14px;" onclick="DiscoverController.exportLogs('csv')">
              <i data-lucide="file-spreadsheet" style="width:16px;height:16px;color:#34d399;"></i>
              <div>
                <strong style="color:#ffffff;display:block;">CSV / Excel Spreadsheet (.csv)</strong>
                <span style="font-size:11px;color:#94a3b8;">Tabular export of currently visible columns</span>
              </div>
            </button>
          </div>
        </div>
        <div class="discover-modal-footer">
          <button class="btn-kibana" onclick="DiscoverController.closeExportModal()">Cancel</button>
        </div>
      </div>
    `;

    modal.style.display = 'flex';
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  function closeExportModal() {
    const modal = document.getElementById('discover-export-modal');
    if (modal) modal.style.display = 'none';
  }

  function exportLogs(format) {
    const logs = getFilteredLogs();
    closeExportModal();

    if (format === 'json') {
      const jsonStr = JSON.stringify(logs, null, 2);
      _downloadFile(jsonStr, `wazuh-discover-${Date.now()}.json`, 'application/json');
    } else {
      // CSV Format
      const headers = _visibleColumns;
      const rows = logs.map(log => {
        return headers.map(h => {
          let val = _extractFieldValue(log, h);
          val = String(val).replace(/"/g, '""');
          return `"${val}"`;
        }).join(',');
      });
      const csvContent = [headers.join(','), ...rows].join('\n');
      _downloadFile(csvContent, `wazuh-discover-${Date.now()}.csv`, 'text/csv;charset=utf-8;');
    }

    if (window.Toast) {
      window.Toast.show({
        type: 'success',
        title: 'Export Complete',
        body: `Exported ${logs.length} events as ${format.toUpperCase()}`,
        duration: 3000
      });
    }
  }

  function _downloadFile(content, fileName, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
  }

  function resetView() {
    _activeFilters = {
      search: '',
      fieldFilters: { 'agent.name': 'wazuh-server' },
    };
    _visibleColumns = ['timestamp', 'agent.name', 'rule.description', 'rule.level', 'rule.id'];
    _density = 'normal';
    _sortConfig = { field: 'timestamp', direction: 'desc' };
    _pagination.currentPage = 1;

    const searchInput = document.getElementById('discover-search-input');
    if (searchInput) searchInput.value = '';

    const sortLabel = document.getElementById('discover-sort-label');
    if (sortLabel) sortLabel.textContent = '1 fields sorted';

    const densityLabel = document.getElementById('discover-density-label');
    if (densityLabel) densityLabel.textContent = 'Density';

    const table = document.getElementById('discover-table');
    if (table) {
      table.classList.remove('density-compact', 'density-normal', 'density-expanded');
      table.classList.add('density-normal');
    }

    renderAll();

    if (window.Toast) {
      window.Toast.show({
        type: 'info',
        title: 'View Reset',
        body: 'Filters, columns, sort, and search reset to default',
        duration: 2500
      });
    }
  }

  function _cleanLogForDisplay(log) {
    if (!log || typeof log !== 'object') return log;
    const clean = {};
    for (const [k, v] of Object.entries(log)) {
      if (!k.startsWith('_')) {
        clean[k] = v;
      }
    }
    return clean;
  }

  function _renderDrawerKVTable(log) {
    const clean = _cleanLogForDisplay(log);
    const flattened = [];
    function _traverse(obj, prefix = '') {
      if (!obj || typeof obj !== 'object') return;
      for (const [k, v] of Object.entries(obj)) {
        if (k.startsWith('_')) continue;
        const fullKey = prefix ? `${prefix}.${k}` : k;
        if (v && typeof v === 'object' && !Array.isArray(v)) {
          _traverse(v, fullKey);
        } else {
          flattened.push({ key: fullKey, val: Array.isArray(v) ? JSON.stringify(v) : v });
        }
      }
    }
    _traverse(clean);

    let kvHtml = `<table class="kv-table">`;
    flattened.forEach(f => {
      kvHtml += `
        <tr>
          <td class="kv-actions">
            <button class="kv-btn-filter" title="Filter for value" onclick="DiscoverController.addFieldFilter('${f.key}', '${_escapeHtml(String(f.val))}')">+</button>
            <button class="kv-btn-filter neg" title="Filter out value" onclick="DiscoverController.removeFieldFilter('${f.key}')">-</button>
          </td>
          <td class="kv-key">${_escapeHtml(f.key)}</td>
          <td class="kv-val">${_escapeHtml(String(f.val))}</td>
        </tr>
      `;
    });
    kvHtml += `</table>`;
    return kvHtml;
  }

  function _renderDrawerJSONView(log) {
    const clean = _cleanLogForDisplay(log);
    const jsonStr = JSON.stringify(clean, null, 2);
    return `<div class="doc-json-view">${_escapeHtml(jsonStr)}</div>`;
  }

  function toggleRowExpand(globalIdx) {
    const logs = getSortedLogs(getFilteredLogs());
    const { currentPage, rowsPerPage } = _pagination;
    const startIdx = (currentPage - 1) * rowsPerPage;
    const log = logs[globalIdx];

    if (_expandedRowId === globalIdx) {
      // Close
      _expandedRowId = null;
      _closeDocSidePanel();
    } else {
      _expandedRowId = globalIdx;
      _openDocSidePanel(log, globalIdx);
    }
    // Re-render only to update active row highlight
    renderTableAndPagination();
  }

  function setDrawerTab(globalIdx, tab) {
    _activeDrawerTab[globalIdx] = tab;
    const panel = document.getElementById('doc-side-panel');
    if (panel) {
      const body = panel.querySelector('.dsp-body');
      if (body) {
        const logs = getSortedLogs(getFilteredLogs());
        const log = logs[globalIdx];
        if (log) {
          body.innerHTML = tab === 'table' ? _renderDrawerKVTable(log) : _renderDrawerJSONView(log);
        }
      }
      panel.querySelectorAll('.dsp-tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tab);
      });
    }
  }

  /* ── Document Side Panel ─────────────────────────────────── */
  let _dspWidth = parseInt(localStorage.getItem('aegis_dsp_width') || '560', 10);
  if (isNaN(_dspWidth) || _dspWidth < 360) _dspWidth = 560;

  function _initDocSidePanelResizer(panel) {
    const handle = panel.querySelector('.dsp-resize-handle');
    if (!handle || handle._hasResizer) return;
    handle._hasResizer = true;

    let isResizing = false;
    let startX = 0;
    let startWidth = 0;

    const onMouseDown = (e) => {
      isResizing = true;
      startX = e.clientX;
      startWidth = panel.getBoundingClientRect().width;
      panel.classList.add('resizing');
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
      e.preventDefault();
      e.stopPropagation();
    };

    const onMouseMove = (e) => {
      if (!isResizing) return;
      // Dragging left increases width, dragging right decreases width
      const deltaX = startX - e.clientX;
      let newWidth = startWidth + deltaX;
      const minW = 360;
      const maxW = Math.min(window.innerWidth - 40, 1600);
      newWidth = Math.max(minW, Math.min(maxW, newWidth));
      panel.style.width = newWidth + 'px';
      _dspWidth = newWidth;
    };

    const onMouseUp = () => {
      if (!isResizing) return;
      isResizing = false;
      panel.classList.remove('resizing');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      try {
        localStorage.setItem('aegis_dsp_width', String(_dspWidth));
      } catch (_) {}
    };

    handle.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);
  }

  function _openDocSidePanel(log, globalIdx) {
    _ensureDocSidePanel();
    const panel = document.getElementById('doc-side-panel');
    if (!panel) return;

    // Apply persisted or default width
    panel.style.width = _dspWidth + 'px';

    const activeTab = _activeDrawerTab[globalIdx] || 'table';

    // Build inner content with resize handle and close button
    panel.innerHTML = `
      <div class="dsp-resize-handle" id="dsp-resize-handle" title="Drag left/right to resize"></div>
      <div class="dsp-header">
        <span class="dsp-title">Document Details</span>
        <div style="display:flex; align-items:center; gap:8px;">
          ${log.redmine_ticket
            ? `<a href="${log.redmine_ticket.url}" target="_blank" class="redmine-ticket-badge" style="font-size:12px; padding:3px 8px;" title="View Ticket on Redmine">🎟️ #${log.redmine_ticket.id}</a>`
            : `<button class="btn-dispatch-ticket" style="padding:4px 10px; font-size:12px;" onclick="window.RedmineDispatchController && RedmineDispatchController.openSingleModal(DiscoverController.getLogByGlobalIdx(${globalIdx}))"><i data-lucide="ticket"></i> Dispatch to Redmine</button>`}
          <button class="dsp-close-btn" id="dsp-close-btn" title="Close" onclick="DiscoverController.closeDocSidePanel()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
      </div>
      <div class="dsp-tabs">
        <button class="dsp-tab-btn ${activeTab === 'table' ? 'active' : ''}" data-tab="table"
                onclick="DiscoverController.setDrawerTab(${globalIdx}, 'table')">Table</button>
        <button class="dsp-tab-btn ${activeTab === 'json' ? 'active' : ''}" data-tab="json"
                onclick="DiscoverController.setDrawerTab(${globalIdx}, 'json')">JSON</button>
      </div>
      <div class="dsp-body">
        ${activeTab === 'table' ? _renderDrawerKVTable(log) : _renderDrawerJSONView(log)}
      </div>
    `;

    panel.classList.add('open');

    // Attach click handler directly to ensure button always works
    const closeBtn = panel.querySelector('.dsp-close-btn');
    if (closeBtn) {
      closeBtn.onclick = (e) => {
        if (e) {
          e.preventDefault();
          e.stopPropagation();
        }
        closeDocSidePanel();
      };
    }

    _initDocSidePanelResizer(panel);

    // Shrink table area when panel is open
    const tableCard = document.querySelector('.discover-table-card');
    if (tableCard) tableCard.classList.add('with-side-panel');
  }

  function _closeDocSidePanel() {
    const panel = document.getElementById('doc-side-panel');
    if (panel) panel.classList.remove('open');
    const tableCard = document.querySelector('.discover-table-card');
    if (tableCard) tableCard.classList.remove('with-side-panel');
  }

  function closeDocSidePanel() {
    _expandedRowId = null;
    _closeDocSidePanel();
    renderTableAndPagination();
  }

  function _ensureDocSidePanel() {
    if (document.getElementById('doc-side-panel')) return;
    const panel = document.createElement('div');
    panel.id = 'doc-side-panel';
    panel.className = 'doc-side-panel';
    panel.style.width = _dspWidth + 'px';
    // Attach inside #view-discover
    const discoverView = document.getElementById('view-discover');
    if (discoverView) {
      discoverView.appendChild(panel);
    } else {
      document.body.appendChild(panel);
    }

    // ESC key closes drawer
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && panel.classList.contains('open')) {
        closeDocSidePanel();
      }
    });
  }

  function viewSurroundingDocs(globalIdx) {
    if (window.Toast) window.Toast.show({ type: 'info', title: 'View Surrounding Documents', body: `Showing context for document #${globalIdx}`, duration: 2500 });
  }

  function viewSingleDoc(globalIdx) {
    if (window.Toast) window.Toast.show({ type: 'info', title: 'View Single Document', body: `Opening document #${globalIdx}`, duration: 2500 });
  }

  function setPage(p) {
    const logs = getSortedLogs(getFilteredLogs());
    const totalPages = Math.max(1, Math.ceil(logs.length / _pagination.rowsPerPage));
    _pagination.currentPage = Math.max(1, Math.min(totalPages, p));
    renderTableAndPagination();
  }

  function filterByRuleId(ruleId) {
    _activeFilters.fieldFilters['rule.id'] = ruleId;
    renderAll();
  }

  function showBarTooltip(e, timeStr, count) {
    let tip = document.getElementById('discover-bar-tooltip');
    if (!tip) {
      tip = document.createElement('div');
      tip.id = 'discover-bar-tooltip';
      tip.style.position = 'fixed';
      tip.style.zIndex = '999999';
      tip.style.background = 'rgba(15, 23, 42, 0.95)';
      tip.style.backdropFilter = 'blur(8px)';
      tip.style.border = '1px solid rgba(52, 211, 153, 0.35)';
      tip.style.borderRadius = '6px';
      tip.style.padding = '6px 12px';
      tip.style.color = '#ffffff';
      tip.style.fontSize = '12px';
      tip.style.pointerEvents = 'none';
      tip.style.whiteSpace = 'nowrap';
      tip.style.boxShadow = '0 8px 24px rgba(0,0,0,0.6)';
      document.body.appendChild(tip);
    }
    tip.innerHTML = `
      <div style="font-weight:600; color:#f8fafc;">${timeStr}: <span style="color:#34d399;">${count} hit${count === 1 ? '' : 's'}</span></div>
      <div style="font-size:10px; color:#94a3b8; margin-top:2px;">🔍 Click bar to zoom into this timeframe</div>
    `;
    tip.style.display = 'block';

    const tipRect = tip.getBoundingClientRect();
    const tipWidth = tipRect.width || 180;
    const tipHeight = tipRect.height || 42;

    // Smart horizontal placement: if near right edge, flip to left of cursor
    let left = e.clientX + 14;
    if (left + tipWidth > window.innerWidth - 16) {
      left = e.clientX - tipWidth - 14;
    }
    if (left < 10) left = 10;

    // Smart vertical placement
    let top = e.clientY - tipHeight - 10;
    if (top < 10) {
      top = e.clientY + 18;
    }

    tip.style.left = `${left}px`;
    tip.style.top = `${top}px`;
  }

  function hideBarTooltip() {
    const tip = document.getElementById('discover-bar-tooltip');
    if (tip) tip.style.display = 'none';
  }

  function zoomToBucket(startMs, endMs) {
    hideBarTooltip();
    const fromDate = new Date(startMs);
    const toDate = new Date(endMs);

    _discoverZoomRange = { from: fromDate, to: toDate };
    _pagination.currentPage = 1;
    renderAll();

    const timeLabel = `${fromDate.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'})} → ${toDate.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'})}`;
    if (window.Toast) {
      window.Toast.show({
        type: 'info',
        title: 'Discover Zoomed',
        body: `Locked to interval: ${timeLabel}`,
        duration: 1500,
      });
    }
  }

  function zoomIn() {
    let from, to;
    if (_discoverZoomRange && _discoverZoomRange.from && _discoverZoomRange.to) {
      from = _discoverZoomRange.from.getTime();
      to = _discoverZoomRange.to.getTime();
    } else if (window.TimeRangePicker && window.TimeRangePicker.getRange) {
      const r = window.TimeRangePicker.getRange();
      if (r && r.from && r.to) {
        from = r.from.getTime();
        to = r.to.getTime();
      }
    }
    if (!from || !to) {
      const now = Date.now();
      from = now - 24 * 3600 * 1000;
      to = now;
    }

    const dur = to - from;
    if (dur <= 10000) {
      if (window.Toast) window.Toast.show({ type: 'warn', title: 'Maximum Zoom', body: 'Already at maximum zoom level (10 seconds)', duration: 1500 });
      return;
    }
    const center = (from + to) / 2;
    const newHalf = dur / 4;
    const newFrom = new Date(center - newHalf);
    const newTo = new Date(center + newHalf);

    _discoverZoomRange = { from: newFrom, to: newTo };
    _pagination.currentPage = 1;
    renderAll();
  }

  function zoomOut() {
    let from, to;
    if (_discoverZoomRange && _discoverZoomRange.from && _discoverZoomRange.to) {
      from = _discoverZoomRange.from.getTime();
      to = _discoverZoomRange.to.getTime();
    } else if (window.TimeRangePicker && window.TimeRangePicker.getRange) {
      const r = window.TimeRangePicker.getRange();
      if (r && r.from && r.to) {
        from = r.from.getTime();
        to = r.to.getTime();
      }
    }
    if (!from || !to) {
      const now = Date.now();
      from = now - 24 * 3600 * 1000;
      to = now;
    }

    const dur = to - from;
    const center = (from + to) / 2;
    const newHalf = dur;
    const newFrom = new Date(center - newHalf);
    const newTo = new Date(Math.min(Date.now(), center + newHalf));

    _discoverZoomRange = { from: newFrom, to: newTo };
    _pagination.currentPage = 1;
    renderAll();
  }

  function zoomFitHits() {
    const times = _allLogs.map(l => new Date(l.timestamp || l.receivedAt).getTime()).filter(t => !isNaN(t)).sort((a, b) => a - b);
    if (times.length === 0) {
      if (window.Toast) window.Toast.show({ type: 'info', title: 'Fit Hits', body: 'No events found to fit view', duration: 1500 });
      return;
    }

    const minT = times[0];
    const maxT = times[times.length - 1];

    const newFrom = new Date(minT);
    const newTo = new Date(maxT > minT ? maxT : minT + 60000);

    _discoverZoomRange = { from: newFrom, to: newTo };
    _pagination.currentPage = 1;
    renderAll();

    if (window.Toast) {
      window.Toast.show({ type: 'success', title: 'Fit to Hits', body: `Zoomed to all ${_allLogs.length} events in Discover`, duration: 1500 });
    }
  }

  function resetZoom() {
    _discoverZoomRange = null;
    _pagination.currentPage = 1;
    renderAll();

    if (window.Toast) {
      window.Toast.show({ type: 'info', title: 'Discover Reset', body: 'Restored full view in Discover', duration: 1500 });
    }
  }

  function toggleSelectAll(checked) {
    const logs = getSortedLogs(getFilteredLogs());
    const { currentPage, rowsPerPage } = _pagination;
    const startIdx = (currentPage - 1) * rowsPerPage;
    const pageLogs = logs.slice(startIdx, startIdx + rowsPerPage);

    pageLogs.forEach((l, idx) => {
      const id = String(l.id || l._id || l.timestamp || (startIdx + idx));
      if (checked) _selectedLogIds.add(id);
      else _selectedLogIds.delete(id);
    });
    updateBatchToolbar();
    renderTableAndPagination();
  }

  function toggleSelectRow(id, checked) {
    if (checked) _selectedLogIds.add(String(id));
    else _selectedLogIds.delete(String(id));
    updateBatchToolbar();

    // Update row visual class
    const chk = document.querySelector(`.log-row-checkbox[value="${id}"]`);
    if (chk) {
      const row = chk.closest('tr');
      if (row) row.classList.toggle('row--selected', checked);
    }
  }

  function clearSelection() {
    _selectedLogIds.clear();
    updateBatchToolbar();
    renderTableAndPagination();
  }

  function updateBatchToolbar() {
    const toolbar = document.getElementById('discover-batch-toolbar');
    const countEl = document.getElementById('discover-selected-count');
    if (!toolbar) return;

    if (_selectedLogIds.size > 0) {
      toolbar.style.display = 'block';
      if (countEl) countEl.textContent = _selectedLogIds.size;
    } else {
      toolbar.style.display = 'none';
    }
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  function openBatchRedmineModal() {
    const all = getFilteredLogs();
    const selectedAlerts = all.filter((l, idx) => _selectedLogIds.has(String(l.id || l._id || l.timestamp || idx)));
    if (selectedAlerts.length === 0) {
      if (window.Toast) window.Toast.show({ type: 'warn', title: 'No Alerts Selected', body: 'Please select at least 1 alert to dispatch', duration: 2000 });
      return;
    }
    if (window.RedmineDispatchController) {
      window.RedmineDispatchController.openBatchModal(selectedAlerts);
    }
  }

  function getLogById(id) {
    const all = getFilteredLogs();
    return all.find((l, idx) => String(l.id || l._id || l.timestamp || idx) === String(id)) || null;
  }

  function getLogByGlobalIdx(idx) {
    const logs = getSortedLogs(getFilteredLogs());
    return logs[idx] || null;
  }

  function _escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function _debounce(fn, delay) {
    let t;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, args), delay);
    };
  }

  return {
    init,
    reload: fetchDataAndRender,
    renderAll,
    toggleFieldFilter,
    removeFieldFilter,
    addFieldFilter,
    openAddFilterModal,
    toggleRowExpand,
    setDrawerTab,
    setPage,
    filterByRuleId,
    openExportModal,
    closeExportModal,
    exportLogs,
    resetView,
    openFieldsModal,
    closeFieldsModal,
    filterFieldsList,
    addFieldAsColumn,
    openColumnsModal,
    closeColumnsModal,
    resetDefaultColumns,
    applyColumnsModal,
    toggleDensity,
    openSortModal,
    closeSortModal,
    applySortModal,
    sortByColumn,
    toggleFullscreen,
    showBarTooltip,
    hideBarTooltip,
    zoomToBucket,
    zoomIn,
    zoomOut,
    zoomFitHits,
    resetZoom,
    toggleSelectAll,
    toggleSelectRow,
    clearSelection,
    openBatchRedmineModal,
    getLogById,
    getLogByGlobalIdx,
    toggleDatesPopover,
    closeDatesModal,
    toggleTimeRangePopover,
    closeTimeRangeModal,
    viewSurroundingDocs,
    viewSingleDoc,
    closeDocSidePanel,
    toggleGroupDuplicates,
  };
})();

window.DiscoverController = DiscoverController;
