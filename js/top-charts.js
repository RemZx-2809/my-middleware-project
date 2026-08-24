/**
 * Aegis SOC — Top Dashboard Visualizations Controller
 * 
 * Computes and renders the 4 top overview charts directly from REAL ALERTS
 * stored in the middleware (/api/dashboard-data and SSE push events):
 * 
 * 1. Top 10 Alert level evolution (Stacked Area Chart)
 * 2. Top 10 MITRE ATT&CKS (Technique list or clean empty state)
 * 3. Top 5 agents (Donut Chart)
 * 4. Alerts evolution - Top 5 agents (Histogram / Bar Chart)
 * 
 * Includes interactive KPI card drilldown and Kibana "Select filters to apply" click popover modal.
 */

'use strict';

const TopChartsController = (() => {
  // Color Palette for Alert Levels (Wazuh / Kibana style)
  const LEVEL_COLORS = {
    '4':  '#50b59b', // Teal Green
    '11': '#d36086', // Coral / Rose
    '7':  '#8f63b8', // Lavender Purple
    '3':  '#48af9b', // Emerald
    '6':  '#6092cd', // Soft Blue
    '8':  '#e69f00', // Amber
    '12': '#e7664c', // Red Orange
    '10': '#cc79a7',
    '9':  '#d55e00',
    '13': '#c53929',
    '14': '#a51d24',
    '15': '#7c0000',
  };

  const AGENT_COLORS = [
    '#ca789a', // wazuh-server mauve / rose
    '#6092cd', // test-agent blue
    '#50b59b', // teal
    '#e69f00', // amber
    '#8f63b8', // purple
  ];

  let _allAlerts = [];
  let _activeTooltip = null;
  let _activeFieldFilters = {};
  let _activeKpiFilter = null; // 'level12' | 'auth_fail' | 'auth_success' | null

  function init() {
    _createTooltip();
    _initKpiClickHandlers();
    
    // Initial fetch from middleware API
    fetchDataAndRender();

    // Re-render when time range or data updates
    window.addEventListener('aegis:data-updated', fetchDataAndRender);
    window.addEventListener('resize', _debounce(renderAll, 120));

    // Live push events
    window.addEventListener('aegis:alerts-ingested', () => {
      fetchDataAndRender();
    });
  }

  function isAuthFailAlert(a) {
    const desc = (a?.rule?.description || '').toLowerCase();
    const groups = Array.isArray(a?.rule?.groups) ? a.rule.groups.map(g => String(g).toLowerCase()) : [];
    const fullLog = (a?.full_log || '').toLowerCase();
    const useCase = a?.aegis_use_case || '';

    return groups.some(g => g.includes('authentication_fail') || g.includes('invalid_login') || g === 'authentication_failed' || g === 'authentication_failures') ||
      /authentication fail|failed password|login fail|invalid user|pam_unix.*failure|access denied|bad password/i.test(desc) ||
      /authentication fail|failed password|invalid user|authentication error/i.test(fullLog) ||
      (useCase === 'auth_access_anomalies' && !/success|session open/i.test(desc));
  }

  function isAuthSuccessAlert(a) {
    const desc = (a?.rule?.description || '').toLowerCase();
    const groups = Array.isArray(a?.rule?.groups) ? a.rule.groups.map(g => String(g).toLowerCase()) : [];
    const fullLog = (a?.full_log || '').toLowerCase();

    return groups.some(g => g.includes('authentication_success') || g === 'session_opened') ||
      /authentication success|accepted password|accepted publickey|session opened|logged in|login successful/i.test(desc) ||
      /accepted password|session opened for user/i.test(fullLog);
  }

  function _initKpiClickHandlers() {
    const cardTotal = document.getElementById('kpi-ov-total');
    const cardLevel12 = document.getElementById('kpi-ov-level12');
    const cardAuthFail = document.getElementById('kpi-ov-auth-fail');
    const cardAuthSuccess = document.getElementById('kpi-ov-auth-success');

    if (cardTotal) {
      cardTotal.addEventListener('click', () => {
        resetAllFilters();
      });
    }

    if (cardLevel12) {
      cardLevel12.addEventListener('click', () => {
        if (_activeKpiFilter === 'level12') {
          // Toggle off
          removeFieldFilter('rule.level');
          _activeKpiFilter = null;
          if (window.PanelManager && typeof window.PanelManager.clearFilter === 'function') {
            window.PanelManager.clearFilter();
          }
        } else {
          _activeKpiFilter = 'level12';
          _activeFieldFilters['rule.level'] = '>= 12';
          delete _activeFieldFilters['rule.category'];
          if (window.PanelManager && typeof window.PanelManager.setFilter === 'function') {
            window.PanelManager.setFilter(a => parseInt(a?.rule?.level ?? 0, 10) >= 12);
          }
        }
        renderAll();
      });
    }

    if (cardAuthFail) {
      cardAuthFail.addEventListener('click', () => {
        if (_activeKpiFilter === 'auth_fail') {
          // Toggle off
          removeFieldFilter('rule.category');
          _activeKpiFilter = null;
          if (window.PanelManager && typeof window.PanelManager.clearFilter === 'function') {
            window.PanelManager.clearFilter();
          }
        } else {
          _activeKpiFilter = 'auth_fail';
          _activeFieldFilters['rule.category'] = 'Authentication failure';
          delete _activeFieldFilters['rule.level'];
          if (window.PanelManager && typeof window.PanelManager.setFilter === 'function') {
            window.PanelManager.setFilter(isAuthFailAlert);
          }
        }
        renderAll();
      });
    }

    if (cardAuthSuccess) {
      cardAuthSuccess.addEventListener('click', () => {
        if (_activeKpiFilter === 'auth_success') {
          // Toggle off
          removeFieldFilter('rule.category');
          _activeKpiFilter = null;
          if (window.PanelManager && typeof window.PanelManager.clearFilter === 'function') {
            window.PanelManager.clearFilter();
          }
        } else {
          _activeKpiFilter = 'auth_success';
          _activeFieldFilters['rule.category'] = 'Authentication success';
          delete _activeFieldFilters['rule.level'];
          if (window.PanelManager && typeof window.PanelManager.setFilter === 'function') {
            window.PanelManager.setFilter(isAuthSuccessAlert);
          }
        }
        renderAll();
      });
    }
  }

  function _updateKpiCardHighlight() {
    const cardTotal = document.getElementById('kpi-ov-total');
    const cardLevel12 = document.getElementById('kpi-ov-level12');
    const cardAuthFail = document.getElementById('kpi-ov-auth-fail');
    const cardAuthSuccess = document.getElementById('kpi-ov-auth-success');

    [cardTotal, cardLevel12, cardAuthFail, cardAuthSuccess].forEach(c => c?.classList.remove('active'));

    if (_activeKpiFilter === 'level12') {
      cardLevel12?.classList.add('active');
    } else if (_activeKpiFilter === 'auth_fail') {
      cardAuthFail?.classList.add('active');
    } else if (_activeKpiFilter === 'auth_success') {
      cardAuthSuccess?.classList.add('active');
    }
  }

  function _createTooltip() {
    let tip = document.getElementById('top-chart-tooltip');
    if (!tip) {
      tip = document.createElement('div');
      tip.id = 'top-chart-tooltip';
      tip.className = 'top-chart-tooltip';
      tip.style.display = 'none';
      document.body.appendChild(tip);
    }
    _activeTooltip = tip;
  }

  async function fetchDataAndRender() {
    try {
      let url = '/api/dashboard-data';
      if (window.TimeRangePicker && window.TimeRangePicker.getRange) {
        const r = window.TimeRangePicker.getRange();
        if (r && r.from && r.to) {
          url += `?from=${r.from.toISOString()}&to=${r.to.toISOString()}`;
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
      _allAlerts = flat;
      renderAll();
    } catch (e) {
      console.warn('[TopCharts] Failed to fetch dashboard data:', e.message);
      renderAll();
    }
  }

  function _getFilteredAlerts() {
    if (!_allAlerts || _allAlerts.length === 0) return [];
    const filterEntries = Object.entries(_activeFieldFilters);
    if (filterEntries.length === 0) return _allAlerts;

    return _allAlerts.filter(a => {
      return filterEntries.every(([field, val]) => {
        if (val === undefined || val === null || val === '') return true;
        const valStr = String(val).toLowerCase();
        
        if (field === 'rule.category') {
          if (val === 'Authentication failure') return isAuthFailAlert(a);
          if (val === 'Authentication success') return isAuthSuccessAlert(a);
        }
        if (field === 'agent.name') {
          const name = a?.agent?.name || 'wazuh-server';
          return String(name).toLowerCase() === valStr;
        }
        if (field === 'rule.level') {
          if (val === '>= 12') return parseInt(a?.rule?.level ?? 0, 10) >= 12;
          return String(a?.rule?.level) === String(val);
        }
        if (field === 'rule.mitre.id') {
          const mitre = a?.rule?.mitre;
          const ids = mitre?.id || (mitre?.tactic ? [mitre.tactic] : []);
          const arr = Array.isArray(ids) ? ids : [ids];
          return arr.some(x => String(x).toLowerCase() === valStr);
        }
        if (field === 'rule.id') {
          return String(a?.rule?.id) === String(val);
        }
        if (field === 'aegis_use_case') {
          return String(a?.aegis_use_case || '').toLowerCase() === valStr;
        }
        if (field === 'rule.groups') {
          const groups = Array.isArray(a?.rule?.groups) ? a.rule.groups : [];
          return groups.some(g => String(g).toLowerCase().includes(valStr));
        }
        return true;
      });
    });
  }

  function _renderActiveFilterRow() {
    const row = document.getElementById('top-chart-filter-row');
    if (!row) return;

    let html = '';
    const r = (window.TimeRangePicker && window.TimeRangePicker.getRange) ? window.TimeRangePicker.getRange() : null;
    const hasTimeFilter = r && r.from && r.to;

    if (hasTimeFilter) {
      const timeStr = `${_formatKibanaTimestamp(r.from)} → ${_formatKibanaTimestamp(r.to)}`;
      html += `
        <div class="filter-pill" style="border-color: rgba(59, 130, 246, 0.5); background: rgba(59, 130, 246, 0.16);">
          <span class="filter-pill-text">
            <svg style="width:13px;height:13px;color:#60a5fa;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="11" y1="8" x2="11" y2="14"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg>
            <span class="filter-pill-field">time:</span>
            <span class="filter-pill-val">${timeStr}</span>
          </span>
          <div class="filter-pill-actions">
            <button class="filter-pill-btn" title="Reset time zoom" onclick="TopChartsController.resetZoom()">&times;</button>
          </div>
        </div>
      `;
    }

    for (const [field, val] of Object.entries(_activeFieldFilters)) {
      if (val !== undefined && val !== null && val !== '') {
        const fieldName = field === 'rule.category' ? 'category' : field;
        html += `
          <div class="filter-pill">
            <span class="filter-pill-text">
              <span class="filter-pill-field">${fieldName}:</span>
              <span class="filter-pill-val">${val}</span>
            </span>
            <div class="filter-pill-actions">
              <button class="filter-pill-btn" title="Remove filter" onclick="TopChartsController.removeFieldFilter('${field}')">&times;</button>
            </div>
          </div>
        `;
      }
    }

    if (hasTimeFilter || Object.keys(_activeFieldFilters).length > 0) {
      html += `
        <button class="btn-reset-filters" onclick="TopChartsController.resetAllFilters()">
          <svg style="width:12px;height:12px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path><path d="M3 3v5h5"></path></svg>
          Reset all filters
        </button>
      `;
      row.innerHTML = html;
      row.style.display = 'flex';
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
      }
    } else {
      row.style.display = 'none';
      row.innerHTML = '';
    }
  }

  function renderAll() {
    _updateKpiCardHighlight();
    _renderActiveFilterRow();
    renderOverviewKpis();
    renderAlertLevelEvolution();
    renderMitreAttacks();
    renderTopAgents();
    renderAgentAlertsEvolution();
  }

  /* ══════════════════════════════════════════════════════════
     0. SECURITY OVERVIEW KPIS (Total, Level 12+, Auth Fail, Auth Success)
  ════════════════════════════════════════════════════════════ */
  function renderOverviewKpis() {
    // Total counters always calculated from total loaded alerts
    const total = _allAlerts.length;
    let level12Count = 0;
    let authFailCount = 0;
    let authSuccessCount = 0;

    _allAlerts.forEach(a => {
      const lvl = parseInt(a?.rule?.level ?? 0, 10);
      if (lvl >= 12) level12Count++;
      if (isAuthFailAlert(a)) authFailCount++;
      if (isAuthSuccessAlert(a)) authSuccessCount++;
    });

    const totalEl = document.getElementById('kpi-val-total');
    const lvl12El = document.getElementById('kpi-val-level12');
    const failEl = document.getElementById('kpi-val-auth-fail');
    const successEl = document.getElementById('kpi-val-auth-success');

    if (totalEl) totalEl.textContent = total.toLocaleString();
    if (lvl12El) lvl12El.textContent = level12Count.toLocaleString();
    if (failEl) failEl.textContent = authFailCount.toLocaleString();
    if (successEl) successEl.textContent = authSuccessCount.toLocaleString();
  }

  function _formatIntervalLabel(bucketMs) {
    const sec = Math.round(bucketMs / 1000);
    if (sec < 60) return `${Math.max(1, sec)} second${sec > 1 ? 's' : ''}`;
    const min = Math.round(sec / 60);
    if (min < 60) return `${min} minute${min > 1 ? 's' : ''}`;
    const hrs = Math.round(min / 60);
    if (hrs < 24) return `${hrs} hour${hrs > 1 ? 's' : ''}`;
    const days = Math.round(hrs / 24);
    return `${days} day${days > 1 ? 's' : ''}`;
  }

  /* ══════════════════════════════════════════════════════════
     TIME BUCKETING LOGIC (Based on real alerts in time range)
  ════════════════════════════════════════════════════════════ */
  function _computeTimeBuckets(numBuckets = 36) {
    let rangeStart = null;
    let rangeEnd = null;

    if (window.TimeRangePicker && window.TimeRangePicker.getRange) {
      const r = window.TimeRangePicker.getRange();
      if (r && r.from && r.to) {
        rangeStart = r.from.getTime();
        rangeEnd = r.to.getTime();
      }
    }

    const currentAlerts = _getFilteredAlerts();

    if (!rangeStart || !rangeEnd) {
      const validTimestamps = currentAlerts.map(a => {
        const ts = a.timestamp || a.receivedAt || a['@timestamp'];
        return ts ? new Date(ts).getTime() : NaN;
      }).filter(t => !isNaN(t)).sort((a, b) => a - b);

      if (validTimestamps.length > 0) {
        const minT = validTimestamps[0];
        const maxT = validTimestamps[validTimestamps.length - 1];
        const spanMs = maxT - minT;

        if (spanMs < 24 * 60 * 60 * 1000) {
          const d = new Date(minT);
          rangeStart = new Date(d.getFullYear(), d.getMonth(), d.getDate(), 0, 0, 0, 0).getTime();
          rangeEnd = rangeStart + (24 * 60 * 60 * 1000);
        } else {
          const pad = Math.max(3600000, spanMs * 0.05);
          rangeStart = minT - pad;
          rangeEnd = maxT + pad;
        }
      } else {
        const now = Date.now();
        rangeEnd = now;
        rangeStart = now - (24 * 60 * 60 * 1000);
      }
    }

    const totalDuration = Math.max(1000, rangeEnd - rangeStart);
    const bucketMs = totalDuration / numBuckets;
    const intervalLabel = _formatIntervalLabel(bucketMs);
    const buckets = [];

    for (let i = 0; i < numBuckets; i++) {
      const bStart = new Date(rangeStart + i * bucketMs);
      const bEnd = new Date(rangeStart + (i + 1) * bucketMs);

      const hh1 = bStart.getHours().toString().padStart(2, '0');
      const mm1 = bStart.getMinutes().toString().padStart(2, '0');
      const ss1 = bStart.getSeconds().toString().padStart(2, '0');
      const hh2 = bEnd.getHours().toString().padStart(2, '0');
      const mm2 = bEnd.getMinutes().toString().padStart(2, '0');
      const ss2 = bEnd.getSeconds().toString().padStart(2, '0');

      let label = `${hh1}:${mm1}`;
      let timeRange = `${hh1}:${mm1} - ${hh2}:${mm2}`;

      if (totalDuration <= 60 * 60 * 1000 && bucketMs < 60000) {
        label = `${hh1}:${mm1}:${ss1}`;
        timeRange = `${hh1}:${mm1}:${ss1} - ${hh2}:${mm2}:${ss2}`;
      } else if (totalDuration > 3 * 24 * 60 * 60 * 1000) {
        const mon = (bStart.getMonth() + 1).toString().padStart(2, '0');
        const day = bStart.getDate().toString().padStart(2, '0');
        label = `${mon}/${day}`;
        timeRange = `${mon}/${day} ${hh1}:${mm1} - ${hh2}:${mm2}`;
      }

      buckets.push({
        index: i,
        startMs: bStart.getTime(),
        endMs: bEnd.getTime(),
        label,
        timeRange,
        countsByLevel: {},
        countsByAgent: {},
        totalCount: 0,
      });
    }

    currentAlerts.forEach(a => {
      const ts = a.timestamp || a.receivedAt || a['@timestamp'];
      if (!ts) return;
      const t = new Date(ts).getTime();
      if (isNaN(t) || t < rangeStart || t > rangeEnd) return;

      const idx = Math.min(numBuckets - 1, Math.max(0, Math.floor((t - rangeStart) / bucketMs)));
      const lvl = String(a?.rule?.level ?? 'unknown');
      const ag = a?.agent?.name || 'wazuh-server';

      buckets[idx].countsByLevel[lvl] = (buckets[idx].countsByLevel[lvl] || 0) + 1;
      buckets[idx].countsByAgent[ag] = (buckets[idx].countsByAgent[ag] || 0) + 1;
      buckets[idx].totalCount++;
    });

    return { buckets, rangeStart, rangeEnd, bucketMs, totalDuration, intervalLabel };
  }

  /* ══════════════════════════════════════════════════════════
     1. TOP 10 ALERT LEVEL EVOLUTION (Monotone Stacked Area Chart with Halo Target)
  ════════════════════════════════════════════════════════════ */
  function _buildMonotoneSplinePath(pts) {
    if (!pts || pts.length === 0) return '';
    if (pts.length === 1) return `M ${pts[0].x} ${pts[0].y}`;
    if (pts.length === 2) return `M ${pts[0].x} ${pts[0].y} L ${pts[1].x} ${pts[1].y}`;

    const n = pts.length;
    const dx = [];
    const dy = [];
    const slopes = [];

    for (let i = 0; i < n - 1; i++) {
      dx.push(pts[i + 1].x - pts[i].x);
      dy.push(pts[i + 1].y - pts[i].y);
      slopes.push(dx[i] === 0 ? 0 : dy[i] / dx[i]);
    }

    const tangents = [slopes[0]];
    for (let i = 1; i < n - 1; i++) {
      if (slopes[i - 1] * slopes[i] <= 0) {
        tangents.push(0);
      } else {
        tangents.push((2 * slopes[i - 1] * slopes[i]) / (slopes[i - 1] + slopes[i]));
      }
    }
    tangents.push(slopes[n - 2]);

    let d = `M ${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)}`;
    for (let i = 0; i < n - 1; i++) {
      const p1 = pts[i];
      const p2 = pts[i + 1];
      const segDx = dx[i] / 3;
      const cp1x = (p1.x + segDx).toFixed(2);
      const cp1y = (p1.y + tangents[i] * segDx).toFixed(2);
      const cp2x = (p2.x - segDx).toFixed(2);
      const cp2y = (p2.y - tangents[i + 1] * segDx).toFixed(2);

      d += ` C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${p2.x.toFixed(2)} ${p2.y.toFixed(2)}`;
    }
    return d;
  }

  function _buildMonotoneAreaPath(upperPts, lowerPts) {
    if (!upperPts || upperPts.length === 0) return '';
    const upperD = _buildMonotoneSplinePath(upperPts);
    const reversedLower = [...lowerPts].reverse();
    const lowerD = _buildMonotoneSplinePath(reversedLower);
    const lowerPathCmds = lowerD.replace(/^M\s*[^C\s]+\s+[^C\s]+/, `L ${reversedLower[0].x.toFixed(2)} ${reversedLower[0].y.toFixed(2)}`);
    return `${upperD} ${lowerPathCmds} Z`;
  }

  function renderAlertLevelEvolution() {
    const container = document.getElementById('chart-alert-level-evolution');
    const legendEl = document.getElementById('legend-alert-level-evolution');
    if (!container) return;

    const { buckets, rangeStart, bucketMs, intervalLabel } = _computeTimeBuckets(40);
    const alerts = _getFilteredAlerts();

    const levelTotals = {};
    alerts.forEach(a => {
      const lvl = String(a?.rule?.level ?? 'unknown');
      levelTotals[lvl] = (levelTotals[lvl] || 0) + 1;
    });

    const activeLevels = Object.keys(levelTotals).sort((a, b) => levelTotals[b] - levelTotals[a]).slice(0, 10);
    const targetLevels = activeLevels.length > 0 ? activeLevels : ['4', '6', '11'];

    if (legendEl) {
      legendEl.innerHTML = targetLevels.map(lvl => {
        const color = LEVEL_COLORS[lvl] || '#50b59b';
        const count = levelTotals[lvl] || 0;
        return `
          <div class="top-chart-legend-item" data-level="${lvl}" title="Click to filter Alert Level ${lvl} (${count} events)">
            <span class="legend-dot" style="background-color: ${color};"></span>
            <span class="legend-label">${lvl}</span>
          </div>
        `;
      }).join('');

      legendEl.querySelectorAll('.top-chart-legend-item').forEach(item => {
        const lvl = item.getAttribute('data-level');
        item.addEventListener('mouseenter', () => {
          container.querySelectorAll('.area-layer-path').forEach(layer => {
            if (layer.getAttribute('data-level') !== lvl) {
              layer.style.opacity = '0.2';
            } else {
              layer.style.opacity = '0.9';
            }
          });
        });
        item.addEventListener('mouseleave', () => {
          container.querySelectorAll('.area-layer-path').forEach(layer => {
            layer.style.opacity = '0.6';
          });
        });
        item.addEventListener('click', () => {
          if (_activeFieldFilters['rule.level'] === String(lvl)) {
            removeFieldFilter('rule.level');
          } else {
            _activeFieldFilters['rule.level'] = String(lvl);
            if (window.PanelManager && typeof window.PanelManager.setFilter === 'function') {
              window.PanelManager.setFilter(a => String(a?.rule?.level) === String(lvl));
            }
            renderAll();
          }
        });
      });
    }

    const width = container.clientWidth || 520;
    const height = 210;
    const padLeft = 42;
    const padRight = 30;
    const padTop = 15;
    const padBottom = 38;

    const chartW = Math.max(80, width - padLeft - padRight);
    const chartH = Math.max(40, height - padTop - padBottom);

    const maxBucketVal = Math.max(10, ...buckets.map(b => b.totalCount));
    const maxY = _computeNiceMax(maxBucketVal);
    const yTicks = _generateNiceTicks(maxY, 4);

    const N = buckets.length;
    const xStep = chartW / Math.max(1, N - 1);

    const layers = {};
    targetLevels.forEach(lvl => layers[lvl] = { upper: [], lower: [], counts: [] });

    for (let i = 0; i < N; i++) {
      const b = buckets[i];
      const x = padLeft + i * xStep;
      let cumY = 0;

      targetLevels.forEach(lvl => {
        const cnt = b.countsByLevel[lvl] || 0;
        const y0Val = cumY;
        const y1Val = cumY + cnt;
        cumY = y1Val;

        const y0Px = Math.max(padTop, Math.min(padTop + chartH, padTop + chartH - (y0Val / maxY) * chartH));
        const y1Px = Math.max(padTop, Math.min(padTop + chartH, padTop + chartH - (Math.min(y1Val, maxY) / maxY) * chartH));

        layers[lvl].upper.push({ x, y: y1Px });
        layers[lvl].lower.push({ x, y: y0Px });
        layers[lvl].counts.push(cnt);
      });
    }

    let pathsHtml = '';
    targetLevels.forEach(lvl => {
      const layer = layers[lvl];
      if (!layer || layer.upper.length === 0) return;

      const color = LEVEL_COLORS[lvl] || '#50b59b';
      const pathD = _buildMonotoneAreaPath(layer.upper, layer.lower);
      const topStrokeD = _buildMonotoneSplinePath(layer.upper);

      pathsHtml += `
        <path d="${pathD}" fill="${color}" class="area-layer-path" data-level="${lvl}" style="opacity: 0.52; transition: opacity 0.15s ease;" />
        <path d="${topStrokeD}" fill="none" stroke="${color}" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round" class="area-layer-stroke" data-level="${lvl}" />
      `;
    });

    let gridHtml = '';
    let yLabelsHtml = '';
    yTicks.forEach(tick => {
      const y = padTop + chartH - (tick / maxY) * chartH;
      gridHtml += `<line x1="${padLeft}" y1="${y}" x2="${padLeft + chartW}" y2="${y}" stroke="rgba(255,255,255,0.06)" stroke-width="1" />`;
      yLabelsHtml += `<text x="${padLeft - 6}" y="${y + 4}" text-anchor="end" class="top-chart-axis-tick">${tick}</text>`;
    });

    let xTicksHtml = '';
    const numXTicks = Math.min(8, N);
    const xInterval = Math.max(1, Math.floor((N - 1) / (numXTicks - 1)));
    for (let i = 0; i < numXTicks; i++) {
      const bIdx = Math.min(N - 1, i * xInterval);
      const x = padLeft + bIdx * xStep;
      const b = buckets[bIdx];
      xTicksHtml += `<text x="${x}" y="${padTop + chartH + 16}" text-anchor="middle" class="top-chart-axis-tick">${b.label}</text>`;
      gridHtml += `<line x1="${x}" y1="${padTop}" x2="${x}" y2="${padTop + chartH}" stroke="rgba(255,255,255,0.04)" stroke-width="1" />`;
    }

    container.innerHTML = `
      <svg class="top-chart-svg" width="100%" height="${height}" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" style="overflow: visible;">
        <g class="chart-grid">${gridHtml}</g>
        <line x1="${padLeft}" y1="${padTop + chartH}" x2="${padLeft + chartW}" y2="${padTop + chartH}" stroke="rgba(255,255,255,0.15)" stroke-width="1" />
        <line x1="${padLeft}" y1="${padTop}" x2="${padLeft}" y2="${padTop + chartH}" stroke="rgba(255,255,255,0.15)" stroke-width="1" />
        
        <text x="${12}" y="${padTop + chartH / 2}" transform="rotate(-90 12 ${padTop + chartH / 2})" text-anchor="middle" class="top-chart-axis-title">Count</text>
        
        <g class="chart-y-ticks">${yLabelsHtml}</g>
        <g class="chart-areas">${pathsHtml}</g>
        <g class="chart-x-ticks">${xTicksHtml}</g>
        
        <text x="${padLeft + chartW / 2}" y="${padTop + chartH + 30}" text-anchor="middle" class="top-chart-axis-title">timestamp per ${intervalLabel}</text>
        
        <!-- Circular Halo Target Indicator on Curve matching exact graph color -->
        <g id="area-hover-target" style="display:none; pointer-events:none; transition: transform 0.08s cubic-bezier(0.2, 0.8, 0.2, 1);">
          <circle id="hover-halo-outer" r="10" fill="rgba(96, 146, 205, 0.3)" stroke="#6092cd" stroke-width="2.5" />
          <circle id="hover-halo-inner" r="4" fill="#6092cd" stroke="#ffffff" stroke-width="1.5" />
        </g>
      </svg>
    `;

    _attachAreaHaloHover(container, buckets, layers, targetLevels, padLeft, chartW, xStep, padTop, chartH, intervalLabel);
  }

  function _attachAreaHaloHover(container, buckets, layers, levels, padLeft, chartW, xStep, padTop, chartH, intervalLabel) {
    const svg = container.querySelector('svg');
    const targetGroup = container.querySelector('#area-hover-target');
    const outerRing = container.querySelector('#hover-halo-outer');
    const innerDot = container.querySelector('#hover-halo-inner');
    if (!svg || !targetGroup || !outerRing) return;

    let activeLevelUnderCursor = null;
    let activeBucketIdx = -1;

    svg.addEventListener('mousemove', (e) => {
      const rect = svg.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      if (mouseX < padLeft - 6 || mouseX > padLeft + chartW + 6 || mouseY < padTop - 10 || mouseY > padTop + chartH + 10) {
        targetGroup.style.display = 'none';
        _hideTooltip();
        activeBucketIdx = -1;
        activeLevelUnderCursor = null;
        return;
      }

      const approxIdx = (mouseX - padLeft) / xStep;
      const idx = Math.min(buckets.length - 1, Math.max(0, Math.round(approxIdx)));
      const b = buckets[idx];
      if (!b) {
        targetGroup.style.display = 'none';
        _hideTooltip();
        activeBucketIdx = -1;
        activeLevelUnderCursor = null;
        return;
      }

      const targetX = padLeft + idx * xStep;
      const distToX = Math.abs(mouseX - targetX);
      const maxAllowedXDist = Math.max(xStep * 0.75, 14);

      if (distToX > maxAllowedXDist) {
        targetGroup.style.display = 'none';
        _hideTooltip();
        activeBucketIdx = -1;
        activeLevelUnderCursor = null;
        return;
      }

      // Find closest active layer with count > 0 in this bucket
      let bestCandidate = null;
      let minDistance = Infinity;

      for (let i = 0; i < levels.length; i++) {
        const lvl = levels[i];
        const layer = layers[lvl];
        if (!layer) continue;
        const cnt = layer.counts[idx] || 0;
        if (cnt <= 0) continue;

        const upperY = layer.upper[idx].y;
        const lowerY = layer.lower[idx].y;

        let dy = 0;
        if (mouseY < upperY) {
          dy = upperY - mouseY;
        } else if (mouseY > lowerY) {
          dy = mouseY - lowerY;
        } else {
          dy = 0;
        }

        const dist = Math.hypot(distToX, dy);
        if (dist < minDistance) {
          minDistance = dist;
          bestCandidate = {
            lvl,
            cnt,
            targetY: upperY,
            upperY,
            lowerY,
            dist
          };
        }
      }

      // Check if cursor is close enough to the data point or inside the layer
      const isInside = bestCandidate && mouseY >= bestCandidate.upperY - 8 && mouseY <= bestCandidate.lowerY + 8;
      const isNearPoint = bestCandidate && minDistance <= 25;

      if (!bestCandidate || (!isInside && !isNearPoint)) {
        targetGroup.style.display = 'none';
        _hideTooltip();
        activeBucketIdx = -1;
        activeLevelUnderCursor = null;
        return;
      }

      const chosenLvl = bestCandidate.lvl;
      const targetY = bestCandidate.targetY;
      const cnt = bestCandidate.cnt;

      activeBucketIdx = idx;
      activeLevelUnderCursor = chosenLvl;

      const color = LEVEL_COLORS[chosenLvl] || '#50b59b';

      // Move Halo Circle directly to (targetX, targetY) with matching color
      targetGroup.setAttribute('transform', `translate(${targetX}, ${targetY})`);
      outerRing.setAttribute('stroke', color);
      outerRing.setAttribute('fill', color);
      outerRing.setAttribute('fill-opacity', '0.35');
      innerDot.setAttribute('fill', color);
      targetGroup.style.display = 'block';

      // Tooltip matching Kibana format with matching color indicator
      const html = `
        <div class="top-tooltip-head" style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid rgba(255,255,255,0.1); padding-bottom:6px; margin-bottom:6px;">
          <span style="color:#94a3b8; font-size:11.5px; margin-right:12px;">timestamp per ${intervalLabel}</span>
          <span style="color:#ffffff; font-weight:700; font-family:var(--font-mono); font-size:12px;">${b.label}</span>
        </div>
        <div class="top-tooltip-row" style="display:flex; justify-content:space-between; margin-bottom:4px;">
          <span class="tooltip-name" style="color:#94a3b8; font-size:11.5px;">Count</span>
          <span class="tooltip-val" style="color:#ffffff; font-weight:700; font-family:var(--font-mono); font-size:12px;">${cnt}</span>
        </div>
        <div class="top-tooltip-row" style="display:flex; justify-content:space-between; align-items:center;">
          <span class="tooltip-name" style="color:#94a3b8; font-size:11.5px; display:inline-flex; align-items:center; gap:5px;">
            <span style="display:inline-block; width:7px; height:7px; border-radius:50%; background:${color};"></span>
            rule.level: Descending
          </span>
          <span class="tooltip-val" style="color:${color}; font-weight:700; font-family:var(--font-mono); font-size:12px;">${chosenLvl}</span>
        </div>
      `;

      // Position tooltip near the halo ring
      const tipX = e.clientX > window.innerWidth / 2 ? e.clientX - 230 : e.clientX + 18;
      _showTooltip(tipX, e.clientY - 40, html);
    });

    svg.addEventListener('mouseleave', () => {
      targetGroup.style.display = 'none';
      _hideTooltip();
      activeBucketIdx = -1;
      activeLevelUnderCursor = null;
    });

    svg.addEventListener('click', (e) => {
      if (activeBucketIdx === -1 || !activeLevelUnderCursor) return;
      e.stopPropagation();
      e.preventDefault();
      const b = buckets[activeBucketIdx];
      if (!b) return;

      _showFilterPopover(e.clientX, e.clientY, {
        bStart: new Date(b.startMs),
        bEnd: new Date(b.endMs),
        field: 'rule.level',
        value: activeLevelUnderCursor
      });
    });
  }

  /* ══════════════════════════════════════════════════════════
     2. TOP 10 MITRE ATT&CKS (Real data or clean empty state)
  ════════════════════════════════════════════════════════════ */
  function renderMitreAttacks() {
    const container = document.getElementById('chart-mitre-attacks');
    if (!container) return;

    const alerts = _getFilteredAlerts();
    const mitreCounts = {};
    alerts.forEach(a => {
      const mitre = a?.rule?.mitre;
      if (!mitre) return;
      const ids = mitre.id || (mitre.tactic ? [mitre.tactic] : []);
      const arr = Array.isArray(ids) ? ids : [ids];
      arr.forEach(id => {
        if (id) mitreCounts[id] = (mitreCounts[id] || 0) + 1;
      });
    });

    const entries = Object.entries(mitreCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);

    if (entries.length === 0) {
      container.innerHTML = `
        <div class="top-chart-empty-state">
          <div class="empty-icon-wrap" aria-hidden="true">
            <svg class="empty-results-icon" viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="#606c7d" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round">
              <path d="M4 21h16M5 21V9l7-5 7 5v12M9 21v-7h6v7" />
            </svg>
          </div>
          <span class="empty-text">No results found</span>
        </div>
      `;
    } else {
      const maxVal = Math.max(...entries.map(e => e[1]), 1);
      const totalMitreCount = Object.values(mitreCounts).reduce((a, b) => a + b, 0);
      container.innerHTML = `
        <div class="mitre-bars-list">
          ${entries.map(([tech, cnt]) => {
            const pct = ((cnt / maxVal) * 100).toFixed(1);
            const pctTotal = totalMitreCount > 0 ? ((cnt / totalMitreCount) * 100).toFixed(1) : '0.0';
            return `
              <div class="mitre-bar-row" data-tech="${tech}" data-count="${cnt}" data-pct="${pctTotal}" style="cursor: pointer;">
                <span class="mitre-tech-name" title="${tech}">${tech}</span>
                <div class="mitre-bar-track">
                  <div class="mitre-bar-fill" style="width: ${pct}%;"></div>
                </div>
                <span class="mitre-count">${cnt}</span>
              </div>
            `;
          }).join('')}
        </div>
      `;

      container.querySelectorAll('.mitre-bar-row').forEach(row => {
        row.addEventListener('mouseenter', (e) => {
          const tech = row.getAttribute('data-tech');
          const count = row.getAttribute('data-count');
          const pct = row.getAttribute('data-pct');

          const html = `
            <div class="top-tooltip-head" style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid rgba(255,255,255,0.1); padding-bottom:6px; margin-bottom:6px;">
              <span style="color:#94a3b8; font-size:11.5px; margin-right:12px;">MITRE ATT&CK</span>
              <span style="color:#ffffff; font-weight:700; font-family:var(--font-mono); font-size:12px;">${tech}</span>
            </div>
            <div class="top-tooltip-row" style="display:flex; justify-content:space-between; margin-bottom:4px;">
              <span class="tooltip-name" style="color:#94a3b8; font-size:11.5px;">Alerts</span>
              <span class="tooltip-val" style="color:#ffffff; font-weight:700; font-family:var(--font-mono); font-size:12px;">${count} <span style="font-weight:400; color:#94a3b8; font-size:11px;">(${pct}%)</span></span>
            </div>
            <div class="top-tooltip-row" style="display:flex; justify-content:space-between; align-items:center;">
              <span class="tooltip-name" style="color:#94a3b8; font-size:11.5px; display:inline-flex; align-items:center; gap:5px;">
                <span style="display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--accent, #6092cd);"></span>
                rule.mitre.id
              </span>
              <span class="tooltip-val" style="color:var(--accent, #6092cd); font-weight:700; font-family:var(--font-mono); font-size:12px;">${tech}</span>
            </div>
          `;
          _showTooltip(e.clientX + 12, e.clientY - 20, html);
        });

        row.addEventListener('mousemove', (e) => {
          _positionTooltip(e.clientX + 12, e.clientY - 20);
        });

        row.addEventListener('mouseleave', () => {
          _hideTooltip();
        });

        row.addEventListener('click', (e) => {
          e.stopPropagation();
          const tech = row.getAttribute('data-tech');
          _showFilterPopover(e.clientX, e.clientY, {
            field: 'rule.mitre.id',
            value: tech
          });
        });
      });
    }
  }

  /* ══════════════════════════════════════════════════════════
     3. TOP 5 AGENTS (Donut Chart from REAL AGENTS)
  ════════════════════════════════════════════════════════════ */
  function renderTopAgents() {
    const container = document.getElementById('chart-top-agents');
    const legendEl = document.getElementById('legend-top-agents');
    if (!container) return;

    const alerts = _getFilteredAlerts();
    const agentCounts = {};
    alerts.forEach(a => {
      const name = a?.agent?.name || 'wazuh-server';
      agentCounts[name] = (agentCounts[name] || 0) + 1;
    });

    const sortedAgents = Object.entries(agentCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    const total = sortedAgents.reduce((sum, [, cnt]) => sum + cnt, 0);

    if (total === 0) {
      container.innerHTML = `
        <div class="top-chart-empty-state">
          <span class="empty-text">No agent alerts</span>
        </div>
      `;
      if (legendEl) legendEl.innerHTML = '';
      return;
    }

    if (legendEl) {
      legendEl.innerHTML = sortedAgents.map(([name, cnt], idx) => {
        const color = AGENT_COLORS[idx % AGENT_COLORS.length];
        const pct = ((cnt / total) * 100).toFixed(1);
        return `
          <div class="top-chart-legend-item" title="Agent ${name}: ${cnt} alerts (${pct}%)">
            <span class="legend-dot" style="background-color: ${color};"></span>
            <span class="legend-label">${name}</span>
          </div>
        `;
      }).join('');
    }

    const width = container.clientWidth || 260;
    const height = 210;
    const cx = width / 2;
    const cy = height / 2;
    const outerRadius = Math.min(cx, cy) - 14;
    const innerRadius = outerRadius - 30;

    let currentAngle = -Math.PI / 2;
    let pathsHtml = '';

    sortedAgents.forEach(([name, count], idx) => {
      const color = AGENT_COLORS[idx % AGENT_COLORS.length];
      const sliceAngle = (count / total) * 2 * Math.PI;
      const endAngle = currentAngle + sliceAngle;

      let d = '';
      if (sortedAgents.length === 1 || sliceAngle >= 2 * Math.PI - 0.001) {
        d = `
          M ${cx} ${cy - outerRadius}
          A ${outerRadius} ${outerRadius} 0 1 0 ${cx} ${cy + outerRadius}
          A ${outerRadius} ${outerRadius} 0 1 0 ${cx} ${cy - outerRadius}
          M ${cx} ${cy - innerRadius}
          A ${innerRadius} ${innerRadius} 0 1 1 ${cx} ${cy + innerRadius}
          A ${innerRadius} ${innerRadius} 0 1 1 ${cx} ${cy - innerRadius}
          Z
        `;
      } else {
        const x1 = cx + outerRadius * Math.cos(currentAngle);
        const y1 = cy + outerRadius * Math.sin(currentAngle);
        const x2 = cx + outerRadius * Math.cos(endAngle);
        const y2 = cy + outerRadius * Math.sin(endAngle);

        const x3 = cx + innerRadius * Math.cos(endAngle);
        const y3 = cy + innerRadius * Math.sin(endAngle);
        const x4 = cx + innerRadius * Math.cos(currentAngle);
        const y4 = cy + innerRadius * Math.sin(currentAngle);

        const largeArc = sliceAngle > Math.PI ? 1 : 0;

        d = `
          M ${x1} ${y1}
          A ${outerRadius} ${outerRadius} 0 ${largeArc} 1 ${x2} ${y2}
          L ${x3} ${y3}
          A ${innerRadius} ${innerRadius} 0 ${largeArc} 0 ${x4} ${y4}
          Z
        `;
      }

      pathsHtml += `
        <path
          d="${d}"
          fill="${color}"
          class="donut-segment"
          data-agent="${name}"
          data-count="${count}"
          data-pct="${((count / total) * 100).toFixed(1)}"
          style="transition: transform 0.2s, opacity 0.2s; transform-origin: ${cx}px ${cy}px; cursor: pointer;"
        />
      `;

      currentAngle = endAngle;
    });

    container.innerHTML = `
      <svg class="top-chart-svg" width="100%" height="${height}" viewBox="0 0 ${width} ${height}">
        <g class="donut-group">${pathsHtml}</g>
      </svg>
    `;

    container.querySelectorAll('.donut-segment').forEach(seg => {
      seg.addEventListener('mouseenter', (e) => {
        seg.style.opacity = '0.9';
        seg.style.transform = 'scale(1.02)';
        const name = seg.getAttribute('data-agent');
        const count = seg.getAttribute('data-count');
        const pct = seg.getAttribute('data-pct');

        const html = `
          <div class="top-tooltip-head">${name}</div>
          <div class="top-tooltip-row">
            <span class="tooltip-name">Alerts:</span>
            <span class="tooltip-val">${count} (${pct}%)</span>
          </div>
        `;
        _showTooltip(e.clientX + 10, e.clientY - 20, html);
      });

      seg.addEventListener('mousemove', (e) => {
        _positionTooltip(e.clientX + 10, e.clientY - 20);
      });

      seg.addEventListener('mouseleave', () => {
        seg.style.opacity = '1';
        seg.style.transform = 'none';
        _hideTooltip();
      });

      // CLICK HANDLER: Filter by clicked agent
      seg.addEventListener('click', (e) => {
        e.stopPropagation();
        const name = seg.getAttribute('data-agent');
        _showFilterPopover(e.clientX, e.clientY, {
          field: 'agent.name',
          value: name
        });
      });
    });
  }

  /* ══════════════════════════════════════════════════════════
     4. ALERTS EVOLUTION - TOP 5 AGENTS (Histogram / Bar Chart)
  ════════════════════════════════════════════════════════════ */
  function renderAgentAlertsEvolution() {
    const container = document.getElementById('chart-agent-alerts-evolution');
    const legendEl = document.getElementById('legend-agent-alerts-evolution');
    if (!container) return;

    const { buckets, rangeStart, bucketMs, intervalLabel } = _computeTimeBuckets(40);
    const alerts = _getFilteredAlerts();

    const agentTotals = {};
    alerts.forEach(a => {
      const ag = a?.agent?.name || 'wazuh-server';
      agentTotals[ag] = (agentTotals[ag] || 0) + 1;
    });

    const topAgents = Object.keys(agentTotals).sort((a, b) => agentTotals[b] - agentTotals[a]).slice(0, 5);
    const primaryAgent = topAgents[0] || 'wazuh-server';

    if (legendEl) {
      legendEl.innerHTML = topAgents.map((ag, idx) => {
        const color = AGENT_COLORS[idx % AGENT_COLORS.length];
        return `
          <div class="top-chart-legend-item" title="Agent ${ag}">
            <span class="legend-dot" style="background-color: ${color};"></span>
            <span class="legend-label">${ag}</span>
          </div>
        `;
      }).join('');
    }

    const width = container.clientWidth || 520;
    const height = 210;
    const padLeft = 42;
    const padRight = 20;
    const padTop = 15;
    const padBottom = 38;

    const chartW = Math.max(80, width - padLeft - padRight);
    const chartH = Math.max(40, height - padTop - padBottom);

    const maxBucketVal = Math.max(10, ...buckets.map(b => b.totalCount));
    const maxY = _computeNiceMax(maxBucketVal);
    const yTicks = _generateNiceTicks(maxY, 4);

    const N = buckets.length;
    const slotW = chartW / N;
    const barW = Math.max(2, slotW - 3);

    let barsHtml = '';
    buckets.forEach((b, i) => {
      const cnt = b.totalCount;
      const barH = cnt > 0 ? Math.max(2, (cnt / maxY) * chartH) : 0;
      const x = padLeft + i * slotW + (slotW - barW) / 2;
      const y = padTop + chartH - barH;

      if (cnt > 0) {
        barsHtml += `
          <rect
            x="${x}"
            y="${y}"
            width="${barW}"
            height="${barH}"
            fill="${AGENT_COLORS[0]}"
            rx="1"
            class="hist-bar"
            data-index="${i}"
            data-time="${b.timeRange}"
            data-count="${cnt}"
            data-agent="${primaryAgent}"
            style="transition: fill 0.15s; cursor: pointer;"
          />
        `;
      }
    });

    let gridHtml = '';
    let yLabelsHtml = '';
    yTicks.forEach(tick => {
      const y = padTop + chartH - (tick / maxY) * chartH;
      gridHtml += `<line x1="${padLeft}" y1="${y}" x2="${padLeft + chartW}" y2="${y}" stroke="rgba(255,255,255,0.08)" stroke-width="1" />`;
      yLabelsHtml += `<text x="${padLeft - 6}" y="${y + 4}" text-anchor="end" class="top-chart-axis-tick">${tick}</text>`;
    });

    let xTicksHtml = '';
    const numXTicks = Math.min(8, N);
    const xInterval = Math.max(1, Math.floor((N - 1) / (numXTicks - 1)));
    for (let i = 0; i < numXTicks; i++) {
      const bIdx = Math.min(N - 1, i * xInterval);
      const x = padLeft + bIdx * slotW + slotW / 2;
      const b = buckets[bIdx];
      xTicksHtml += `<text x="${x}" y="${padTop + chartH + 16}" text-anchor="middle" class="top-chart-axis-tick">${b.label}</text>`;
    }

    container.innerHTML = `
      <svg class="top-chart-svg" width="100%" height="${height}" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
        <g class="chart-grid">${gridHtml}</g>
        <line x1="${padLeft}" y1="${padTop + chartH}" x2="${padLeft + chartW}" y2="${padTop + chartH}" stroke="rgba(255,255,255,0.15)" stroke-width="1" />
        <line x1="${padLeft}" y1="${padTop}" x2="${padLeft}" y2="${padTop + chartH}" stroke="rgba(255,255,255,0.15)" stroke-width="1" />
        
        <text x="${12}" y="${padTop + chartH / 2}" transform="rotate(-90 12 ${padTop + chartH / 2})" text-anchor="middle" class="top-chart-axis-title">Count</text>
        
        <g class="chart-y-ticks">${yLabelsHtml}</g>
        <g class="chart-bars">${barsHtml}</g>
        <g class="chart-x-ticks">${xTicksHtml}</g>
        
        <text x="${padLeft + chartW / 2}" y="${padTop + chartH + 30}" text-anchor="middle" class="top-chart-axis-title">timestamp per ${intervalLabel}</text>
      </svg>
    `;

    container.querySelectorAll('.hist-bar').forEach(bar => {
      bar.addEventListener('mouseenter', (e) => {
        bar.style.fill = '#e08ba9';
        const time = bar.getAttribute('data-time');
        const count = bar.getAttribute('data-count');
        const agent = bar.getAttribute('data-agent');

        const html = `
          <div class="top-tooltip-head">${time}</div>
          <div class="top-tooltip-row">
            <span class="tooltip-dot" style="background:${AGENT_COLORS[0]};"></span>
            <span class="tooltip-name">${agent}:</span>
            <span class="tooltip-val">${count}</span>
          </div>
        `;
        _showTooltip(e.clientX + 10, e.clientY - 20, html);
      });

      bar.addEventListener('mousemove', (e) => {
        _positionTooltip(e.clientX + 10, e.clientY - 20);
      });

      bar.addEventListener('mouseleave', () => {
        bar.style.fill = AGENT_COLORS[0];
        _hideTooltip();
      });

      // CLICK HANDLER: Open Kibana Filter Popover
      bar.addEventListener('click', (e) => {
        e.stopPropagation();
        const idx = parseInt(bar.getAttribute('data-index'), 10);
        const b = buckets[idx];
        const agent = bar.getAttribute('data-agent') || 'wazuh-server';

        if (b) {
          _showFilterPopover(e.clientX, e.clientY, {
            bStart: new Date(b.startMs),
            bEnd: new Date(b.endMs),
            field: 'agent.name',
            value: agent
          });
        }
      });
    });
  }

  /* ══════════════════════════════════════════════════════════
     KIBANA "Select filters to apply" POPOVER MODAL
  ════════════════════════════════════════════════════════════ */
  function _formatKibanaTimestamp(d) {
    if (!d || isNaN(d.getTime())) return '';
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const m = months[d.getMonth()];
    const day = d.getDate();
    const yr = d.getFullYear();
    const hh = d.getHours().toString().padStart(2, '0');
    const mm = d.getMinutes().toString().padStart(2, '0');
    const ss = d.getSeconds().toString().padStart(2, '0');
    return `${m} ${day}, ${yr} @ ${hh}:${mm}:${ss}.000`;
  }

  function _showFilterPopover(x, y, data) {
    let popover = document.getElementById('chart-filter-popover');
    if (!popover) {
      popover = document.createElement('div');
      popover.id = 'chart-filter-popover';
      popover.className = 'chart-filter-popover';
      document.body.appendChild(popover);
    }

    const timeText = (data.bStart && data.bEnd)
      ? `timestamp: ${_formatKibanaTimestamp(data.bStart)} to ${_formatKibanaTimestamp(data.bEnd)}`
      : null;

    const fieldText = (data.field && data.value !== undefined)
      ? `${data.field}: ${data.value}`
      : null;

    popover.innerHTML = `
      <div class="popover-header">
        <h3 class="popover-title">Select filters to apply</h3>
        <button class="popover-close-btn" id="popover-close-btn" aria-label="Close">&times;</button>
      </div>
      <div class="popover-body">
        ${timeText ? `
          <label class="filter-toggle-row">
            <input type="checkbox" id="popover-toggle-time" class="popover-switch" checked />
            <span class="switch-slider"></span>
            <span class="toggle-text">${timeText}</span>
          </label>
        ` : ''}
        ${fieldText ? `
          <label class="filter-toggle-row">
            <input type="checkbox" id="popover-toggle-field" class="popover-switch" checked />
            <span class="switch-slider"></span>
            <span class="toggle-text">${fieldText}</span>
          </label>
        ` : ''}
      </div>
      <div class="popover-footer">
        <button class="popover-btn-cancel" id="popover-btn-cancel">Cancel</button>
        <button class="popover-btn-apply" id="popover-btn-apply">Apply</button>
      </div>
    `;

    popover.style.display = 'block';

    const pWidth = 410;
    const pHeight = popover.offsetHeight || 220;
    const maxLeft = window.innerWidth - pWidth - 20;
    const maxTop = window.innerHeight - pHeight - 20;

    const left = Math.max(20, Math.min(x - 200, maxLeft));
    const top = Math.max(20, Math.min(y + 15, maxTop));

    popover.style.left = `${left}px`;
    popover.style.top = `${top}px`;

    const closeBtn = document.getElementById('popover-close-btn');
    const cancelBtn = document.getElementById('popover-btn-cancel');
    const applyBtn = document.getElementById('popover-btn-apply');

    const _close = (ev) => {
      if (ev) ev.stopPropagation();
      popover.style.display = 'none';
      document.removeEventListener('click', _outsideClick);
    };

    if (closeBtn) closeBtn.onclick = _close;
    if (cancelBtn) cancelBtn.onclick = _close;

    if (applyBtn) {
      applyBtn.onclick = (ev) => {
        ev.stopPropagation();
        const timeChecked = document.getElementById('popover-toggle-time')?.checked;
        const fieldChecked = document.getElementById('popover-toggle-field')?.checked;

        if (timeChecked && data.bStart && data.bEnd) {
          if (window.TimeRangePicker && typeof window.TimeRangePicker.setAbsolute === 'function') {
            window.TimeRangePicker.setAbsolute(data.bStart, data.bEnd);
          }
        }

        if (fieldChecked && data.field && data.value !== undefined) {
          _activeFieldFilters[data.field] = String(data.value);
          if (window.PanelManager && typeof window.PanelManager.setFilter === 'function') {
            window.PanelManager.setFilter(a => {
              if (data.field === 'agent.name') return String(a?.agent?.name || 'wazuh-server').toLowerCase() === String(data.value).toLowerCase();
              if (data.field === 'rule.level') return String(a?.rule?.level) === String(data.value);
              if (data.field === 'rule.mitre.id') {
                const ids = a?.rule?.mitre?.id || a?.rule?.mitre?.tactic || [];
                const arr = Array.isArray(ids) ? ids : [ids];
                return arr.some(x => String(x).toLowerCase() === String(data.value).toLowerCase());
              }
              return true;
            });
          }
        }

        _close();
        fetchDataAndRender();
      };
    }

    const _outsideClick = (ev) => {
      if (!popover.contains(ev.target) && ev.target !== popover) {
        _close();
      }
    };
    setTimeout(() => document.addEventListener('click', _outsideClick), 100);
  }

  function resetZoom() {
    if (window.TimeRangePicker && typeof window.TimeRangePicker.reset === 'function') {
      window.TimeRangePicker.reset();
    }
    fetchDataAndRender();
  }

  function removeFieldFilter(field) {
    if (field in _activeFieldFilters) {
      delete _activeFieldFilters[field];
      if (field === 'rule.level' && _activeKpiFilter === 'level12') _activeKpiFilter = null;
      if (field === 'rule.category' && (_activeKpiFilter === 'auth_fail' || _activeKpiFilter === 'auth_success')) _activeKpiFilter = null;
      
      if (window.PanelManager) {
        const remaining = Object.keys(_activeFieldFilters);
        if (remaining.length === 0) {
          window.PanelManager.clearFilter();
        } else {
          // Reapply remaining
          if (_activeFieldFilters['rule.level'] === '>= 12') {
            window.PanelManager.setFilter(a => parseInt(a?.rule?.level ?? 0, 10) >= 12);
          } else if (_activeFieldFilters['rule.category'] === 'Authentication failure') {
            window.PanelManager.setFilter(isAuthFailAlert);
          } else if (_activeFieldFilters['rule.category'] === 'Authentication success') {
            window.PanelManager.setFilter(isAuthSuccessAlert);
          }
        }
      }
      renderAll();
    }
  }

  function resetAllFilters() {
    _activeFieldFilters = {};
    _activeKpiFilter = null;
    if (window.TimeRangePicker && typeof window.TimeRangePicker.reset === 'function') {
      window.TimeRangePicker.reset();
    }
    if (window.PanelManager && typeof window.PanelManager.clearFilter === 'function') {
      window.PanelManager.clearFilter();
    }
    fetchDataAndRender();
  }

  /* ══════════════════════════════════════════════════════════
     SCALE & MATH HELPERS
  ════════════════════════════════════════════════════════════ */
  function _computeNiceMax(val) {
    if (val <= 10) return 10;
    if (val <= 20) return 20;
    if (val <= 50) return 50;
    if (val <= 100) return 100;
    if (val <= 150) return 150;
    if (val <= 200) return 200;
    if (val <= 400) return 400;
    if (val <= 600) return 600;
    if (val <= 800) return 800;
    if (val <= 1000) return 1000;
    const pow = Math.pow(10, Math.floor(Math.log10(val)));
    return Math.ceil(val / pow) * pow;
  }

  function _generateNiceTicks(maxVal, count = 4) {
    const step = maxVal / count;
    const ticks = [];
    for (let i = 0; i <= count; i++) {
      ticks.push(Math.round(i * step));
    }
    return ticks;
  }

  /* ══════════════════════════════════════════════════════════
     TOOLTIP HELPERS
  ════════════════════════════════════════════════════════════ */
  function _showTooltip(x, y, contentHtml) {
    if (!_activeTooltip) return;
    _activeTooltip.innerHTML = contentHtml;
    _activeTooltip.style.display = 'block';
    _positionTooltip(x, y);
  }

  function _positionTooltip(x, y) {
    if (!_activeTooltip) return;
    const tipW = _activeTooltip.offsetWidth || 180;
    const tipH = _activeTooltip.offsetHeight || 80;
    const maxLeft = window.innerWidth - tipW - 16;
    const maxTop = window.innerHeight - tipH - 16;

    _activeTooltip.style.left = `${Math.max(12, Math.min(x, maxLeft))}px`;
    _activeTooltip.style.top = `${Math.max(12, Math.min(y, maxTop))}px`;
  }

  function _hideTooltip() {
    if (_activeTooltip) _activeTooltip.style.display = 'none';
  }

  function _debounce(fn, delay) {
    let t;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, args), delay);
    };
  }

  function setUseCaseFilter(useCase) {
    if (!useCase) {
      delete _activeFieldFilters['aegis_use_case'];
    } else {
      _activeFieldFilters['aegis_use_case'] = useCase;
    }
    renderAll();
  }

  return {
    init,
    reload: fetchDataAndRender,
    renderAll,
    showFilterPopover: _showFilterPopover,
    resetZoom,
    removeFieldFilter,
    resetAllFilters,
    setUseCaseFilter,
  };
})();

window.TopChartsController = TopChartsController;
