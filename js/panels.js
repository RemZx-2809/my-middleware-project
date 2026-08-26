/**
 * Aegis SOC — Panel State Machine
 *
 * Manages the loading → (empty | error | data) state transitions
 * for each of the 5 data panels and 5 KPI cards.
 *
 * States:
 *   loading  — shimmer skeleton rows shown
 *   empty    — no data available (clean state, not an error)
 *   error    — fetch failed
 *   data     — data rows rendered by ingestAlerts() from WebhookReceiver
 *
 * Data flow (push-only, no Wazuh polling):
 *   Wazuh → server.js webhook → SSE → receiver.js → ingestAlerts() → renderAlerts()
 */

'use strict';

const PanelManager = (() => {
  /* ── Panel Registry ────────────────────────────────────── */
  const panels = {};

  /**
   * Register a panel by id.
   * @param {string} id — the panel element's id
   */
  function register(id) {
    const el = document.getElementById(id);
    if (!el) { console.warn(`[PanelManager] Panel #${id} not found.`); return; }

    panels[id] = {
      el,
      currentState: 'loading',
      states: {
        loading: el.querySelector('.state-loading'),
        empty:   el.querySelector('.state-empty'),
        error:   el.querySelector('.state-error'),
        data:    el.querySelector('.state-data'),
      },
    };

    // Start in loading
    _applyState(id, 'loading');
  }

  /**
   * Transition a panel to a new state.
   * @param {string} id
   * @param {'loading'|'empty'|'error'|'data'} state
   */
  function setState(id, state) {
    if (!panels[id]) { console.warn(`[PanelManager] Unknown panel: ${id}`); return; }
    _applyState(id, state);
  }

  function _applyState(id, state) {
    const panel = panels[id];
    if (!panel) return;

    panel.currentState = state;

    // Hide all, show target
    Object.entries(panel.states).forEach(([key, el]) => {
      if (!el) return;
      el.classList.remove('active');
      if (key === state) el.classList.add('active');
    });
  }

  function getState(id) {
    return panels[id]?.currentState ?? null;
  }

  /* ── KPI Card State Machine & Selection ─────────────────── */
  const kpiCards = {};
  let _activeKpiUseCase = null;

  function registerKpi(id) {
    const el = document.getElementById(id);
    if (!el) { console.warn(`[PanelManager] KPI #${id} not found.`); return; }
    kpiCards[id] = { el, currentState: 'loading' };
    _applyKpiState(id, 'loading');
  }

  function _applyKpiPanelFilter() {
    const allPanelIds = [
      'panel-critical-alerts',
      'panel-file-changes',
      'panel-blind-spots',
      'panel-auth-anomalies',
      'panel-threat-intel',
    ];

    allPanelIds.forEach(pId => {
      const pEl = document.getElementById(pId);
      if (pEl) {
        pEl.style.display = '';
        pEl.classList.remove('panel--highlighted');
      }
    });

    document.querySelectorAll('.panel-col').forEach(col => {
      col.style.display = '';
    });
  }

  function setKpiState(id, state, value, deltaText, deltaDir) {
    if (!kpiCards[id]) return;
    const { el } = kpiCards[id];

    el.setAttribute('data-state', state);
    kpiCards[id].currentState = state;

    if (state === 'data' || state === 'empty') {
      const valEl    = el.querySelector('.kpi-value');
      const deltaEl  = el.querySelector('.kpi-delta');
      const deltaSpan = el.querySelector('.kpi-delta-text');
      if (valEl)   valEl.textContent   = value   ?? '—';
      if (deltaSpan) deltaSpan.textContent = deltaText ?? 'awaiting Wazuh data';
      if (deltaEl && deltaDir) {
        deltaEl.classList.remove('kpi-delta--up', 'kpi-delta--down', 'kpi-delta--flat');
        deltaEl.classList.add(`kpi-delta--${deltaDir}`);
      }
    }
  }

  function _applyKpiState(id, state) {
    const { el } = kpiCards[id];
    el.setAttribute('data-state', state);
  }

  /* ── Wazuh Event Integration ───────────────────────────── */
  /**
   * Listen for Wazuh connection state changes and update panels.
   * When disconnected/errored: move all panels to 'error'.
   * When connected: panels should be refreshed by WebhookReceiver.
   */
  function attachWazuhListeners() {
    window.addEventListener('wazuh:statechange', (e) => {
      const { current } = e.detail;

      if (current === 'error') {
        Object.keys(panels).forEach(id => {
          if (panels[id].currentState === 'loading') {
            setState(id, 'error');
          }
        });
      }

      if (current === 'not-connected') {
        // Only move panels back to loading if they have no data
        Object.keys(panels).forEach(id => {
          if (panels[id].currentState !== 'data') setState(id, 'loading');
        });
      }
    });
  }

  /* ════════════════════════════════════════════════════════════
     WEBHOOK DATA INTEGRATION
     Called by receiver.js when alerts arrive via SSE.
  ════════════════════════════════════════════════════════════ */

  /**
   * Use-case → panel/KPI/rows mapping
   */
  const USE_CASE_MAP = {
    critical_alerts: {
      panelId: 'panel-critical-alerts',
      kpiId:   'kpi-critical-alerts',
      rowsId:  'critical-alerts-rows',
      renderer: _renderCriticalAlert,
      kpiDir:  'up',
    },
    blind_spots_agent_health: {
      panelId: 'panel-blind-spots',
      kpiId:   'kpi-blind-spots',
      rowsId:  'blind-spots-rows',
      renderer: _renderBlindSpotAlert,
      kpiDir:  'up',
    },
    critical_file_changes: {
      panelId: 'panel-file-changes',
      kpiId:   'kpi-file-changes',
      rowsId:  'file-changes-rows',
      renderer: _renderFileChangeAlert,
      kpiDir:  'up',
    },
    auth_access_anomalies: {
      panelId: 'panel-auth-anomalies',
      kpiId:   'kpi-access-anomalies',
      rowsId:  'auth-anomalies-rows',
      renderer: _renderAuthAlert,
      kpiDir:  'up',
    },
    threat_intel_matches: {
      panelId: 'panel-threat-intel',
      kpiId:   'kpi-threat-intel',
      rowsId:  'threat-intel-rows',
      renderer: _renderThreatIntelAlert,
      kpiDir:  'up',
    },
  };

  const _storedAlertsByUseCase = {};
  let _activeFilterFn = null;

  /**
   * Ingest a batch of alerts for a use case and render them.
   * Called by receiver.js with the top-N alerts from the server store.
   * @param {string}  useCase   — aegis_use_case value
   * @param {Array}   alerts    — array of alert objects (most recent first)
   * @param {boolean} [replace] — if true, replace all rows (snapshot/sync); if false, prepend new rows only
   */
  function ingestAlerts(useCase, alerts = [], replace = false) {
    const mapping = USE_CASE_MAP[useCase];
    if (!mapping) {
      console.warn(`[PanelManager] Unknown use case: ${useCase}`);
      return;
    }

    if (replace || !_storedAlertsByUseCase[useCase]) {
      _storedAlertsByUseCase[useCase] = [...alerts];
    } else {
      _storedAlertsByUseCase[useCase] = [...alerts, ..._storedAlertsByUseCase[useCase]];
    }

    const currentAlerts = _activeFilterFn 
      ? _storedAlertsByUseCase[useCase].filter(_activeFilterFn)
      : _storedAlertsByUseCase[useCase];

    _renderPanelAlerts(useCase, currentAlerts, replace);
  }

  function _renderPanelAlerts(useCase, alerts = [], replace = true) {
    const mapping = USE_CASE_MAP[useCase];
    if (!mapping) return;

    const container = document.getElementById(mapping.rowsId);
    if (!container) return;

    if (!alerts || alerts.length === 0) {
      container.innerHTML = '';
      setState(mapping.panelId, 'empty');
      _updateKpi(mapping.kpiId, 0, mapping.kpiDir);
      const panel = document.getElementById(mapping.panelId);
      const badge = panel?.querySelector('.panel-count-badge');
      if (badge) badge.textContent = '0';
      return;
    }

    // Sort by severity desc then timestamp desc
    const sorted = [...alerts].sort((a, b) => {
      const lvA = parseInt(a?.rule?.level ?? 0, 10);
      const lvB = parseInt(b?.rule?.level ?? 0, 10);
      if (lvB !== lvA) return lvB - lvA;
      const tsA = new Date(a.timestamp || a.receivedAt || a['@timestamp'] || 0).getTime();
      const tsB = new Date(b.timestamp || b.receivedAt || b['@timestamp'] || 0).getTime();
      return tsB - tsA;
    });

    container.innerHTML = sorted.map(mapping.renderer).join('');
    setState(mapping.panelId, 'data');

    const rowCount = container.children.length;
    const panel = document.getElementById(mapping.panelId);
    const badge = panel?.querySelector('.panel-count-badge');

    _updateKpi(mapping.kpiId, rowCount, mapping.kpiDir);
    if (badge) badge.textContent = rowCount;
  }

  function setFilter(filterFn) {
    _activeFilterFn = filterFn;
    reRenderAllPanels();
  }

  function clearFilter() {
    _activeFilterFn = null;
    reRenderAllPanels();
  }

  function reRenderAllPanels() {
    Object.keys(USE_CASE_MAP).forEach(useCase => {
      const allForCase = _storedAlertsByUseCase[useCase] || [];
      const current = _activeFilterFn ? allForCase.filter(_activeFilterFn) : allForCase;
      _renderPanelAlerts(useCase, current, true);
    });
  }

  /**
   * Update a KPI card to show an event count.
   */
  function _updateKpi(kpiId, count, dir) {
    const sub = `${count} event${count !== 1 ? 's' : ''} received`;
    setKpiState(
      kpiId,
      'data',
      String(count),
      sub,
      dir ?? 'up',
    );
  }

  /* ── Row Renderers (one per use case) ──────────────────── */

  /**
   * Severity level → CSS class for dot + chip colour
   */
  function _levelClass(level) {
    const n = parseInt(level, 10);
    if (n >= 12) return 'crit';
    if (n >= 7)  return 'warn';
    return 'ok';
  }

  /** Format ISO timestamp to "HH:MM" or relative "Xm ago" */
  function _relTime(ts) {
    if (!ts) return '—';
    try {
      const d    = new Date(ts);
      const diff = Date.now() - d.getTime();
      const mins = Math.floor(diff / 60000);
      if (mins < 1)  return 'just now';
      if (mins < 60) return `${mins}m ago`;
      const hrs = Math.floor(mins / 60);
      if (hrs < 24)  return `${hrs}h ago`;
      return d.toLocaleDateString();
    } catch { return '—'; }
  }

  /** Escape HTML to prevent XSS in injected alert text */
  function _esc(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /* USE CASE 1: Critical Alerts */
  function _renderCriticalAlert(alert) {
    const level  = alert.rule?.level ?? 0;
    const cls    = _levelClass(level);
    const desc   = _esc(alert.rule?.description ?? 'Unknown rule');
    const agent  = _esc(alert.agent?.name ?? 'unknown agent');
    const mitre  = _esc(alert.rule?.mitre?.technique?.[0] ?? alert.rule?.groups?.[0] ?? '');
    const sub    = [agent, mitre].filter(Boolean).join(' · ');
    const time   = _relTime(alert.timestamp ?? alert.receivedAt);
    const alertId = alert.id || alert._id || '';

    const ticketBadge = alert.redmine_ticket
      ? `<a href="${alert.redmine_ticket.url}" target="_blank" class="redmine-ticket-badge" onclick="event.stopPropagation()" title="View Ticket #${alert.redmine_ticket.id}">🎟️ #${alert.redmine_ticket.id}</a>`
      : `<button class="btn-dispatch-ticket" style="padding:2px 6px; font-size:10px;" onclick="event.stopPropagation(); window.RedmineDispatchController && RedmineDispatchController.openSingleModal(PanelManager.getAlertById('${alertId}'))" title="Dispatch to Redmine"><i data-lucide="ticket" style="width:11px;height:11px;"></i></button>`;

    return `<div class="data-row" style="cursor:pointer;" onclick="window.RedmineDispatchController && RedmineDispatchController.openSingleModal(PanelManager.getAlertById('${alertId}'))">
  <div class="row-dot row-dot--${cls}"></div>
  <div class="row-body">
    <span class="row-title">${desc}</span>
    <span class="row-sub">${sub}</span>
  </div>
  <div style="display:flex; align-items:center; gap:6px;">
    ${ticketBadge}
    <span class="row-chip row-chip--${cls}">L${level}</span>
    <span class="row-time">${time}</span>
  </div>
</div>`;
  }

  /* USE CASE 2: Blind Spots & Agent Health */
  function _renderBlindSpotAlert(alert) {
    const level = alert.rule?.level ?? 0;
    const cls   = _levelClass(level);
    const desc  = _esc(alert.rule?.description ?? 'Agent event');
    const agent = _esc(alert.agent?.name ?? 'unknown');
    const ip    = _esc(alert.agent?.ip ?? '');
    const sub   = ip ? `${agent} · ${ip}` : agent;
    const time  = _relTime(alert.timestamp ?? alert.receivedAt);

    return `<div class="data-row">
  <div class="row-dot row-dot--${cls}"></div>
  <div class="row-body">
    <span class="row-title">${desc}</span>
    <span class="row-sub">${sub}</span>
  </div>
  <span class="row-chip row-chip--${cls}">L${level}</span>
  <span class="row-time">${time}</span>
</div>`;
  }

  /* USE CASE 3: Redmine Resolved Fixes & File Changes */
  function _renderFileChangeAlert(alert) {
    const isFix  = alert.action === 'redmine_fix_synced' || !alert.rule?.level;
    const level  = alert.rule?.level ?? 0;
    const cls    = isFix ? 'ok' : _levelClass(level);
    const desc   = _esc(alert.subject || alert.rule?.description || alert.filename || 'Resolved fix');
    const fpath  = _esc(alert.filename || alert.syscheck?.path || alert.data?.path || '');
    const user   = _esc(alert.user || alert.author?.name || alert.agent?.name || 'Redmine');
    const sub    = [fpath, user].filter(Boolean).join(' · ');
    const time   = _relTime(alert.timestamp ?? alert.receivedAt ?? alert.updated_on);
    const chipText = isFix ? 'FIXED' : `L${level}`;

    return `<div class="data-row">
  <div class="row-dot row-dot--${cls}"></div>
  <div class="row-body">
    <span class="row-title">${desc}</span>
    <span class="row-sub">${sub}</span>
  </div>
  <span class="row-chip row-chip--${cls}">${chipText}</span>
  <span class="row-time">${time}</span>
</div>`;
  }

  /* USE CASE 4: Authentication & Access Anomalies */
  function _renderAuthAlert(alert) {
    const level  = alert.rule?.level ?? 0;
    const cls    = _levelClass(level);
    const desc   = _esc(alert.rule?.description ?? 'Auth event');
    const srcip  = _esc(alert.source?.srcip ?? alert.data?.srcip ?? '');
    const srcusr = _esc(alert.source?.srcuser ?? alert.data?.srcuser ?? '');
    const agent  = _esc(alert.agent?.name ?? '');
    const sub    = [srcusr, srcip, agent].filter(Boolean).join(' · ');
    const time   = _relTime(alert.timestamp ?? alert.receivedAt);

    return `<div class="data-row">
  <div class="row-dot row-dot--${cls}"></div>
  <div class="row-body">
    <span class="row-title">${desc}</span>
    <span class="row-sub">${sub}</span>
  </div>
  <span class="row-chip row-chip--${cls}">L${level}</span>
  <span class="row-time">${time}</span>
</div>`;
  }

  /* USE CASE 5: Threat Intelligence Matches */
  function _renderThreatIntelAlert(alert) {
    const level  = alert.rule?.level ?? 0;
    const cls    = _levelClass(level);
    const desc   = _esc(alert.rule?.description ?? 'Threat intel match');
    const vtDesc = _esc(alert.data?.virustotal?.description ?? '');
    const url    = _esc(alert.source?.url ?? alert.data?.url ?? '');
    const agent  = _esc(alert.agent?.name ?? '');
    const sub    = [vtDesc || url, agent].filter(Boolean).join(' · ');
    const time   = _relTime(alert.timestamp ?? alert.receivedAt);
    const alertId = alert.id || alert._id || '';

    const ticketBadge = alert.redmine_ticket
      ? `<a href="${alert.redmine_ticket.url}" target="_blank" class="redmine-ticket-badge" onclick="event.stopPropagation()" title="View Ticket #${alert.redmine_ticket.id}">🎟️ #${alert.redmine_ticket.id}</a>`
      : `<button class="btn-dispatch-ticket" style="padding:2px 6px; font-size:10px;" onclick="event.stopPropagation(); window.RedmineDispatchController && RedmineDispatchController.openSingleModal(PanelManager.getAlertById('${alertId}'))" title="Dispatch to Redmine"><i data-lucide="ticket" style="width:11px;height:11px;"></i></button>`;

    return `<div class="data-row" style="cursor:pointer;" onclick="window.RedmineDispatchController && RedmineDispatchController.openSingleModal(PanelManager.getAlertById('${alertId}'))">
  <div class="row-dot row-dot--${cls}"></div>
  <div class="row-body">
    <span class="row-title">${desc}</span>
    <span class="row-sub">${sub}</span>
  </div>
  <div style="display:flex; align-items:center; gap:6px;">
    ${ticketBadge}
    <span class="row-chip row-chip--${cls}">L${level}</span>
    <span class="row-time">${time}</span>
  </div>
</div>`;
  }

  function getAlertById(id) {
    for (const list of Object.values(_storedAlertsByUseCase)) {
      const found = list.find(a => String(a.id || a._id) === String(id));
      if (found) return found;
    }
    return null;
  }

  return {
    register,
    setState,
    getState,
    registerKpi,
    setKpiState,
    attachWazuhListeners,
    ingestAlerts,
    setFilter,
    clearFilter,
    reRenderAllPanels,
    getAlertById,
  };
})();

window.PanelManager = PanelManager;
