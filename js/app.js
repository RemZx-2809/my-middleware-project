/**
 * Aegis SOC — App Entry Point
 *
 * Bootstraps all controllers, registers panels, and wires keyboard shortcuts.
 *
 * Data flow (push-only):
 *   Wazuh → POST /api/wazuh-webhook → server.js → SSE /api/events
 *     → WebhookReceiver → PanelManager.ingestAlerts()
 *   The app NEVER initiates a request to Wazuh.
 */

'use strict';


document.addEventListener('DOMContentLoaded', () => {
  /* ── Initialize Controllers ────────────────────────────── */
  SidebarController.init();
  TopbarController.init();
  PanelManager.attachWazuhListeners();
  IntegrationsController.init();
  if (window.RulesEditorController) RulesEditorController.init();
  if (window.SshAuthController)     SshAuthController.init();
  if (window.TerminalController)    TerminalController.init();
  WebhookReceiver.init();      // connects SSE, populates panels from push data
  if (window.TimeRangePicker) TimeRangePicker.init(); // time range picker (also does initial data fetch)

  /* ── Register KPI Cards ────────────────────────────────── */
  [
    'kpi-critical-alerts',
    'kpi-blind-spots',
    'kpi-file-changes',
    'kpi-access-anomalies',
    'kpi-threat-intel',
  ].forEach(id => PanelManager.registerKpi(id));

  // KPI cards: start loading, move to empty after delay unless receiver
  // has already populated them with real Wazuh push data.
  setTimeout(() => {
    const kpis = [
      ['kpi-critical-alerts',  'critical_alerts'],
      ['kpi-blind-spots',      'blind_spots_agent_health'],
      ['kpi-file-changes',     'critical_file_changes'],
      ['kpi-access-anomalies', 'auth_access_anomalies'],
      ['kpi-threat-intel',     'threat_intel_matches'],
    ];
    kpis.forEach(([kpiId]) => {
      const card = document.getElementById(kpiId);
      // Only set empty if receiver hasn't already set it to 'data'
      if (card && card.getAttribute('data-state') === 'loading') {
        PanelManager.setKpiState(kpiId, 'empty', '—', 'awaiting Wazuh data');
      }
    });
  }, 1400);

  /* ── Register Panels ───────────────────────────────────── */
  [
    'panel-critical-alerts',
    'panel-file-changes',
    'panel-blind-spots',
    'panel-auth-anomalies',
    'panel-threat-intel',
  ].forEach(id => PanelManager.register(id));

  // Panels: start loading → move to empty after delay unless receiver
  // has already populated them with real Wazuh push data.
  setTimeout(() => {
    const panelIds = [
      'panel-critical-alerts',
      'panel-file-changes',
      'panel-blind-spots',
      'panel-auth-anomalies',
      'panel-threat-intel',
    ];
    panelIds.forEach(id => {
      if (PanelManager.getState(id) === 'loading') {
        PanelManager.setState(id, 'empty');
      }
    });
  }, 1600);

  /* ── Sidebar Toggle Button ─────────────────────────────── */
  const toggleBtn = document.getElementById('sidebar-toggle');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => SidebarController.toggle());
  }

  /* ── Panel Refresh Buttons ─────────────────────────────── */
  document.querySelectorAll('.panel-refresh-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const icon = btn.querySelector('svg');
      if (icon) {
        icon.classList.add('spinning');
        setTimeout(() => icon.classList.remove('spinning'), 700);
      }
      // Re-fetch with current time range
      if (window.TimeRangePicker) TimeRangePicker.reload();
    });
  });

  /* ── Keyboard Shortcuts ────────────────────────────────── */
  document.addEventListener('keydown', (e) => {
    const tag = document.activeElement?.tagName;
    const inInput = tag === 'INPUT' || tag === 'TEXTAREA';

    // "/" → focus search
    if (e.key === '/' && !inInput) {
      e.preventDefault();
      const search = document.getElementById('search-input');
      if (search) { search.focus(); search.select(); }
    }

    // Ctrl+B → toggle sidebar
    if (e.key === 'b' && (e.ctrlKey || e.metaKey) && !inInput) {
      e.preventDefault();
      SidebarController.toggle();
    }

    // Escape → blur search, close dropdown
    if (e.key === 'Escape') {
      const search = document.getElementById('search-input');
      if (search && document.activeElement === search) search.blur();
    }
  });

  /* ── Lucide Icons ──────────────────────────────────────── */
  if (typeof lucide !== 'undefined') {
    lucide.createIcons();
  }

  console.log('[Aegis SOC] Dashboard initialized.');
  console.log('[Aegis SOC] Webhook receiver active — waiting for Wazuh push data on /api/events');
  console.log('[Aegis SOC] Wazuh should POST to: http://<this-server>:3000/api/wazuh-webhook');
});
