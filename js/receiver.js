/**
 * AEGIS SOC — Webhook Receiver (Browser side)
 *
 * Responsibilities:
 *  1. Connect to GET /api/events (SSE) for real-time alert delivery
 *  2. On initial load: fetch GET /api/dashboard-data to restore state
 *  3. Route each incoming alert to PanelManager.ingestAlert()
 *  4. Drive topbar + integration-card badge via wazuh:statechange events
 *
 * Does NOT:
 *  - Poll Wazuh directly
 *  - Initiate any connection to the Wazuh Manager API
 *  - Modify any UI element directly (delegates entirely to PanelManager)
 */

'use strict';

const WebhookReceiver = (() => {
  const SERVER_BASE = ''; // same origin — server serves static files too
  let _eventSource  = null;
  let _connected    = false;

  /* ════════════════════════════════════════════════════════════
     INIT
  ════════════════════════════════════════════════════════════ */
  function init() {
    // Open SSE stream for live updates (TimeRangePicker handles initial time-filtered snapshot)
    _connectSSE();

    console.log('[WebhookReceiver] Initialized — listening on /api/events');
  }

  /* ════════════════════════════════════════════════════════════
     SSE CONNECTION
  ════════════════════════════════════════════════════════════ */
  function _connectSSE() {
    if (!window.EventSource) {
      console.warn('[WebhookReceiver] EventSource not supported — falling back to polling');
      _startPolling();
      return;
    }

    _eventSource = new EventSource(`${SERVER_BASE}/api/events`);

    /* ── connected ──────────────────────────────────────────── */
    _eventSource.addEventListener('connected', () => {
      console.log('[WebhookReceiver] SSE stream connected');
      _setState('connected');  // SSE alive = server is reachable = CONNECTED
    });

    /* ── snapshot (full store on reconnect — trigger time-range reload) */
    _eventSource.addEventListener('snapshot', (e) => {
      if (window.TimeRangePicker && TimeRangePicker.reload) {
        TimeRangePicker.reload();
      } else {
        try {
          const store = JSON.parse(e.data);
          for (const [useCase, alerts] of Object.entries(store)) {
            PanelManager.ingestAlerts(useCase, alerts || [], true);
          }
        } catch (err) {
          console.warn('[WebhookReceiver] Bad snapshot data:', err);
        }
      }
      _setState('connected');
    });

    /* ── alert (single incoming alert — filter by active time range) */
    _eventSource.addEventListener('alert', (e) => {
      try {
        const { useCase, alert } = JSON.parse(e.data);
        if (window.TimeRangePicker && TimeRangePicker.isInRange) {
          if (!TimeRangePicker.isInRange(alert)) return;
        }
        PanelManager.ingestAlerts(useCase, [alert]);
        _setState('connected');
      } catch (err) {
        console.warn('[WebhookReceiver] Bad alert event:', err);
      }
    });

    /* ── sync-done (backfill completed — reload time-range dashboard) */
    _eventSource.addEventListener('sync-done', (e) => {
      try {
        const info = JSON.parse(e.data);
        console.log(`[WebhookReceiver] Sync complete — ${info.accepted} alerts ingested`);
        if (window.TimeRangePicker && TimeRangePicker.reload) {
          TimeRangePicker.reload();
        }
        if (typeof Toast !== 'undefined') {
          Toast.show({
            type: 'ok',
            title: '30-Day Sync Complete',
            body: `${info.accepted} historical alerts loaded into Dashboard.`,
            duration: 5000,
          });
        }
      } catch (err) {
        console.warn('[WebhookReceiver] Bad sync-done event:', err);
      }
    });

    /* ── SSE error / disconnect ─────────────────────── */
    _eventSource.addEventListener('error', () => {
      console.warn('[WebhookReceiver] SSE error / signal dropped');
      _setState('disconnected');
    });
  }

  /* ════════════════════════════════════════════════════════════
     POLLING FALLBACK (if EventSource unavailable)
  ════════════════════════════════════════════════════════════ */
  let _pollLastCounts = {};

  function _startPolling() {
    setInterval(async () => {
      try {
        const res  = await fetch(`${SERVER_BASE}/api/dashboard-data`);
        if (!res.ok) throw new Error('Server unreachable');
        const data = await res.json();

        _setState('connected');

        for (const [useCase, { count, alerts }] of Object.entries(data)) {
          if (count !== (_pollLastCounts[useCase] ?? -1) && alerts.length > 0) {
            _pollLastCounts[useCase] = count;
            PanelManager.ingestAlerts(useCase, alerts, true); // replace=true: polling always replaces
          }
        }
      } catch (_) {
        _setState('disconnected');
      }
    }, 5000);
  }

  /* ════════════════════════════════════════════════════════════
     TOPBAR + BADGE STATE
  ════════════════════════════════════════════════════════════ */
  let _currentState = 'not-connected';

  function _setState(state) {
    if (_currentState === state) return;
    _currentState = state;

    if (window.WazuhClient && WazuhClient.setState) {
      WazuhClient.setState(state);
    } else {
      window.dispatchEvent(new CustomEvent('wazuh:statechange', {
        detail: { current: state },
      }));
    }
  }

  /* ── Public surface ─────────────────────────────────────── */
  return { init };
})();

window.WebhookReceiver = WebhookReceiver;
