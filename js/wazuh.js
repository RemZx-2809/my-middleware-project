/**
 * Aegis SOC — Wazuh API Client (Stub)
 *
 * This module provides the state machine and API interface for
 * connecting to the Wazuh REST API. All fetch methods currently
 * return null (no data) until a real Wazuh server is configured.
 *
 * Integration points:
 *   1. Set config.baseUrl and config.token, then call connect().
 *   2. Each data method will call the appropriate Wazuh endpoint.
 *   3. The 'statechange' event fires whenever connection state updates.
 *
 * Endpoint mapping (to implement):
 *   Critical Alerts      → GET /alerts (severity >= high)
 *   File/System Changes  → GET /syscheck
 *   Blind Spots / Agents → GET /agents (status != active)
 *   Auth Anomalies       → GET /alerts?rule.groups=authentication
 *   Threat Intel         → GET /alerts?rule.groups=threat_intel
 */

'use strict';

const WazuhClient = (() => {
  /* ── Connection States ─────────────────────────────────── */
  const STATES = {
    NOT_CONNECTED: 'not-connected',
    CONNECTING:    'connecting',
    CONNECTED:     'connected',
    ERROR:         'error',
  };

  /* ── Internal State ────────────────────────────────────── */
  let _state = STATES.NOT_CONNECTED;
  let _config = {
    baseUrl: null,    // e.g. "https://wazuh.yourdomain.com:55000"
    token:   null,    // JWT from POST /security/user/authenticate
    timeout: 10000,
  };
  let _listeners = [];

  /* ── State Machine ─────────────────────────────────────── */
  function setState(newState) {
    if (_state === newState) return;
    const prev = _state;
    _state = newState;
    _emit('statechange', { prev, current: newState });
  }

  function _emit(event, detail = {}) {
    _listeners
      .filter(l => l.event === event)
      .forEach(l => {
        try { l.handler({ ...detail, event }); }
        catch (e) { console.error('[WazuhClient] Listener error:', e); }
      });

    // Also dispatch a DOM event for convenience
    window.dispatchEvent(
      new CustomEvent(`wazuh:${event}`, { detail: { ...detail, event } })
    );
  }

  /* ── Public API ────────────────────────────────────────── */
  const client = {
    STATES,

    get state() { return _state; },

    /** Explicitly update connection state and trigger statechange event */
    setState(newState) {
      setState(newState);
    },

    /** Configure the client with a Wazuh base URL and auth token. */
    configure(baseUrl, token) {
      _config.baseUrl = baseUrl;
      _config.token   = token;
    },

    /** Subscribe to client events: 'statechange', 'data' */
    on(event, handler) {
      _listeners.push({ event, handler });
      return () => { _listeners = _listeners.filter(l => l.handler !== handler); };
    },

    /**
     * Attempt to connect to Wazuh.
     * In the stub: immediately transitions to NOT_CONNECTED (no server configured).
     * In production: call POST /security/user/authenticate and store JWT.
     */
    async connect() {
      if (!_config.baseUrl || !_config.token) {
        setState(STATES.NOT_CONNECTED);
        console.warn('[WazuhClient] No baseUrl or token configured. Staying NOT_CONNECTED.');
        return false;
      }

      setState(STATES.CONNECTING);
      try {
        // TODO: verify token / ping Wazuh API
        // const res = await fetch(`${_config.baseUrl}/`, { headers: _authHeaders() });
        // if (!res.ok) throw new Error(`HTTP ${res.status}`);
        setState(STATES.CONNECTED);
        return true;
      } catch (err) {
        console.error('[WazuhClient] Connection failed:', err);
        setState(STATES.ERROR);
        return false;
      }
    },

    disconnect() {
      setState(STATES.NOT_CONNECTED);
      _config.token = null;
    },

    /* ── Data Methods (all return null until connected) ──── */

    /**
     * GET /alerts — critical/high severity alerts
     * @returns {Promise<Array|null>}
     */
    async getCriticalAlerts() {
      return _fetch('/alerts', {
        'filters': JSON.stringify({ 'rule.level': { '$gte': 12 } }),
        'limit': 50,
      });
    },

    /**
     * GET /syscheck — File Integrity Monitoring events
     * @returns {Promise<Array|null>}
     */
    async getSyscheck() {
      return _fetch('/syscheck', { 'limit': 50 });
    },

    /**
     * GET /agents — agents that are not active (blind spots)
     * @returns {Promise<Array|null>}
     */
    async getOfflineAgents() {
      return _fetch('/agents', {
        'status': 'disconnected,never_connected',
        'limit': 50,
      });
    },

    /**
     * GET /alerts?rule.groups=authentication — auth anomalies
     * @returns {Promise<Array|null>}
     */
    async getAuthAlerts() {
      return _fetch('/alerts', {
        'q': 'rule.groups~authentication',
        'limit': 50,
      });
    },

    /**
     * GET /alerts?rule.groups=threat_intel — threat intel matches
     * @returns {Promise<Array|null>}
     */
    async getThreatIntel() {
      return _fetch('/alerts', {
        'q': 'rule.groups~threat_intel',
        'limit': 50,
      });
    },

    /**
     * GET /agents — count: total and active (for sidebar footer)
     * @returns {Promise<{total: number, active: number}|null>}
     */
    async getAgentSummary() {
      const result = await _fetch('/agents/summary/status');
      if (!result) return null;
      return {
        total:  result?.data?.connection?.total  ?? 0,
        active: result?.data?.connection?.active ?? 0,
      };
    },
  };

  /* ── Private Helpers ───────────────────────────────────── */
  function _authHeaders() {
    return {
      'Authorization': `Bearer ${_config.token}`,
      'Content-Type':  'application/json',
    };
  }

  async function _fetch(path, params = {}) {
    if (_state !== STATES.CONNECTED) return null;

    const url = new URL(`${_config.baseUrl}${path}`);
    Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));

    try {
      const res = await fetch(url.toString(), {
        headers: _authHeaders(),
        signal: AbortSignal.timeout(_config.timeout),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      return json?.data?.affected_items ?? json?.data ?? null;
    } catch (err) {
      console.error(`[WazuhClient] Fetch ${path} failed:`, err);
      return null;
    }
  }

  return client;
})();

// Make available globally
window.WazuhClient = WazuhClient;
