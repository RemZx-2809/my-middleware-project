/**
 * Aegis SOC — Wazuh Integration Settings Controller
 *
 * Responsibilities:
 *  1. Auth-method tab toggle (Username/Password ↔ API Token)
 *  2. Password / token reveal buttons
 *  3. Persist connection settings to localStorage & server backend
 *  4. "Test Connection" — tests connection via backend proxy POST /api/wazuh-test
 *     (bypassing browser CORS & self-signed SSL cert issues), falls back to direct fetch.
 *  5. "Save Settings" — writes config to localStorage, updates server
 *     webhook secret, and calls WazuhClient.configure().
 *  6. "Clear" — wipes stored settings and resets the form + status.
 *  7. "Cancel" — returns to the main Security Overview dashboard.
 */

'use strict';

const IntegrationsController = (() => {

  /* ── Storage key ────────────────────────────────────────── */
  const STORAGE_KEY = 'aegis-wazuh-config';

  /* ── DOM refs (populated in init) ──────────────────────── */
  let _el = {};

  /* ── Current auth mode ──────────────────────────────────── */
  let _authMode = 'userpass'; // 'userpass' | 'token'

  /* ── Whether the last test succeeded ───────────────────── */
  let _testPassed = false;

  /* ══════════════════════════════════════════════════════════
     INIT
  ══════════════════════════════════════════════════════════ */
  function init() {
    _el = {
      apiUrl:        document.getElementById('wazuh-api-url'),
      apiPort:       document.getElementById('wazuh-api-port'),
      username:      document.getElementById('wazuh-username'),
      password:      document.getElementById('wazuh-password'),
      jwtToken:      document.getElementById('wazuh-jwt-token'),
      sslVerify:     document.getElementById('wazuh-ssl-verify'),
      webhookSecret: document.getElementById('wazuh-webhook-secret'),

      tabUserpass:   document.getElementById('auth-toggle-userpass'),
      tabToken:      document.getElementById('auth-toggle-token'),
      panelUserpass: document.getElementById('auth-fields-userpass'),
      panelToken:    document.getElementById('auth-fields-token'),

      pwReveal:      document.getElementById('password-reveal-btn'),
      tokenReveal:   document.getElementById('token-reveal-btn'),

      testBtn:       document.getElementById('wazuh-test-btn'),
      saveBtn:       document.getElementById('wazuh-save-btn'),
      clearBtn:      document.getElementById('wazuh-clear-btn'),
      cancelBtn:     document.getElementById('wazuh-cancel-btn'),

      testResult:    document.getElementById('wazuh-test-result'),
      badge:         document.getElementById('int-wazuh-badge'),
    };

    if (!_el.testBtn) return;

    _bindAuthTabs();
    _bindRevealBtns();
    _bindActions();
    _bindInputCleaners();
    _loadSaved();
    _syncBadgeFromWazuh();

    window.addEventListener('wazuh:statechange', () => _syncBadgeFromWazuh());

    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }

    console.log('[IntegrationsController] Initialized settings form handlers.');
  }

  /* ══════════════════════════════════════════════════════════
     INPUT CLEANING & VALIDATION HELPERS
  ══════════════════════════════════════════════════════════ */
  function _bindInputCleaners() {
    _el.username?.addEventListener('input', _validateUsername);
    _el.username?.addEventListener('blur', _validateUsername);

    _el.apiUrl?.addEventListener('blur', () => {
      _buildBaseUrl(); // auto-normalizes protocol & port
    });
  }

  function _validateUsername() {
    const val = (_el.username?.value ?? '').trim();
    const warnEl = document.getElementById('wazuh-username-warning');

    if (/^https?:\/\//i.test(val) || val.includes('/') || (val.includes(':') && !val.includes('@'))) {
      if (warnEl) {
        warnEl.style.display = 'block';
        warnEl.textContent = '⚠ Username should be a user ID (e.g. wazuh-wui or admin), not a server URL.';
      }
      return false;
    } else {
      if (warnEl) warnEl.style.display = 'none';
      return true;
    }
  }

  /* ══════════════════════════════════════════════════════════
     AUTH TAB TOGGLE
  ══════════════════════════════════════════════════════════ */
  function _bindAuthTabs() {
    [_el.tabUserpass, _el.tabToken].forEach(tab => {
      if (!tab) return;
      tab.addEventListener('click', () => _setAuthMode(tab.dataset.auth));
    });
  }

  function _setAuthMode(mode) {
    _authMode = mode;

    const isUserpass = mode === 'userpass';

    _el.tabUserpass?.classList.toggle('active', isUserpass);
    _el.tabToken?.classList.toggle('active', !isUserpass);
    _el.tabUserpass?.setAttribute('aria-pressed', String(isUserpass));
    _el.tabToken?.setAttribute('aria-pressed', String(!isUserpass));

    if (_el.panelUserpass) _el.panelUserpass.style.display = isUserpass ? 'flex' : 'none';
    if (_el.panelToken)    _el.panelToken.style.display    = isUserpass ? 'none' : 'flex';

    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  /* ══════════════════════════════════════════════════════════
     PASSWORD / TOKEN REVEAL
  ══════════════════════════════════════════════════════════ */
  function _bindRevealBtns() {
    _bindReveal(_el.pwReveal, _el.password, 'Password');
    _bindReveal(_el.tokenReveal, _el.jwtToken, 'JWT Token');
  }

  function _bindReveal(btn, input, labelName = 'Field') {
    if (!btn || !input) return;
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();

      const isHidden = input.type === 'password';
      input.type = isHidden ? 'text' : 'password';
      btn.classList.toggle('active', isHidden);

      const iconName = isHidden ? 'eye-off' : 'eye';
      btn.innerHTML = `<i data-lucide="${iconName}"></i>`;
      if (typeof lucide !== 'undefined') lucide.createIcons();
      btn.setAttribute('aria-label', isHidden ? `Hide ${labelName}` : `Show ${labelName}`);

      console.log(`[IntegrationsController] ${labelName} visibility toggled to ${input.type}.`);

      if (!input.value && isHidden) {
        Toast.show({
          type: 'info',
          title: `${labelName} Visible`,
          body: `${labelName} field is currently empty. Type a ${labelName.toLowerCase()} to see plain text.`,
          duration: 3000,
        });
      }
    });
  }

  /* ══════════════════════════════════════════════════════════
     ACTION BUTTONS
  ══════════════════════════════════════════════════════════ */
  function _bindActions() {
    _el.testBtn?.addEventListener('click', _handleTest);
    _el.saveBtn?.addEventListener('click', _handleSave);
    _el.clearBtn?.addEventListener('click', _handleClear);
    _el.cancelBtn?.addEventListener('click', _handleCancel);
  }

  /* ── Test Connection ──────────────────────────────────── */
  async function _handleTest() {
    console.log('[IntegrationsController] "Test Connection" button clicked.');

    const url  = _buildBaseUrl();
    const creds = _collectCredentials();

    if (!url) {
      const title = 'Missing API URL';
      const detail = 'Please enter a valid Wazuh Manager API URL (e.g. 10.145.10.58 or wazuh-manager).';
      _showResult('error', title, detail);
      Toast.show({ type: 'warn', title, body: detail, duration: 4500 });
      return;
    }

    if (_authMode === 'userpass' && !_validateUsername()) {
      const title = 'Invalid Username';
      const detail = 'Username field contains a URL. Please enter your Wazuh API user name (e.g. wazuh-wui).';
      _showResult('error', title, detail);
      Toast.show({ type: 'warn', title, body: detail, duration: 4500 });
      return;
    }

    if (!creds) {
      const title = 'Missing Credentials';
      const detail = _authMode === 'userpass'
        ? 'Please enter both Username and Password.'
        : 'Please enter a valid JWT API Token.';
      _showResult('error', title, detail);
      Toast.show({ type: 'warn', title, body: detail, duration: 4500 });
      return;
    }

    _setTestBusy(true);
    _showResult('pending', 'Testing connection…', `Connecting to ${url}`);
    _setBadge('connecting');

    try {
      let token = null;

      // 1. Try testing via local backend proxy endpoint POST /api/wazuh-test
      // (This bypasses browser CORS and self-signed SSL cert errors)
      const payload = {
        baseUrl:   url,
        authMode:  _authMode,
        username:  creds.username || '',
        password:  creds.password || '',
        token:     creds.token || '',
        sslVerify: _el.sslVerify?.checked ?? true,
      };

      let testRes = null;
      try {
        const resp = await fetch('/api/wazuh-test', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify(payload),
          signal:  AbortSignal.timeout(12000),
        });
        testRes = await resp.json();
      } catch (err) {
        console.warn('[IntegrationsController] Backend test endpoint unavailable, trying direct fetch:', err.message);
      }

      if (testRes) {
        if (!testRes.ok) {
          throw new Error(testRes.error || 'Connection failed.');
        }
        token = testRes.token || creds.token || null;
      } else {
        // Fallback: direct browser fetch
        if (_authMode === 'token') {
          token = creds.token;
          const ok = await _pingWithToken(url, token, _el.sslVerify?.checked ?? true);
          if (!ok) throw new Error('Token rejected or endpoint unreachable.');
        } else {
          token = await _authenticate(url, creds.username, creds.password, _el.sslVerify?.checked ?? true);
          if (!token) throw new Error('Authentication failed — check username and password.');
        }
      }

      // Success
      _testPassed = true;
      _showResult('success', 'Connection Successful', `Authenticated successfully · ${url}`);
      _setBadge('connected');

      WazuhClient.configure(url, token);
      if (typeof WazuhClient.setState === 'function') {
        WazuhClient.setState(WazuhClient.STATES.CONNECTED);
      } else {
        _dispatchWazuhState('connected');
      }

      Toast.show({
        type:  'ok',
        title: 'Wazuh Connected',
        body:  'Connection verified successfully. Click Save Settings to persist.',
        duration: 5000,
      });

    } catch (err) {
      console.error('[IntegrationsController] Connection test failed:', err);
      _testPassed = false;
      const msg = err.message || String(err);
      _showResult('error', 'Connection Failed', msg);
      _setBadge('disconnected');

      if (typeof WazuhClient.setState === 'function') {
        WazuhClient.setState(WazuhClient.STATES.NOT_CONNECTED);
      } else {
        _dispatchWazuhState('not-connected');
      }

      Toast.show({
        type:  'error',
        title: 'Connection Failed',
        body:  msg,
        duration: 6000,
      });
    } finally {
      _setTestBusy(false);
      const lastTestedEl = document.getElementById('int-last-tested');
      if (lastTestedEl) {
        const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        lastTestedEl.textContent = `Last tested: Today at ${timeStr}`;
      }
    }
  }

  /* ── Save Settings ────────────────────────────────────── */
  function _handleSave() {
    console.log('[IntegrationsController] "Save Settings" button clicked.');

    const url = _buildBaseUrl();

    if (!url) {
      Toast.show({ type: 'warn', title: 'Cannot Save Settings', body: 'Please enter a valid API URL first.', duration: 4000 });
      return;
    }

    if (_authMode === 'userpass' && !_validateUsername()) {
      Toast.show({ type: 'warn', title: 'Invalid Username', body: 'Please fix the Username field before saving.', duration: 4500 });
      return;
    }

    const config = {
      baseUrl:       url,
      authMode:      _authMode,
      username:      _el.username?.value.trim() ?? '',
      hasPassword:   !!_el.password?.value,
      token:         _authMode === 'token' ? (_el.jwtToken?.value.trim() ?? '') : '',
      sslVerify:     _el.sslVerify?.checked ?? true,
      webhookSecret: _el.webhookSecret?.value.trim() ?? '',
      savedAt:       Date.now(),
    };

    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
    } catch (e) {
      console.warn('[IntegrationsController] Could not write config to localStorage:', e);
    }

    // Also persist config & secret to server
    const secret = config.webhookSecret;
    if (secret) {
      fetch('/api/config', {
        method:  'PUT',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ webhookSecret: secret }),
      }).then(res => res.json())
        .then(resData => {
          if (resData.ok) console.log('[IntegrationsController] Server config updated.');
        })
        .catch(err => {
          console.warn('[IntegrationsController] Could not save secret to server:', err.message);
        });
    }

    const activeToken = _authMode === 'token' ? (_el.jwtToken?.value.trim() || null) : null;
    WazuhClient.configure(url, activeToken);

    Toast.show({
      type:  'ok',
      title: 'Settings Saved',
      body:  `Wazuh integration settings saved successfully.${_testPassed ? ' Connection verified.' : ' Run Test Connection to verify.'}`,
      duration: 4500,
    });

    _syncBadgeFromWazuh();
  }

  /* ── Clear Settings ───────────────────────────────────── */
  function _handleClear() {
    console.log('[IntegrationsController] "Clear" button clicked.');

    try { localStorage.removeItem(STORAGE_KEY); } catch (_) {}

    // Reset form inputs
    if (_el.apiUrl)        _el.apiUrl.value = 'wazuh-manager';
    if (_el.apiPort)       _el.apiPort.value = '55000';
    if (_el.username)      _el.username.value = '';
    if (_el.password)      { _el.password.value = ''; _el.password.placeholder = '••••••••••••'; }
    if (_el.jwtToken)      _el.jwtToken.value = '';
    if (_el.sslVerify)     _el.sslVerify.checked = true;
    if (_el.webhookSecret) _el.webhookSecret.value = '';

    const warnEl = document.getElementById('wazuh-username-warning');
    if (warnEl) warnEl.style.display = 'none';

    _setAuthMode('userpass');
    _hideResult();
    _setBadge('disconnected');
    _testPassed = false;

    if (typeof WazuhClient.disconnect === 'function') {
      WazuhClient.disconnect();
    }

    const lastTestedEl = document.getElementById('int-last-tested');
    if (lastTestedEl) {
      lastTestedEl.textContent = 'Last tested: Never';
    }

    Toast.show({
      type:  'info',
      title: 'Settings Cleared',
      body:  'Wazuh integration settings have been removed.',
      duration: 3500,
    });
  }

  /* ── Cancel Editing ───────────────────────────────────── */
  function _handleCancel() {
    console.log('[IntegrationsController] "Cancel" button clicked.');
    if (typeof SidebarController !== 'undefined' && typeof SidebarController.setActive === 'function') {
      SidebarController.setActive('nav-dashboard', 'Security Overview');
    } else {
      const dashboardView = document.getElementById('view-dashboard');
      const settingsView  = document.getElementById('view-settings');
      if (settingsView)  settingsView.style.display  = 'none';
      if (dashboardView) dashboardView.style.display = 'flex';
    }
  }

  /* ══════════════════════════════════════════════════════════
     API HELPERS (BROWSER FALLBACK)
  ══════════════════════════════════════════════════════════ */

  async function _authenticate(baseUrl, username, password, verifySsl) {
    const endpoint = `${baseUrl}/security/user/authenticate`;
    const basicToken = btoa(`${username}:${password}`);

    const res = await fetch(endpoint, {
      method:  'POST',
      headers: {
        'Authorization': `Basic ${basicToken}`,
        'Content-Type':  'application/json',
      },
      signal: AbortSignal.timeout(12000),
    }).catch(err => {
      if (err.name === 'AbortError') {
        throw new Error('Connection timed out (12s) — check that the Wazuh Manager is online.');
      }
      if (err.name === 'TypeError') {
        throw new Error('Network / SSL Error — unable to reach Wazuh Manager API. Check URL, CORS settings, or self-signed SSL cert.');
      }
      throw err;
    });

    if (res.status === 401) throw new Error('Invalid username or password (HTTP 401).');
    if (res.status === 403) throw new Error('Access denied — user lacks API permission (HTTP 403).');
    if (!res.ok) throw new Error(`Wazuh API returned HTTP ${res.status}.`);

    const json = await res.json();
    const jwt  = json?.data?.token ?? null;
    if (!jwt) throw new Error('Unexpected response — no token in reply.');
    return jwt;
  }

  async function _pingWithToken(baseUrl, token, verifySsl) {
    const res = await fetch(`${baseUrl}/`, {
      headers: { 'Authorization': `Bearer ${token}` },
      signal:  AbortSignal.timeout(10000),
    }).catch(err => {
      if (err.name === 'AbortError') {
        throw new Error('Connection timed out (10s) — check that the Wazuh Manager is online.');
      }
      if (err.name === 'TypeError') {
        throw new Error('Network / SSL Error — unable to reach Wazuh Manager API. Check URL, CORS settings, or self-signed SSL cert.');
      }
      throw err;
    });

    if (res.status === 401) throw new Error('Token expired or invalid (HTTP 401).');
    if (!res.ok && res.status !== 200) throw new Error(`Wazuh API returned HTTP ${res.status}.`);
    return true;
  }

  /* ══════════════════════════════════════════════════════════
     FORM HELPERS
  ══════════════════════════════════════════════════════════ */

  function _buildBaseUrl() {
    let raw = (_el.apiUrl?.value ?? '').trim();
    if (!raw) return null;

    const protoEl = document.getElementById('wazuh-api-proto');
    let proto = protoEl?.value || 'https://';

    // If user pasted full URL into Manager API URL field (e.g. http://10.145.10.58:8080/)
    if (/^https?:\/\//i.test(raw)) {
      if (raw.toLowerCase().startsWith('http://')) {
        proto = 'http://';
        if (protoEl) protoEl.value = 'http://';
      } else if (raw.toLowerCase().startsWith('https://')) {
        proto = 'https://';
        if (protoEl) protoEl.value = 'https://';
      }
      raw = raw.replace(/^https?:\/\//i, '');
    }

    // Strip path trailing slashes
    raw = raw.replace(/\/.*$/, '').trim();
    if (!raw) return null;

    // Check if user included port in raw input (e.g. 10.145.10.58:8080)
    const portMatch = raw.match(/:(\d+)$/);
    if (portMatch) {
      if (_el.apiPort) _el.apiPort.value = portMatch[1];
      raw = raw.replace(/:\d+$/, '');
    }

    const portVal = (_el.apiPort?.value ?? '').trim();
    const port = parseInt(portVal || '55000', 10);
    const finalPort = (!isNaN(port) && port > 0 && port <= 65535) ? port : 55000;

    const fullUrl = `${proto}${raw}:${finalPort}`;
    try {
      const parsed = new URL(fullUrl);
      // Clean display value in input box
      if (_el.apiUrl) _el.apiUrl.value = raw;
      return parsed.toString().replace(/\/$/, '');
    } catch {
      return null;
    }
  }

  function _collectCredentials() {
    if (_authMode === 'token') {
      const token = (_el.jwtToken?.value ?? '').trim();
      return token ? { token } : null;
    }
    const username = (_el.username?.value ?? '').trim();
    const password = (_el.password?.value ?? '');
    return username && password ? { username, password } : null;
  }

  /* ══════════════════════════════════════════════════════════
     UI STATE
  ══════════════════════════════════════════════════════════ */

  function _setTestBusy(busy) {
    if (!_el.testBtn) return;
    _el.testBtn.disabled = busy;
    if (_el.saveBtn)  _el.saveBtn.disabled  = busy;
    if (_el.clearBtn) _el.clearBtn.disabled = busy;

    const iconName = busy ? 'loader-2' : 'wifi';
    const btnText  = busy ? 'Testing Connection…' : 'Test Connection';

    _el.testBtn.innerHTML = `<i data-lucide="${iconName}"></i> ${btnText}`;
    if (typeof lucide !== 'undefined') lucide.createIcons();

    const svg = _el.testBtn.querySelector('svg');
    if (svg && busy) svg.classList.add('int-icon-spin');
  }

  function _showResult(state, title, detail) {
    const el = _el.testResult;
    if (!el) return;

    el.style.display = 'flex';
    el.className = `int-test-result int-test-result--${state}`;

    const iconMap = {
      pending: 'loader-2',
      success: 'check-circle-2',
      error:   'x-circle',
    };

    const iconName = iconMap[state] ?? 'info';

    el.innerHTML = `
      <div class="int-result-icon"><i data-lucide="${iconName}"></i></div>
      <div class="int-result-body">
        <span class="int-result-title">${_escapeHtml(title)}</span>
        <span class="int-result-detail">${_escapeHtml(detail ?? '')}</span>
      </div>
    `;

    if (typeof lucide !== 'undefined') lucide.createIcons();

    const svg = el.querySelector('.int-result-icon svg');
    if (svg && state === 'pending') {
      svg.classList.add('int-icon-spin');
    }
  }

  function _hideResult() {
    if (_el.testResult) _el.testResult.style.display = 'none';
  }

  function _escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /* ── Card Badge ─────────────────────────────────────────── */
  function _setBadge(state) {
    const badge = _el.badge;
    if (!badge) return;

    const map = {
      connected:    { cls: 'int-status-badge--connected',    label: 'CONNECTED' },
      connecting:   { cls: 'int-status-badge--connecting',   label: 'CONNECTING…' },
      disconnected: { cls: 'int-status-badge--disconnected', label: 'NOT CONNECTED' },
      error:        { cls: 'int-status-badge--error',        label: 'ERROR' },
    };

    const cfg = map[state] ?? map.disconnected;

    badge.className = `int-status-badge ${cfg.cls}`;
    const textEl = badge.querySelector('.int-badge-text');
    if (textEl) textEl.textContent = cfg.label;
  }

  function _syncBadgeFromWazuh() {
    const state = WazuhClient?.state ?? 'not-connected';
    const map = {
      'not-connected': 'disconnected',
      'connecting':    'connecting',
      'connected':     'connected',
      'error':         'error',
    };
    _setBadge(map[state] ?? 'disconnected');
  }

  function _dispatchWazuhState(newState) {
    window.dispatchEvent(
      new CustomEvent('wazuh:statechange', {
        detail: { current: newState, prev: WazuhClient?.state ?? 'not-connected' },
      })
    );
  }

  /* ══════════════════════════════════════════════════════════
     PERSISTENCE — Load saved config into form
  ══════════════════════════════════════════════════════════ */
  function _loadSaved() {
    let config = null;
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) config = JSON.parse(raw);
    } catch (_) {}

    if (!config) return;

    if (_el.apiUrl) {
      try {
        const p = new URL(config.baseUrl ?? '');
        _el.apiUrl.value = p.hostname || config.baseUrl || '';
        if (_el.apiPort) _el.apiPort.value = p.port || '55000';
        const protoEl = document.getElementById('wazuh-api-proto');
        if (protoEl && p.protocol) protoEl.value = `${p.protocol}//`;
      } catch {
        _el.apiUrl.value = config.baseUrl ?? '';
      }
    }

    if (_el.username)  _el.username.value  = config.username ?? '';
    if (_el.sslVerify) _el.sslVerify.checked = config.sslVerify ?? true;

    if (config.authMode === 'token') {
      _setAuthMode('token');
      if (_el.jwtToken) _el.jwtToken.value = config.token ?? '';
    } else {
      _setAuthMode('userpass');
    }

    if (_el.webhookSecret && config.webhookSecret) {
      _el.webhookSecret.value = config.webhookSecret;
    }

    if (config.hasPassword && _el.password) {
      _el.password.placeholder = '(previously saved — re-enter to update)';
    }
  }

  /* ── Public surface ─────────────────────────────────────── */
  return { init };
})();

window.IntegrationsController = IntegrationsController;
