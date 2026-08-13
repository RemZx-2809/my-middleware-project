/**
 * Aegis SOC — Topbar Controller
 *
 * Handles:
 *   - Account dropdown open/close (click + outside-click)
 *   - Notification bell → toast
 *   - Connection status display (driven by WazuhClient state)
 *   - Search input visibility
 */

'use strict';

const TopbarController = (() => {
  let _accountBtn  = null;
  let _accountMenu = null;
  let _connEl      = null;
  let _bellBtn     = null;

  function init() {
    _accountBtn  = document.getElementById('account-btn');
    _accountMenu = document.getElementById('account-dropdown');
    _connEl      = document.getElementById('conn-status');
    _bellBtn     = document.getElementById('bell-btn');

    if (_accountBtn && _accountMenu) {
      _accountBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = _accountMenu.classList.toggle('open');
        _accountBtn.classList.toggle('open', isOpen);
      });

      document.addEventListener('click', () => {
        _accountMenu.classList.remove('open');
        _accountBtn.classList.remove('open');
      });

      const dropdownSettings = document.getElementById('dropdown-settings');
      if (dropdownSettings) {
        dropdownSettings.addEventListener('click', (e) => {
          e.stopPropagation();
          const dashboardView = document.getElementById('view-dashboard');
          const settingsView  = document.getElementById('view-settings');
          const rulesView     = document.getElementById('view-rules');
          const breadcrumb    = document.getElementById('breadcrumb-current');
          const navDashboard  = document.getElementById('nav-dashboard');
          const navRules      = document.getElementById('nav-rules');

          if (dashboardView) dashboardView.style.display = 'none';
          if (rulesView)     rulesView.style.display     = 'none';
          if (settingsView)  settingsView.style.display  = 'flex';
          if (breadcrumb)    breadcrumb.textContent      = 'Settings';
          if (navDashboard)  navDashboard.classList.remove('active');
          if (navRules)      navRules.classList.remove('active');

          _accountMenu.classList.remove('open');
          _accountBtn.classList.remove('open');

          if (typeof lucide !== 'undefined') {
            lucide.createIcons();
          }
        });
      }
    }

    if (_bellBtn) {
      _bellBtn.addEventListener('click', () => {
        Toast.show({
          type:  'info',
          title: 'Notifications',
          body:  'No new notifications — all panels are awaiting Wazuh data.',
          duration: 4000,
        });
      });
    }

    // Listen for Wazuh connection state changes
    window.addEventListener('wazuh:statechange', (e) => {
      setConnectionState(e.detail.current);
    });

    // Initialize to not-connected
    setConnectionState('not-connected');

    // SSH Tunnel button wiring
    _initTunnelBtn();


    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
  }

  /* ── SSH Tunnel Button ───────────────────────────────────── */
  function _initTunnelBtn() {
    const btn = document.getElementById('tunnel-btn');
    if (!btn) return;

    // Poll tunnel status on load and every 5s
    _refreshTunnelStatus(btn);
    setInterval(() => _refreshTunnelStatus(btn), 5000);

    btn.addEventListener('click', async () => {
      const state = btn.dataset.state;
      if (state === 'connecting') return; // ignore while busy

      btn.dataset.state = 'connecting';
      btn.querySelector('.tunnel-btn-text').textContent = 'Connecting…';

      try {
        if (state === 'open') {
          // Stop tunnel
          await fetch('/api/tunnel', { method: 'DELETE' });
          _setTunnelState(btn, false);
          Toast.show({ type: 'warn', title: 'Tunnel Closed', body: 'SSH Reverse Tunnel has been disconnected.', duration: 3500 });
        } else {
          // Start tunnel
          await fetch('/api/tunnel', { method: 'POST' });
          // Give SSH a moment to connect
          await new Promise(r => setTimeout(r, 2000));
          await _refreshTunnelStatus(btn);
          if (btn.dataset.state === 'open') {
            Toast.show({ type: 'ok', title: 'Tunnel Open', body: 'SSH Reverse Tunnel is active. Wazuh can now send alerts to the middleware.', duration: 4000 });
          }
        }
      } catch (e) {
        btn.dataset.state = 'closed';
        btn.querySelector('.tunnel-btn-text').textContent = 'Open Tunnel';
        Toast.show({ type: 'error', title: 'Tunnel Error', body: 'Could not reach the server. Is node server.js running?', duration: 4000 });
      }
    });
  }

  async function _refreshTunnelStatus(btn) {
    if (!btn) { btn = document.getElementById('tunnel-btn'); }
    if (!btn) return;
    try {
      const res  = await fetch('/api/tunnel');
      const data = await res.json();
      _setTunnelState(btn, data.running);
    } catch (_) {
      _setTunnelState(btn, false);
    }
  }

  function _setTunnelState(btn, running) {
    btn.dataset.state = running ? 'open' : 'closed';
    const textEl = btn.querySelector('.tunnel-btn-text');
    if (textEl) textEl.textContent = running ? 'Tunnel Open' : 'Open Tunnel';
  }



  function setConnectionState(state) {
    if (!_connEl) return;
    _connEl.setAttribute('data-state', state);

    const dot  = _connEl.querySelector('.pulse-dot');
    const text = _connEl.querySelector('.conn-status-text');

    if (dot) {
      dot.className = 'pulse-dot';
      if (state === 'connected') {
        dot.classList.add('pulse-dot--ok');
      } else if (state === 'connecting' || state === 'disconnected') {
        dot.classList.add('pulse-dot--warn');
      } else {
        dot.classList.add('pulse-dot--dim');
      }
    }

    if (text) {
      const labels = {
        'not-connected': 'NOT CONNECTED',
        'connecting':    'RECONNECTING…',
        'connected':     'CONNECTED',
        'disconnected':  'SERVER DISCONNECTED',
        'error':         'CONNECTION ERROR',
      };
      text.textContent = labels[state] ?? 'UNKNOWN';
    }
  }

  return { init, setConnectionState };
})();

window.TopbarController = TopbarController;

/* ══════════════════════════════════════════════════════════
   TOAST SYSTEM
══════════════════════════════════════════════════════════ */
const Toast = (() => {
  let _container = null;

  function _getContainer() {
    if (!_container) _container = document.getElementById('toast-container');
    return _container;
  }

  function show({ type = 'info', title, body, duration = 4000 }) {
    const container = _getContainer();
    if (!container) return;

    const iconMap = {
      info:  `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
      warn:  `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
      error: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
      ok:    `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
    };

    const toast = document.createElement('div');
    toast.className = 'toast toast-enter';
    toast.innerHTML = `
      <div class="toast-icon toast-icon--${type}">${iconMap[type] || iconMap.info}</div>
      <div class="toast-content">
        <div class="toast-title">${title}</div>
        <div class="toast-body">${body}</div>
      </div>
      <button class="toast-close" aria-label="Dismiss">
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
      <div class="toast-progress" style="animation: progress-fill ${duration}ms linear both; --target-w: 100%;"></div>
    `;

    const dismiss = () => {
      toast.classList.remove('toast-enter');
      toast.classList.add('toast-leave');
      toast.addEventListener('animationend', () => toast.remove(), { once: true });
    };

    toast.querySelector('.toast-close').addEventListener('click', dismiss);
    container.appendChild(toast);

    if (duration > 0) setTimeout(dismiss, duration);
  }

  return { show };
})();

window.Toast = Toast;
