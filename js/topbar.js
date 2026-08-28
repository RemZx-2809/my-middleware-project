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
          const discoverView  = document.getElementById('view-discover');
          const settingsView  = document.getElementById('view-settings');
          const breadcrumb    = document.getElementById('breadcrumb-current');
          const navDashboard  = document.getElementById('nav-dashboard');
          const navDiscover   = document.getElementById('nav-discover');

          if (dashboardView) dashboardView.style.display = 'none';
          if (discoverView)  discoverView.style.display  = 'none';
          if (settingsView)  settingsView.style.display  = 'flex';
          if (breadcrumb)    breadcrumb.textContent      = 'Settings';
          if (navDashboard)  navDashboard.classList.remove('active');
          if (navDiscover)   navDiscover.classList.remove('active');

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

    // Check persisted Wazuh configuration state from localStorage
    let initialConnected = false;
    try {
      const raw = localStorage.getItem('aegis-wazuh-config');
      if (raw) {
        const cfg = JSON.parse(raw);
        if (cfg && (cfg.isConnected || cfg.savedAt || cfg.baseUrl)) {
          initialConnected = true;
        }
      }
    } catch (_) {}

    setConnectionState(initialConnected ? 'connected' : 'not-connected');

    // Webhook Ingest URL copy button wiring
    _initWebhookCopyBtn();

    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
  }

  /* ── Webhook Ingest URL Copy Button ──────────────────────── */
  function _initWebhookCopyBtn() {
    const btn = document.getElementById('webhook-copy-btn');
    if (!btn) return;

    btn.addEventListener('click', () => {
      const webhookUrl = `${window.location.protocol}//${window.location.host}/api/wazuh-webhook`;
      navigator.clipboard.writeText(webhookUrl).then(() => {
        Toast.show({
          type: 'ok',
          title: '🔗 Webhook URL Copied!',
          body: `Copied: ${webhookUrl} (Paste into Wazuh ossec.conf)`,
          duration: 3500,
        });
      }).catch(() => {
        Toast.show({
          type: 'info',
          title: 'Webhook Receiver Endpoint',
          body: webhookUrl,
          duration: 4000,
        });
      });
    });
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
