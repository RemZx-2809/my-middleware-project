/**
 * Aegis SOC — Pure Receiver & SSH Tunnel Settings Controller
 *
 * Manages:
 *  1. Webhook Ingest URL copy helper & Shared Secret settings
 *  2. SSH Reverse Tunnel Host, User, and Auto-Start configuration
 *  3. Live SSH Tunnel state monitoring & Connect/Disconnect toggle
 *  4. Syncs settings directly with /api/config on the Node.js backend
 */

'use strict';

const IntegrationsController = (() => {
  let _secretInput = null;
  let _sshHostInput = null;
  let _sshUserInput = null;
  let _sshAutoTunnelCheckbox = null;
  let _saveBtn = null;
  let _copyWebhookBtn = null;
  let _secretRevealBtn = null;
  let _tunnelToggleBtn = null;
  let _tunnelStatusText = null;

  let _tunnelStatusInterval = null;

  /* ── Init ────────────────────────────────────────────────── */
  function init() {
    _secretInput           = document.getElementById('wazuh-webhook-secret');
    _sshHostInput          = document.getElementById('ssh-host');
    _sshUserInput          = document.getElementById('ssh-user');
    _sshAutoTunnelCheckbox = document.getElementById('ssh-auto-tunnel');
    _saveBtn               = document.getElementById('wazuh-save-btn');
    _copyWebhookBtn        = document.getElementById('btn-copy-webhook-url');
    _secretRevealBtn       = document.getElementById('wazuh-secret-reveal-btn');
    _tunnelToggleBtn       = document.getElementById('btn-toggle-tunnel');
    _tunnelStatusText      = document.getElementById('settings-tunnel-status-text');

    // 1. Copy Webhook URL
    if (_copyWebhookBtn) {
      _copyWebhookBtn.addEventListener('click', () => {
        const urlInput = document.getElementById('wazuh-webhook-url');
        const text = urlInput?.value || 'http://127.0.0.1:3000/api/wazuh-webhook';
        navigator.clipboard.writeText(text).then(() => {
          if (window.Toast) {
            window.Toast.show({
              type: 'success',
              title: 'Webhook URL Copied',
              body: 'Copied to clipboard: ' + text,
              duration: 2500,
            });
          }
        });
      });
    }

    // 2. Secret reveal button
    if (_secretRevealBtn && _secretInput) {
      _secretRevealBtn.addEventListener('click', () => {
        const isPwd = _secretInput.type === 'password';
        _secretInput.type = isPwd ? 'text' : 'password';
        _secretRevealBtn.innerHTML = `<i data-lucide="${isPwd ? 'eye-off' : 'eye'}"></i>`;
        if (typeof lucide !== 'undefined') lucide.createIcons();
      });
    }

    // 3. Save Settings
    if (_saveBtn) {
      _saveBtn.addEventListener('click', saveSettings);
    }

    // 4. Toggle SSH Tunnel
    if (_tunnelToggleBtn) {
      _tunnelToggleBtn.addEventListener('click', toggleTunnel);
    }

    // Load initial settings
    loadSettings();
    pollTunnelStatus();

    if (_tunnelStatusInterval) clearInterval(_tunnelStatusInterval);
    _tunnelStatusInterval = setInterval(pollTunnelStatus, 6000);

    if (typeof lucide !== 'undefined') lucide.createIcons();
    console.log('[IntegrationsController] Initialized Pure Receiver & SSH Tunnel settings.');
  }

  /* ── Load Settings from Backend ──────────────────────────── */
  async function loadSettings() {
    try {
      const res = await fetch('/api/config');
      if (!res.ok) return;
      const data = await res.json();

      if (_secretInput) _secretInput.value = data.webhookSecret || '';
      if (_sshHostInput) _sshHostInput.value = data.sshHost || '10.145.10.57';
      if (_sshUserInput) _sshUserInput.value = data.sshUser || 'tawaikiar_p';
      if (_sshAutoTunnelCheckbox) _sshAutoTunnelCheckbox.checked = data.sshAutoTunnel !== false;
    } catch (e) {
      console.warn('[IntegrationsController] Could not load config:', e.message);
    }
  }

  /* ── Save Settings to Backend ────────────────────────────── */
  async function saveSettings() {
    if (_saveBtn) {
      _saveBtn.disabled = true;
      _saveBtn.innerHTML = '<i data-lucide="loader-2" class="spinning"></i> Saving…';
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    const payload = {
      webhookSecret: _secretInput?.value.trim() || '',
      sshHost:       _sshHostInput?.value.trim() || '10.145.10.57',
      sshUser:       _sshUserInput?.value.trim() || 'tawaikiar_p',
      sshAutoTunnel: _sshAutoTunnelCheckbox?.checked ?? true,
    };

    try {
      const res = await fetch('/api/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();

      if (data.ok) {
        if (window.Toast) {
          window.Toast.show({
            type: 'success',
            title: 'Settings Saved',
            body: 'Ingestion & SSH Tunnel configuration saved successfully',
            duration: 2500,
          });
        }
      } else {
        if (window.Toast) {
          window.Toast.show({
            type: 'error',
            title: 'Save Failed',
            body: data.error || 'Could not save settings',
            duration: 3500,
          });
        }
      }
    } catch (err) {
      if (window.Toast) {
        window.Toast.show({
          type: 'error',
          title: 'Error',
          body: `Network error: ${err.message}`,
          duration: 3500,
        });
      }
    } finally {
      if (_saveBtn) {
        _saveBtn.disabled = false;
        _saveBtn.innerHTML = '<i data-lucide="save"></i> Save Ingestion &amp; Tunnel Settings';
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }
    }
  }

  /* ── Poll Live SSH Tunnel Status ─────────────────────────── */
  async function pollTunnelStatus() {
    if (!_tunnelStatusText) return;
    try {
      const res = await fetch('/api/tunnel');
      if (!res.ok) return;
      const data = await res.json();

      const isOpen = data.active && data.state === 'connected';
      const isConnecting = data.state === 'connecting';

      if (isOpen) {
        _tunnelStatusText.innerHTML = `<span style="color:#34d399; font-weight:600;">● Active &amp; Forwarding</span> (Remote port ${data.remotePort || 3000} → Local 3000)`;
        if (_tunnelToggleBtn) {
          _tunnelToggleBtn.className = 'int-btn int-btn--outline-danger';
          _tunnelToggleBtn.innerHTML = '<i data-lucide="power-off"></i> Disconnect';
        }
      } else if (isConnecting) {
        _tunnelStatusText.innerHTML = `<span style="color:#fbbf24; font-weight:600;">◌ Connecting…</span> to ${data.host || 'remote host'}`;
        if (_tunnelToggleBtn) {
          _tunnelToggleBtn.className = 'int-btn int-btn--neutral';
          _tunnelToggleBtn.innerHTML = '<i data-lucide="loader-2" class="spinning"></i> Connecting…';
        }
      } else {
        _tunnelStatusText.innerHTML = `<span style="color:#94a3b8;">○ Disconnected</span> ${data.error ? `<span style="color:#f4576a;">(${data.error})</span>` : ''}`;
        if (_tunnelToggleBtn) {
          _tunnelToggleBtn.className = 'int-btn int-btn--primary';
          _tunnelToggleBtn.innerHTML = '<i data-lucide="plug"></i> Connect Tunnel';
        }
      }
      if (typeof lucide !== 'undefined') lucide.createIcons();
    } catch (_) {}
  }

  /* ── Toggle SSH Tunnel ───────────────────────────────────── */
  async function toggleTunnel() {
    if (!_tunnelToggleBtn) return;
    _tunnelToggleBtn.disabled = true;
    try {
      const checkRes = await fetch('/api/tunnel');
      const checkData = await checkRes.json();
      const isOpen = checkData.active && checkData.state === 'connected';

      if (isOpen) {
        await fetch('/api/tunnel', { method: 'DELETE' });
        if (window.Toast) window.Toast.show({ type: 'info', title: 'Tunnel Stopped', body: 'SSH reverse tunnel disconnected', duration: 2000 });
      } else {
        await fetch('/api/tunnel', { method: 'POST' });
        if (window.Toast) window.Toast.show({ type: 'info', title: 'Tunnel Starting', body: 'Connecting SSH reverse tunnel…', duration: 2500 });
      }
      setTimeout(pollTunnelStatus, 800);
    } catch (e) {
      if (window.Toast) window.Toast.show({ type: 'error', title: 'Tunnel Error', body: e.message, duration: 3000 });
    } finally {
      _tunnelToggleBtn.disabled = false;
    }
  }

  return {
    init,
    loadSettings,
    saveSettings,
    toggleTunnel,
    pollTunnelStatus,
  };
})();

window.IntegrationsController = IntegrationsController;
