/**
 * Aegis SOC — Pure Receiver & Webhook Ingestion Controller
 *
 * Manages:
 *  1. Dynamic Webhook Ingest URL generator & 1-click clipboard copy
 *  2. Real-time Wazuh ossec.conf XML integration snippet generator
 *  3. Webhook Shared Secret authentication configuration
 *  4. Syncs settings directly with /api/config on Node.js backend
 */

'use strict';

const IntegrationsController = (() => {
  let _secretInput      = null;
  let _saveBtn          = null;
  let _copyWebhookBtn   = null;
  let _copyOssecXmlBtn  = null;
  let _secretRevealBtn  = null;
  let _urlInput         = null;
  let _ossecXmlSnippet  = null;

  function _getWebhookUrl() {
    return `${window.location.protocol}//${window.location.host}/api/wazuh-webhook`;
  }

  function _updateXmlSnippet() {
    if (!_ossecXmlSnippet) return;
    const url = _urlInput?.value || _getWebhookUrl();
    const secret = _secretInput?.value?.trim() || '';
    const apiKeyBlock = secret ? `\n    <api_key>${_escapeXml(secret)}</api_key>` : '';

    const xml = `<ossec_config>
  <integration>
    <name>custom-aegis</name>
    <hook_url>${url}</hook_url>${apiKeyBlock}
    <alert_format>json</alert_format>
    <alert_level>3</alert_level>
  </integration>
</ossec_config>`;

    _ossecXmlSnippet.textContent = xml;
  }

  function _escapeXml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  /* ── Init ────────────────────────────────────────────────── */
  function init() {
    _secretInput     = document.getElementById('wazuh-webhook-secret');
    _saveBtn         = document.getElementById('wazuh-save-btn');
    _copyWebhookBtn  = document.getElementById('btn-copy-webhook-url');
    _copyOssecXmlBtn = document.getElementById('btn-copy-ossec-xml');
    _secretRevealBtn = document.getElementById('wazuh-secret-reveal-btn');
    _urlInput        = document.getElementById('wazuh-webhook-url');
    _ossecXmlSnippet = document.getElementById('ossec-xml-snippet');

    // Auto-detect and populate dynamic current URL
    if (_urlInput) {
      _urlInput.value = _getWebhookUrl();
    }
    _updateXmlSnippet();

    // 1. Copy Webhook URL
    if (_copyWebhookBtn) {
      _copyWebhookBtn.addEventListener('click', () => {
        const text = _urlInput?.value || _getWebhookUrl();
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

    // 2. Copy ossec.conf XML snippet
    if (_copyOssecXmlBtn) {
      _copyOssecXmlBtn.addEventListener('click', () => {
        const text = _ossecXmlSnippet?.textContent || '';
        navigator.clipboard.writeText(text).then(() => {
          if (window.Toast) {
            window.Toast.show({
              type: 'success',
              title: 'ossec.conf XML Copied',
              body: 'Paste this snippet into /var/ossec/etc/ossec.conf on Wazuh Manager',
              duration: 3500,
            });
          }
        });
      });
    }

    // 3. Secret reveal button & dynamic XML update
    if (_secretRevealBtn && _secretInput) {
      _secretRevealBtn.addEventListener('click', () => {
        const isPwd = _secretInput.type === 'password';
        _secretInput.type = isPwd ? 'text' : 'password';
        _secretRevealBtn.innerHTML = `<i data-lucide="${isPwd ? 'eye-off' : 'eye'}"></i>`;
        if (typeof lucide !== 'undefined') lucide.createIcons();
      });
      _secretInput.addEventListener('input', _updateXmlSnippet);
    }

    // 4. Save Settings
    if (_saveBtn) {
      _saveBtn.addEventListener('click', saveSettings);
    }

    // Load initial settings
    loadSettings();

    if (typeof lucide !== 'undefined') lucide.createIcons();
    console.log('[IntegrationsController] Initialized Pure Webhook URL Ingestion.');
  }

  /* ── Load Settings from Backend ──────────────────────────── */
  async function loadSettings() {
    try {
      const res = await fetch('/api/config');
      if (!res.ok) return;
      const data = await res.json();

      if (_secretInput) _secretInput.value = data.webhookSecret || '';

      // If user opened on localhost, automatically prefer real LAN IP so Wazuh can connect
      if (data.serverIp && data.serverIp !== '127.0.0.1') {
        const port = data.port || window.location.port || '3000';
        const lanUrl = `http://${data.serverIp}:${port}/api/wazuh-webhook`;
        if (_urlInput) _urlInput.value = lanUrl;
      }

      _updateXmlSnippet();
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
            body: 'Webhook Ingestion configuration updated successfully',
            duration: 2500,
          });
        }
        _updateXmlSnippet();
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
        _saveBtn.innerHTML = '<i data-lucide="save"></i> Save Ingestion Settings';
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }
    }
  }

  return {
    init,
    loadSettings,
    saveSettings,
  };
})();

window.IntegrationsController = IntegrationsController;

