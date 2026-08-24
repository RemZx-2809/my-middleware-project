/**
 * Aegis SOC — Redmine Integration Controller
 * Handles Redmine settings, credentials testing, manual vulnerability history syncing,
 * flexible rule trigger matching, intelligent deduplication configuration,
 * and topbar connection status badge updates.
 */

'use strict';

const RedmineController = (() => {

  /* ── DOM Elements ────────────────────────────────────────── */
  let _urlInput, _apiKeyInput, _projectInput, _trackerInput;
  let _triggerModeSelect, _minLevelSelect, _minLevelWrap, _customRulesInput, _customRulesWrap, _dedupHoursSelect, _autoTicketCheckbox;
  let _keyRevealBtn, _testBtn, _syncBtn, _saveBtn, _resultBanner;
  let _topBadge;

  /* ── Toast Helper ────────────────────────────────────────── */
  function _showToast(msg, type = 'info') {
    if (window.TopbarController && typeof window.TopbarController.showToast === 'function') {
      window.TopbarController.showToast(msg, type);
    } else {
      console.log(`[Toast] [${type}] ${msg}`);
    }
  }

  /* ── Topbar Status Badge Helper ──────────────────────────── */
  function updateTopStatusBadge(state = 'disconnected', label = 'Redmine', tooltip = '') {
    if (!_topBadge) _topBadge = document.getElementById('redmine-status-badge');
    if (!_topBadge) return;

    _topBadge.setAttribute('data-state', state);
    const textEl = _topBadge.querySelector('.redmine-status-text');
    if (textEl) textEl.textContent = label;
    if (tooltip) _topBadge.setAttribute('title', tooltip);
  }

  function _updateTriggerModeUI(mode) {
    if (_minLevelWrap) {
      _minLevelWrap.style.display = (mode === 'min_level') ? 'flex' : 'none';
    }
    if (_customRulesWrap) {
      _customRulesWrap.style.display = (mode === 'custom_rules') ? 'flex' : 'none';
    }
  }

  /* ── Load Config from Server & Verify Connection ─────────── */
  async function loadConfig(silentCheck = true) {
    try {
      const res = await fetch('/api/redmine/config');
      const data = await res.json();
      if (!data.ok || !data.config) return;

      const cfg = data.config;
      if (_urlInput)           _urlInput.value = cfg.redmineUrl || '';
      if (_apiKeyInput)        _apiKeyInput.value = cfg.redmineApiKey || '';
      if (_projectInput)       _projectInput.value = cfg.redmineProject || '';
      if (_trackerInput)       _trackerInput.value = cfg.redmineTrackerId || '1';
      if (_triggerModeSelect)  _triggerModeSelect.value = cfg.redmineTriggerMode || 'min_level';
      if (_minLevelSelect)     _minLevelSelect.value = cfg.redmineMinLevel || '7';
      if (_customRulesInput)   _customRulesInput.value = cfg.redmineCustomRules || '';
      if (_dedupHoursSelect)   _dedupHoursSelect.value = cfg.redmineDedupHours || '24';
      if (_autoTicketCheckbox) _autoTicketCheckbox.checked = cfg.redmineAutoTicket !== false;

      _updateTriggerModeUI(cfg.redmineTriggerMode || 'min_level');

      // Check topbar status
      if (cfg.redmineUrl && cfg.hasApiKey) {
        if (silentCheck) {
          _checkConnectionSilently(cfg.redmineUrl);
        }
      } else {
        updateTopStatusBadge('disconnected', 'Redmine', 'Redmine: Not Configured (Click to open Settings)');
      }

    } catch (err) {
      console.warn('[RedmineController] Failed to load config:', err.message);
      updateTopStatusBadge('disconnected', 'Redmine', 'Redmine: Offline');
    }
  }

  /* ── Silent Connection Check ─────────────────────────────── */
  async function _checkConnectionSilently(url) {
    updateTopStatusBadge('connecting', 'Redmine…', 'Redmine: Connecting to ' + url);
    try {
      const res = await fetch('/api/redmine/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (data.ok) {
        updateTopStatusBadge('connected', 'Redmine Connected', `Redmine: Online as ${data.user?.name || data.user?.login || 'User'}`);
      } else {
        updateTopStatusBadge('error', 'Redmine Error', `Redmine: ${data.error || 'Connection Failed'}`);
      }
    } catch (_) {
      updateTopStatusBadge('error', 'Redmine Error', 'Redmine: Unreachable');
    }
  }

  /* ── Save Config ─────────────────────────────────────────── */
  async function saveConfig() {
    const payload = {
      redmineUrl:         _urlInput?.value.trim() || '',
      redmineApiKey:      _apiKeyInput?.value.trim() || '',
      redmineProject:     _projectInput?.value.trim() || '',
      redmineTrackerId:   _trackerInput?.value.trim() || '1',
      redmineTriggerMode: _triggerModeSelect?.value || 'min_level',
      redmineMinLevel:    _minLevelSelect?.value || '7',
      redmineCustomRules: _customRulesInput?.value.trim() || '',
      redmineDedupHours:  _dedupHoursSelect?.value || '24',
      redmineAutoTicket:  _autoTicketCheckbox?.checked ?? true,
    };

    if (_saveBtn) {
      _saveBtn.disabled = true;
      _saveBtn.innerHTML = '<i data-lucide="loader-2" class="spinning"></i> Saving…';
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    try {
      const res = await fetch('/api/redmine/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();

      if (data.ok) {
        _showToast('Redmine settings saved successfully', 'success');
        await loadConfig(true);
      } else {
        _showToast(data.error || 'Failed to save Redmine settings', 'error');
      }
    } catch (err) {
      _showToast(`Error saving settings: ${err.message}`, 'error');
    } finally {
      if (_saveBtn) {
        _saveBtn.disabled = false;
        _saveBtn.innerHTML = '<i data-lucide="save"></i> Save Redmine Settings';
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }
    }
  }

  /* ── Test Connection ─────────────────────────────────────── */
  async function testConnection() {
    const payload = {
      redmineUrl:    _urlInput?.value.trim() || '',
      redmineApiKey: _apiKeyInput?.value.trim() || '',
    };

    if (!payload.redmineUrl) {
      _showToast('Please enter Redmine Server URL first', 'warn');
      return;
    }

    _showResultBanner('loading', 'Testing Redmine connection…', 'Contacting Redmine API at ' + payload.redmineUrl);
    updateTopStatusBadge('connecting', 'Redmine…', 'Testing Redmine connection…');

    if (_testBtn) {
      _testBtn.disabled = true;
      _testBtn.innerHTML = '<i data-lucide="loader-2" class="spinning"></i> Testing…';
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    try {
      const res = await fetch('/api/redmine/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();

      if (data.ok) {
        _showResultBanner('success', 'Connected Successfully', data.message || `User: ${data.user?.name || data.user?.login}`);
        updateTopStatusBadge('connected', 'Redmine Connected', `Connected as ${data.user?.name || data.user?.login}`);
        _showToast('Redmine connected successfully', 'success');
      } else {
        _showResultBanner('error', 'Connection Failed', data.error || 'Check Redmine URL and API Key');
        updateTopStatusBadge('error', 'Redmine Error', `Redmine: ${data.error || 'Connection Failed'}`);
        _showToast(data.error || 'Redmine connection failed', 'error');
      }
    } catch (err) {
      _showResultBanner('error', 'Connection Error', err.message);
      updateTopStatusBadge('error', 'Redmine Error', `Connection error: ${err.message}`);
      _showToast(`Connection error: ${err.message}`, 'error');
    } finally {
      if (_testBtn) {
        _testBtn.disabled = false;
        _testBtn.innerHTML = '<i data-lucide="wifi"></i> Test Connection';
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }
    }
  }

  /* ── Sync Issues from Redmine ────────────────────────────── */
  async function syncIssues() {
    _showResultBanner('loading', 'Syncing from Redmine…', 'Pulling recently resolved vulnerability issues into History');

    if (_syncBtn) {
      _syncBtn.disabled = true;
      _syncBtn.innerHTML = '<i data-lucide="loader-2" class="spinning"></i> Syncing…';
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    try {
      const res = await fetch('/api/redmine/sync', { method: 'POST' });
      const data = await res.json();

      if (data.ok) {
        _showResultBanner('success', 'Sync Completed', `Synced ${data.syncedCount || data.count || 0} issues from Redmine into File Edit History`);
        _showToast(`Synced ${data.syncedCount || 0} issues to History`, 'success');
        if (window.FileHistoryController && typeof window.FileHistoryController.load === 'function') {
          window.FileHistoryController.load();
        }
      } else {
        _showResultBanner('error', 'Sync Failed', data.error || 'Could not sync from Redmine');
        _showToast(data.error || 'Redmine sync failed', 'error');
      }
    } catch (err) {
      _showResultBanner('error', 'Sync Error', err.message);
      _showToast(`Sync error: ${err.message}`, 'error');
    } finally {
      if (_syncBtn) {
        _syncBtn.disabled = false;
        _syncBtn.innerHTML = '<i data-lucide="refresh-cw"></i> Sync Fix History Now';
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }
    }
  }

  /* ── Result Banner Helper ────────────────────────────────── */
  function _showResultBanner(type, title, detail) {
    if (!_resultBanner) return;
    _resultBanner.style.display = 'flex';
    _resultBanner.className = `int-test-result int-test-result--${type}`;

    const iconMap = {
      loading: 'loader-2',
      success: 'check-circle-2',
      error:   'alert-circle',
    };

    const icon = _resultBanner.querySelector('.int-result-icon');
    const titleEl = _resultBanner.querySelector('.int-result-title');
    const detailEl = _resultBanner.querySelector('.int-result-detail');

    if (icon) icon.innerHTML = `<i data-lucide="${iconMap[type] || 'info'}"></i>`;
    if (titleEl) titleEl.textContent = title;
    if (detailEl) detailEl.textContent = detail;

    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  /* ── Init ────────────────────────────────────────────────── */
  function init() {
    _urlInput           = document.getElementById('redmine-url');
    _apiKeyInput        = document.getElementById('redmine-api-key');
    _projectInput       = document.getElementById('redmine-project');
    _trackerInput       = document.getElementById('redmine-tracker-id');
    _triggerModeSelect  = document.getElementById('redmine-trigger-mode');
    _minLevelSelect     = document.getElementById('redmine-min-level');
    _minLevelWrap       = document.getElementById('redmine-min-level-wrap');
    _customRulesInput   = document.getElementById('redmine-custom-rules');
    _customRulesWrap    = document.getElementById('redmine-custom-rules-wrap');
    _dedupHoursSelect   = document.getElementById('redmine-dedup-hours');
    _autoTicketCheckbox = document.getElementById('redmine-auto-ticket');

    _keyRevealBtn = document.getElementById('redmine-key-reveal-btn');
    _testBtn      = document.getElementById('redmine-test-btn');
    _syncBtn      = document.getElementById('redmine-sync-btn');
    _saveBtn      = document.getElementById('redmine-save-btn');
    _resultBanner = document.getElementById('redmine-test-result');
    _topBadge     = document.getElementById('redmine-status-badge');

    // Reveal API key
    if (_keyRevealBtn && _apiKeyInput) {
      _keyRevealBtn.addEventListener('click', () => {
        const isPwd = _apiKeyInput.type === 'password';
        _apiKeyInput.type = isPwd ? 'text' : 'password';
        _keyRevealBtn.innerHTML = `<i data-lucide="${isPwd ? 'eye-off' : 'eye'}"></i>`;
        if (typeof lucide !== 'undefined') lucide.createIcons();
      });
    }

    if (_triggerModeSelect) {
      _triggerModeSelect.addEventListener('change', (e) => {
        _updateTriggerModeUI(e.target.value);
      });
    }

    if (_testBtn) _testBtn.addEventListener('click', testConnection);
    if (_syncBtn) _syncBtn.addEventListener('click', syncIssues);
    if (_saveBtn) _saveBtn.addEventListener('click', saveConfig);

    // Click on topbar badge to navigate to settings
    if (_topBadge) {
      _topBadge.addEventListener('click', () => {
        if (window.SidebarController && typeof window.SidebarController.navigate === 'function') {
          window.SidebarController.navigate('settings');
        } else {
          const settingsNav = document.getElementById('nav-settings');
          if (settingsNav) settingsNav.click();
        }
        setTimeout(() => {
          const redmineSection = document.querySelector('.settings-section-header');
          if (redmineSection) redmineSection.scrollIntoView({ behavior: 'smooth' });
        }, 100);
      });
    }

    loadConfig(true);
  }

  return { init, loadConfig, testConnection, syncIssues, saveConfig, updateTopStatusBadge };
})();

window.RedmineController = RedmineController;
