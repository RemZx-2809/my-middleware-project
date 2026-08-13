/**
 * Aegis SOC — Time Range Picker Controller
 *
 * Provides Grafana-style time range selection:
 *  - Quick presets (Last 15m, 1h, 24h, 7d, 30d …)
 *  - Absolute from/to datetime picker
 *  - Previous / Next period navigation
 *  - Auto-refresh trigger
 *
 * On every range change: fetches /api/dashboard-data?from=&to=
 * and calls PanelManager.ingestAlerts(useCase, alerts, true) for each panel.
 */

'use strict';

const TimeRangePicker = (() => {
  // Active range state
  let _from = null; // Date
  let _to   = null; // Date
  let _label = 'Last 24 hours';
  let _durationMs = 24 * 60 * 60 * 1000; // used for prev/next step

  // Elements
  let _trigger, _dropdown, _labelEl, _fromInput, _toInput;

  function init() {
    _trigger   = document.getElementById('tr-trigger');
    _dropdown  = document.getElementById('tr-dropdown');
    _labelEl   = document.getElementById('tr-label');
    _fromInput = document.getElementById('tr-from');
    _toInput   = document.getElementById('tr-to');

    if (!_trigger || !_dropdown) return;

    // Open / close dropdown
    _trigger.addEventListener('click', (e) => {
      e.stopPropagation();
      const isOpen = _dropdown.style.display === 'block';
      _setOpen(!isOpen);
    });

    // Close on outside click
    document.addEventListener('click', (e) => {
      if (!_dropdown.contains(e.target) && e.target !== _trigger) {
        _setOpen(false);
      }
    });

    // Tab switching
    _dropdown.querySelectorAll('.tr-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        _dropdown.querySelectorAll('.tr-tab').forEach(t => t.classList.remove('active'));
        _dropdown.querySelectorAll('.tr-tab-panel').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        _dropdown.querySelector(`[data-panel="${tab.dataset.tab}"]`).classList.add('active');
      });
    });

    // Quick select buttons
    _dropdown.querySelectorAll('.tr-quick-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        if (btn.dataset.minutes) {
          const minutes = parseInt(btn.dataset.minutes, 10);
          _applyRelative(minutes, btn.textContent.trim());
        } else if (btn.dataset.preset) {
          _applyPreset(btn.dataset.preset);
        }
        _setOpen(false);
      });
    });

    // Absolute apply
    const absApply = document.getElementById('tr-abs-apply');
    if (absApply) {
      absApply.addEventListener('click', () => {
        const fromVal = _fromInput?.value;
        const toVal   = _toInput?.value;
        if (!fromVal || !toVal) return;
        const from = new Date(fromVal);
        const to   = new Date(toVal);
        if (isNaN(from) || isNaN(to) || from >= to) return;
        _applyAbsolute(from, to, `${_fmtDateShort(from)} → ${_fmtDateShort(to)}`);
        _setOpen(false);
      });
    }

    // Prev / Next / Refresh
    document.getElementById('tr-prev')?.addEventListener('click', _shiftPrev);
    document.getElementById('tr-next')?.addEventListener('click', _shiftNext);
    document.getElementById('tr-refresh')?.addEventListener('click', _reload);

    // Default: All time (shows all stored data initially)
    _applyPreset('all-time');

    // Mark active quick btn
    _highlightActive();
  }

  /* ── Apply Helpers ──────────────────────────────────────── */

  function _applyRelative(minutes, label) {
    _durationMs = minutes * 60 * 1000;
    _to   = new Date();
    _from = new Date(_to.getTime() - _durationMs);
    _label = label;
    _labelEl.textContent = label;
    _prefillAbsolute();
    _highlightActive(label);
    _reload();
  }

  function _applyPreset(preset) {
    const now = new Date();
    if (preset === 'all-time') {
      _from = null;
      _to   = null;
      _durationMs = 0;
      _label = 'All time (ทั้งหมด)';
    } else if (preset === 'today') {
      _from = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      _to   = new Date();
      _label = 'Today';
    } else if (preset === 'this-week') {
      const day = now.getDay();
      _from = new Date(now.getFullYear(), now.getMonth(), now.getDate() - day);
      _to   = new Date();
      _label = 'This week';
    } else if (preset === 'this-month') {
      _from = new Date(now.getFullYear(), now.getMonth(), 1);
      _to   = new Date();
      _label = 'This month';
    }
    _labelEl.textContent = _label;
    _prefillAbsolute();
    _highlightActive(_label);
    _reload();
  }

  function _applyAbsolute(from, to, label) {
    _from = from;
    _to   = to;
    _durationMs = to - from;
    _label = label;
    _labelEl.textContent = label;
    _highlightActive(null); // no quick btn active
    _reload();
  }

  /* ── Prev / Next ────────────────────────────────────────── */

  function _shiftPrev() {
    if (!_from || !_to) return;
    _from = new Date(_from.getTime() - _durationMs);
    _to   = new Date(_to.getTime()   - _durationMs);
    _labelEl.textContent = `${_fmtDateShort(_from)} → ${_fmtDateShort(_to)}`;
    _prefillAbsolute();
    _reload();
  }

  function _shiftNext() {
    if (!_from || !_to) return;
    const next_to = new Date(_to.getTime() + _durationMs);
    if (next_to > new Date()) return; // don't go into future
    _from = new Date(_from.getTime() + _durationMs);
    _to   = next_to;
    _labelEl.textContent = `${_fmtDateShort(_from)} → ${_fmtDateShort(_to)}`;
    _prefillAbsolute();
    _reload();
  }

  /* ── Fetch & Reload ─────────────────────────────────────── */

  async function _reload() {
    const url = (_from && _to)
      ? `/api/dashboard-data?from=${_from.toISOString()}&to=${_to.toISOString()}`
      : `/api/dashboard-data`;

    // Show loading spinners on all panels
    if (typeof PanelManager !== 'undefined') {
      ['panel-critical-alerts','panel-blind-spots','panel-file-changes',
       'panel-auth-anomalies','panel-threat-intel'].forEach(id => {
        PanelManager.setState(id, 'loading');
      });
    }

    try {
      const res  = await fetch(url);
      const data = await res.json();

      for (const [useCase, { count, alerts }] of Object.entries(data)) {
        if (typeof PanelManager !== 'undefined') {
          PanelManager.ingestAlerts(useCase, alerts || [], true);
        }
      }
    } catch (e) {
      console.warn('[TimeRangePicker] Reload failed:', e.message);
    }
  }

  /* ── UI Helpers ─────────────────────────────────────────── */

  function _setOpen(open) {
    _dropdown.style.display = open ? 'block' : 'none';
    _trigger.setAttribute('aria-expanded', String(open));
  }

  function _highlightActive(label) {
    if (!_dropdown) return;
    _dropdown.querySelectorAll('.tr-quick-btn').forEach(btn => {
      btn.classList.remove('active');
      if (label && btn.textContent.trim() === label) btn.classList.add('active');
    });
  }

  function _prefillAbsolute() {
    if (_fromInput && _from) _fromInput.value = _toLocalInputVal(_from);
    if (_toInput   && _to)   _toInput.value   = _toLocalInputVal(_to);
  }

  function _toLocalInputVal(date) {
    const d = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
    return d.toISOString().slice(0, 16);
  }

  function isInRange(alert) {
    if (!_from || !_to) return true;
    const ts = alert?.timestamp || alert?.receivedAt || alert?.['@timestamp'];
    if (!ts) return true;
    const t = new Date(ts).getTime();
    return !isNaN(t) && t >= _from.getTime() && t <= _to.getTime();
  }

  /* ── Public ─────────────────────────────────────────────── */
  return { init, reload: _reload, isInRange };
})();

window.TimeRangePicker = TimeRangePicker;
