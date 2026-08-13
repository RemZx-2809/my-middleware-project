/**
 * Aegis SOC — SSH Authorization Controller
 *
 * Handles the Settings → SSH Authorization section:
 *  1. Checks SSH key authorization status on page load
 *  2. Allows editing SSH Host IP and Username
 *  3. Provides one-click Re-authorize / Change Server workflow
 *  4. Sends password to server to auto-authorize the key (one-time)
 *  5. Falls back to showing manual command if plink not available
 */

'use strict';

const SshAuthController = (() => {
  function init() {
    const checkBtn     = document.getElementById('ssh-check-btn');
    const authorizeBtn = document.getElementById('ssh-authorize-btn');
    const copyBtn      = document.getElementById('ssh-copy-cmd-btn');
    const reauthBtn    = document.getElementById('ssh-reauth-btn');

    if (checkBtn)     checkBtn.addEventListener('click', checkStatus);
    if (authorizeBtn) authorizeBtn.addEventListener('click', authorize);
    if (copyBtn)      copyBtn.addEventListener('click', copyManualCmd);
    if (reauthBtn)    reauthBtn.addEventListener('click', toggleReauth);

    // Auto-check on load
    setTimeout(checkStatus, 800);
  }

  function toggleReauth() {
    const step1El = document.getElementById('ssh-step1-section');
    if (step1El) {
      step1El.style.display = (step1El.style.display === 'none' || !step1El.style.display) ? 'block' : 'none';
      if (step1El.style.display === 'block') {
        const hostInput = document.getElementById('ssh-target-host');
        if (hostInput) hostInput.focus();
      }
    }
  }

  async function checkStatus() {
    _setStatus('checking', 'Checking SSH key authorization…');
    try {
      const res  = await fetch('/api/ssh/status');
      const data = await res.json();
      const step1El   = document.getElementById('ssh-step1-section');
      const manualEl  = document.getElementById('ssh-manual-section');
      const authCard  = document.getElementById('ssh-active-card');
      const detailEl  = document.getElementById('ssh-active-detail');
      const hostInput = document.getElementById('ssh-target-host');
      const userInput = document.getElementById('ssh-target-user');

      if (data.host && hostInput) hostInput.value = data.host;
      if (data.user && userInput) userInput.value = data.user;

      if (data.authorized) {
        _setStatus('ok', `✅ Connected & Authorized — Passwordless SSH active on ${data.host}`);
        if (step1El)  step1El.style.display = 'none';
        if (manualEl) manualEl.style.display = 'none';
        if (authCard) authCard.style.display = 'flex';
        if (detailEl) detailEl.innerHTML = `Passwordless SSH authentication is enabled for <strong>${data.user}@${data.host}</strong>.`;
      } else {
        _setStatus('warn', `⚠️ Not authorized yet — Authorization required for ${data.host || 'server'}`);
        if (step1El)  step1El.style.display = 'block';
        if (authCard) authCard.style.display = 'none';
      }
    } catch {
      _setStatus('error', '❌ Could not reach server — is node server.js running?');
    }
  }

  async function authorize() {
    const hostInput = document.getElementById('ssh-target-host');
    const userInput = document.getElementById('ssh-target-user');
    const pwInput   = document.getElementById('ssh-auth-password');
    const result    = document.getElementById('ssh-auth-result');
    const btn       = document.getElementById('ssh-authorize-btn');

    const host     = hostInput?.value?.trim();
    const user     = userInput?.value?.trim();
    const password = pwInput?.value?.trim() || '';

    if (!host || !user) {
      _showResult('warn', '⚠️ Please enter both SSH Host IP and Username.');
      return;
    }

    btn.disabled = true;
    btn.innerHTML = '<i data-lucide="loader-2"></i> Saving & Testing…';
    if (typeof lucide !== 'undefined') lucide.createIcons();

    try {
      const res  = await fetch('/api/ssh/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, user, password }),
      });
      const data = await res.json();

      if (data.ok) {
        _setStatus('ok', `✅ SSH Authorized on ${host}! All future operations are passwordless.`);
        _showResult('ok', `🎉 Authorization successful for ${user}@${host}!`);
        if (pwInput) pwInput.value = '';

        const step1El  = document.getElementById('ssh-step1-section');
        const manualEl = document.getElementById('ssh-manual-section');
        const authCard = document.getElementById('ssh-active-card');
        const detailEl = document.getElementById('ssh-active-detail');

        if (step1El)  step1El.style.display = 'none';
        if (manualEl) manualEl.style.display = 'none';
        if (authCard) authCard.style.display = 'flex';
        if (detailEl) detailEl.innerHTML = `Passwordless SSH authentication is enabled for <strong>${user}@${host}</strong>.`;

        if (typeof Toast !== 'undefined') {
          Toast.show({ type: 'ok', title: 'SSH Authorized!', body: `Connected to ${user}@${host} successfully.`, duration: 4000 });
        }
      } else if (data.needManual) {
        const manualSection = document.getElementById('ssh-manual-section');
        const manualCmd     = document.getElementById('ssh-manual-cmd');
        if (manualSection) manualSection.style.display = 'block';
        if (manualCmd)     manualCmd.textContent = data.manualCmd || '';
        _showResult('warn', `⚠️ Run the command below on ${user}@${host} once, then click "Check Status".`);
      } else {
        _showResult('error', `❌ ${data.error || 'Authorization failed. Check the credentials and try again.'}`);
      }
    } catch (e) {
      _showResult('error', '❌ Server error — check that node server.js is running.');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i data-lucide="shield-check"></i> Authorize / Save';
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }
  }

  function copyManualCmd() {
    const cmd = document.getElementById('ssh-manual-cmd')?.textContent;
    if (!cmd) return;
    navigator.clipboard.writeText(cmd).then(() => {
      if (typeof Toast !== 'undefined') {
        Toast.show({ type: 'ok', title: 'Copied!', body: 'Paste this command into your Wazuh Server terminal.', duration: 2500 });
      }
    });
  }

  function _setStatus(type, text) {
    const dot  = document.getElementById('ssh-status-dot');
    const span = document.getElementById('ssh-status-text');
    if (!dot || !span) return;

    const colors = { ok: 'var(--ok)', warn: 'var(--warn)', error: 'var(--crit)', checking: 'var(--accent)' };
    dot.style.background = colors[type] || 'var(--text-dim)';
    span.textContent     = text;
  }

  function _showResult(type, text) {
    const el = document.getElementById('ssh-auth-result');
    if (!el) return;
    const styles = {
      ok:    { bg: 'var(--ok-dim)',   border: 'var(--ok-glow)',   color: 'var(--ok)' },
      warn:  { bg: 'var(--warn-dim)', border: 'var(--warn-glow)', color: 'var(--warn)' },
      error: { bg: 'var(--crit-dim)', border: 'var(--crit-glow)', color: 'var(--crit)' },
    };
    const s = styles[type] || styles.warn;
    el.style.display    = 'block';
    el.style.background = s.bg;
    el.style.borderColor= s.border;
    el.style.color      = s.color;
    el.style.fontSize   = 'var(--fs-sm)';
    el.textContent      = text;
  }

  return { init, checkStatus };
})();

window.SshAuthController = SshAuthController;
