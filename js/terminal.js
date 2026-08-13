/**
 * Aegis SOC — Web Terminal / Server Console Controller
 *
 * Provides in-browser passwordless SSH command execution on Wazuh Server.
 * Supports command history (Up/Down arrows), quick action presets, live output,
 * automatic inline sudo unlock, and full interactive Root Mode (sudo -i / exit).
 */

'use strict';

const TerminalController = (() => {
  const _history = [];
  let _historyIdx  = -1;
  let _isRootMode  = false;
  let _screenEl    = null;
  let _inputEl     = null;
  let _formEl      = null;
  let _runBtn      = null;
  let _promptEl    = null;
  let _rootToggle  = null;

  function init() {
    _screenEl   = document.getElementById('terminal-screen');
    _inputEl    = document.getElementById('terminal-input');
    _formEl     = document.getElementById('terminal-form');
    _runBtn     = document.getElementById('term-run-btn');
    _promptEl   = document.getElementById('term-prompt-label');
    _rootToggle = document.getElementById('term-root-toggle');

    if (!_formEl || !_inputEl) return;

    // Form submit
    _formEl.addEventListener('submit', (e) => {
      e.preventDefault();
      const cmd = _inputEl.value.trim();
      if (!cmd) return;
      runCommand(cmd);
    });

    // Root toggle button
    if (_rootToggle) {
      _rootToggle.addEventListener('click', toggleRootMode);
    }

    // History navigation with Arrow keys
    _inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (_history.length === 0) return;
        if (_historyIdx === -1) _historyIdx = _history.length;
        if (_historyIdx > 0) {
          _historyIdx--;
          _inputEl.value = _history[_historyIdx];
        }
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (_historyIdx !== -1 && _historyIdx < _history.length - 1) {
          _historyIdx++;
          _inputEl.value = _history[_historyIdx];
        } else {
          _historyIdx = -1;
          _inputEl.value = '';
        }
      }
    });

    // Clear button
    const clearBtn = document.getElementById('term-clear-btn');
    if (clearBtn) {
      clearBtn.addEventListener('click', clearScreen);
    }

    // Quick Command Presets
    document.querySelectorAll('.term-preset-chip').forEach((btn) => {
      btn.addEventListener('click', () => {
        const cmd = btn.dataset.cmd;
        if (cmd) {
          _inputEl.value = cmd;
          runCommand(cmd);
        }
      });
    });
  }

  function toggleRootMode() {
    _setRootMode(!_isRootMode);
  }

  function _setRootMode(enabled) {
    _isRootMode = enabled;
    if (_promptEl) {
      _promptEl.textContent = _isRootMode ? 'root@wazuh:~#' : 'tawaikiar_p@wazuh:~$';
      _promptEl.style.color = _isRootMode ? '#ff5f56' : '#38ef7d';
    }
    if (_rootToggle) {
      _rootToggle.classList.toggle('active', _isRootMode);
      _rootToggle.innerHTML = _isRootMode
        ? '<i data-lucide="shield-alert"></i> Root Mode: ON'
        : '<i data-lucide="shield"></i> Root Mode: OFF';
      _rootToggle.style.borderColor = _isRootMode ? 'var(--crit)' : 'var(--border-subtle)';
      _rootToggle.style.color = _isRootMode ? 'var(--crit)' : 'var(--text-mid)';
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }
  }

  function onViewOpen() {
    setTimeout(() => {
      if (_inputEl) _inputEl.focus();
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }, 100);
  }

  async function runCommand(cmd, sudoPassword = null) {
    if (!cmd) return;

    // Handle `sudo -i` or `su` or `su -` command locally
    if (cmd === 'sudo -i' || cmd === 'sudo su' || cmd === 'su' || cmd === 'su -') {
      _history.push(cmd);
      _historyIdx = -1;
      _inputEl.value = '';
      _setRootMode(true);
      _appendLine(`
        <div class="term-entry">
          <div class="term-entry-header">
            <span class="term-prompt">tawaikiar_p@wazuh:~$</span>
            <span class="term-cmd-text">${_escapeHtml(cmd)}</span>
            <span class="term-time">${new Date().toLocaleTimeString()}</span>
          </div>
          <div class="term-output term-output--ok" style="border-left-color:#ff5f56; background:rgba(255,95,86,0.06); color:#ff948f;">
            👑 Switched to <strong>root@wazuh:~#</strong> (Root Mode ON). All commands will execute with root privileges automatically. Type <code>exit</code> to leave root.
          </div>
        </div>
      `);
      _scrollToBottom();
      return;
    }

    // Handle `exit` command when in root mode
    if (cmd === 'exit' && _isRootMode) {
      _history.push(cmd);
      _historyIdx = -1;
      _inputEl.value = '';
      _setRootMode(false);
      _appendLine(`
        <div class="term-entry">
          <div class="term-entry-header">
            <span class="term-prompt" style="color:#ff5f56;">root@wazuh:~#</span>
            <span class="term-cmd-text">${_escapeHtml(cmd)}</span>
            <span class="term-time">${new Date().toLocaleTimeString()}</span>
          </div>
          <div class="term-output term-output--ok">
            ⬅️ Logged out of root. Switched back to <strong>tawaikiar_p@wazuh:~$</strong>
          </div>
        </div>
      `);
      _scrollToBottom();
      return;
    }

    // Add to history if not re-executing
    if (!sudoPassword) {
      _history.push(cmd);
      _historyIdx = -1;
      _inputEl.value = '';
    }

    // If Root Mode is active and command doesn't have sudo, prepend sudo
    let execCmd = cmd;
    if (_isRootMode && !execCmd.startsWith('sudo ')) {
      execCmd = `sudo ${execCmd}`;
    }

    // Render command line in terminal
    const timeStr = new Date().toLocaleTimeString();
    const promptText = _isRootMode ? 'root@wazuh:~#' : 'tawaikiar_p@wazuh:~$';
    const promptColor = _isRootMode ? '#ff5f56' : '#38ef7d';

    _appendLine(`
      <div class="term-entry" data-cmd="${_escapeHtml(cmd)}">
        <div class="term-entry-header">
          <span class="term-prompt" style="color:${promptColor};">${promptText}</span>
          <span class="term-cmd-text">${_escapeHtml(cmd)}</span>
          <span class="term-time">${timeStr}</span>
        </div>
        <div class="term-entry-loading"><i data-lucide="loader-2"></i> Executing on Wazuh Server…</div>
      </div>
    `);
    if (typeof lucide !== 'undefined') lucide.createIcons();
    _scrollToBottom();

    _inputEl.disabled = true;
    if (_runBtn) _runBtn.disabled = true;

    try {
      const res = await fetch('/api/terminal/exec', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: execCmd, sudoPassword }),
      });

      const data = await res.json();

      const entries = _screenEl.querySelectorAll('.term-entry');
      const lastEntry = entries[entries.length - 1];

      if (lastEntry) {
        const loadEl = lastEntry.querySelector('.term-entry-loading');
        if (loadEl) loadEl.remove();

        const outText = ((data.output || '') + (data.error ? ('\n' + data.error) : '')).trim();

        // Check if sudo password was required
        if (outText.includes('password is required') || outText.includes('a terminal is required')) {
          _showSudoPrompt(lastEntry, cmd);
          return;
        }

        const outBox = document.createElement('pre');
        outBox.className = data.ok ? 'term-output term-output--ok' : 'term-output term-output--err';
        outBox.textContent = outText || (data.ok ? '(Command executed successfully with no output)' : `Exit code: ${data.exitCode}`);
        lastEntry.appendChild(outBox);
      }
    } catch (e) {
      _appendLine(`
        <div class="term-output term-output--err">
          Execution failed: ${e.message}. Is node server.js running?
        </div>
      `);
    } finally {
      _inputEl.disabled = false;
      if (_runBtn) _runBtn.disabled = false;
      _inputEl.focus();
      _scrollToBottom();
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }
  }

  function _showSudoPrompt(entryEl, originalCmd) {
    const promptDiv = document.createElement('div');
    promptDiv.className = 'term-sudo-box';
    promptDiv.innerHTML = `
      <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px; color:var(--warn); font-size:12px;">
        <i data-lucide="key-round" style="width:14px; height:14px;"></i>
        <span><strong>Sudo requires authorization.</strong> Enter your Wazuh Server password below to unlock permanently:</span>
      </div>
      <div style="display:flex; gap:8px; align-items:center;">
        <input type="password" class="term-sudo-input" placeholder="Enter password (tawaikiar_p)..." autocomplete="off" />
        <button type="button" class="int-btn int-btn--primary term-sudo-btn" style="padding:4px 14px; font-size:12px;">
          <i data-lucide="unlock"></i> Unlock & Execute
        </button>
      </div>
      <div class="term-sudo-status" style="margin-top:6px; font-size:11px; display:none;"></div>
    `;

    entryEl.appendChild(promptDiv);
    if (typeof lucide !== 'undefined') lucide.createIcons();

    const pwInput = promptDiv.querySelector('.term-sudo-input');
    const submitBtn = promptDiv.querySelector('.term-sudo-btn');
    const statusDiv = promptDiv.querySelector('.term-sudo-status');

    if (pwInput) pwInput.focus();

    const doUnlock = async () => {
      const password = pwInput.value.trim();
      if (!password) return;

      submitBtn.disabled = true;
      submitBtn.innerHTML = '<i data-lucide="loader-2"></i> Unlocking…';
      if (typeof lucide !== 'undefined') lucide.createIcons();

      try {
        const unlockRes = await fetch('/api/terminal/unlock-sudo', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password }),
        });
        const unlockData = await unlockRes.json();

        if (unlockData.ok) {
          statusDiv.style.display = 'block';
          statusDiv.style.color = 'var(--ok)';
          statusDiv.textContent = '✅ Root / Sudo unlocked permanently! Re-running command…';
          setTimeout(() => {
            promptDiv.remove();
            runCommand(originalCmd);
          }, 800);
        } else {
          statusDiv.style.display = 'block';
          statusDiv.style.color = 'var(--crit)';
          statusDiv.textContent = `❌ ${unlockData.error || 'Incorrect password'}`;
          submitBtn.disabled = false;
          submitBtn.innerHTML = '<i data-lucide="unlock"></i> Unlock & Execute';
          if (typeof lucide !== 'undefined') lucide.createIcons();
        }
      } catch (e) {
        statusDiv.style.display = 'block';
        statusDiv.style.color = 'var(--crit)';
        statusDiv.textContent = `❌ Server error: ${e.message}`;
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i data-lucide="unlock"></i> Unlock & Execute';
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }
    };

    submitBtn.addEventListener('click', doUnlock);
    pwInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        doUnlock();
      }
    });

    _scrollToBottom();
  }

  function clearScreen() {
    if (!_screenEl) return;
    _screenEl.innerHTML = `
      <div class="term-line term-line--system">
        [Aegis SOC Web Terminal v1.0] Screen cleared. Ready for commands.
      </div>
    `;
    if (_inputEl) _inputEl.focus();
  }

  function _appendLine(html) {
    if (!_screenEl) return;
    const div = document.createElement('div');
    div.innerHTML = html;
    while (div.firstChild) {
      _screenEl.appendChild(div.firstChild);
    }
  }

  function _scrollToBottom() {
    if (_screenEl) {
      _screenEl.scrollTop = _screenEl.scrollHeight;
    }
  }

  function _escapeHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  return { init, onViewOpen, runCommand, clearScreen, toggleRootMode };
})();

window.TerminalController = TerminalController;
