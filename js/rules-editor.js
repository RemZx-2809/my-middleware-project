'use strict';

/**
 * Aegis SOC — Rules Editor Controller (Monaco Edition)
 *
 * Features:
 *   - Fetch & list editable rule files (GET /api/rules or GET /rules/files)
 *   - Search & filter rule files by name
 *   - Edit XML files with Monaco Editor syntax highlighting (with custom Aegis dark theme)
 *   - Fallback editor support if CDN/offline
 *   - "Save Rules (PUT)" button calling PUT /api/rules/:filename
 *   - Separate "Restart Manager" button with confirmation modal for service downtime
 *   - Ctrl+S keyboard shortcut for saving rules
 *   - XML auto-formatter and clipboard copy tool
 */

const RulesEditorController = (() => {
  /* ── State ─────────────────────────────────────────────────── */
  let _monacoEditor    = null;
  let _editorReady     = false;
  let _pendingLoad     = null;
  let _currentFilename = 'local_rules.xml';
  let _fileList        = [];
  let _isDirty         = false;

  /* ── DOM refs ───────────────────────────────────────────────── */
  let _fileListEl      = null;
  let _fileCountEl     = null;
  let _fileSearchEl    = null;
  let _filenameEl      = null;
  let _statusEl        = null;
  let _statsEl         = null;
  let _saveBtn         = null;
  let _restartBtn      = null;
  let _modal           = null;
  let _modalCloseBtn   = null;
  let _modalLaterBtn   = null;
  let _modalRestartBtn = null;

  function init() {
    _fileListEl      = document.getElementById('rule-file-list');
    _fileCountEl     = document.getElementById('rule-file-count');
    _fileSearchEl    = document.getElementById('rule-file-search');
    _filenameEl      = document.getElementById('rule-current-filename');
    _statusEl        = document.getElementById('rule-status-text');
    _statsEl         = document.getElementById('rule-editor-stats');
    _saveBtn         = document.getElementById('rule-save-btn');
    _restartBtn      = document.getElementById('rule-restart-btn');
    _modal           = document.getElementById('restart-modal');
    _modalCloseBtn   = document.getElementById('modal-close-btn');
    _modalLaterBtn   = document.getElementById('modal-later-btn');
    _modalRestartBtn = document.getElementById('modal-restart-btn');

    if (_saveBtn)         _saveBtn.addEventListener('click', saveRuleFile);
    if (_restartBtn)      _restartBtn.addEventListener('click', promptManagerRestart);
    if (_modalCloseBtn)   _modalCloseBtn.addEventListener('click', closeModal);
    if (_modalLaterBtn)   _modalLaterBtn.addEventListener('click', closeModal);
    if (_modalRestartBtn) _modalRestartBtn.addEventListener('click', executeManagerRestart);

    const formatBtn  = document.getElementById('rule-format-btn');
    const copyBtn    = document.getElementById('rule-copy-btn');
    const refreshBtn = document.getElementById('rule-refresh-btn');
    const newBtn     = document.getElementById('rule-new-btn');

    if (formatBtn)  formatBtn.addEventListener('click', formatXmlContent);
    if (copyBtn)    copyBtn.addEventListener('click', copyXmlContent);
    if (refreshBtn) refreshBtn.addEventListener('click', fetchRuleFilesList);
    if (newBtn)     newBtn.addEventListener('click', _createNewFile);

    if (_fileSearchEl) {
      _fileSearchEl.addEventListener('input', () => _renderFileList(_fileList));
    }

    if (_modal) {
      _modal.addEventListener('click', (e) => { if (e.target === _modal) closeModal(); });
    }

    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        const v = document.getElementById('view-rules');
        if (v && v.style.display !== 'none') {
          e.preventDefault();
          saveRuleFile();
        }
      }
    });

    _initMonaco();
  }

  function _initMonaco() {
    if (typeof require === 'undefined') {
      console.warn('[RulesEditor] Monaco loader not found. Using fallback editor.');
      _initFallbackEditor();
      return;
    }

    try {
      require.config({
        paths: { vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.52.0/min/vs' }
      });

      require(['vs/editor/editor.main'], () => {
        monaco.editor.defineTheme('aegis-dark', {
          base: 'vs-dark',
          inherit: true,
          rules: [
            { token: '',                       foreground: 'd1d5db', background: '070a10' },
            { token: 'tag',                    foreground: '22d3ee', fontStyle: 'bold' },
            { token: 'tag.id',                 foreground: '22d3ee' },
            { token: 'attribute.name',         foreground: '93c5fd' },
            { token: 'attribute.value',        foreground: '86efac' },
            { token: 'attribute.value.number', foreground: 'f5b94d' },
            { token: 'delimiter',              foreground: '4b6080' },
            { token: 'delimiter.xml',          foreground: '4b6080' },
            { token: 'comment',                foreground: '4b6080', fontStyle: 'italic' },
            { token: 'string',                 foreground: '86efac' },
            { token: 'number',                 foreground: 'f5b94d' },
            { token: 'metatag',                foreground: 'f5b94d' },
            { token: 'metatag.content',        foreground: '86efac' },
          ],
          colors: {
            'editor.background':                    '#070a10',
            'editor.foreground':                    '#d1d5db',
            'editorLineNumber.foreground':          '#2c3a4a',
            'editorLineNumber.activeForeground':    '#22d3ee',
            'editor.lineHighlightBackground':       '#0d131f',
            'editor.lineHighlightBorder':           '#0d131f',
            'editorCursor.foreground':              '#22d3ee',
            'editor.selectionBackground':           '#22d3ee25',
            'editor.inactiveSelectionBackground':   '#22d3ee12',
            'editor.findMatchBackground':           '#f5b94d40',
            'editor.findMatchHighlightBackground':  '#f5b94d20',
            'editorIndentGuide.background1':        '#1a2333',
            'editorBracketHighlight.foreground1':   '#22d3ee',
            'editorBracketHighlight.foreground2':   '#93c5fd',
            'editorBracketHighlight.foreground3':   '#86efac',
            'editorWidget.background':              '#0b1119',
            'editorWidget.border':                  '#22d3ee33',
            'editorWidget.foreground':              '#e7eef4',
            'editorSuggestWidget.background':       '#0b1119',
            'editorSuggestWidget.border':           '#22d3ee33',
            'editorSuggestWidget.selectedBackground': '#22d3ee18',
            'input.background':                     '#070a10',
            'input.foreground':                     '#e7eef4',
            'input.border':                         '#22d3ee33',
            'scrollbarSlider.background':           '#22d3ee18',
            'scrollbarSlider.hoverBackground':      '#22d3ee35',
            'scrollbarSlider.activeBackground':     '#22d3ee55',
            'minimap.background':                   '#070a10',
            'minimapSlider.background':             '#22d3ee12',
            'minimapSlider.hoverBackground':        '#22d3ee25',
            'minimapSlider.activeBackground':       '#22d3ee40',
            'editorGutter.background':              '#0a0e18',
            'editorOverviewRuler.border':           '#00000000',
          },
        });

        const container = document.getElementById('rule-monaco-editor');
        if (!container) return;

        _monacoEditor = monaco.editor.create(container, {
          value:                     '',
          language:                  'xml',
          theme:                     'aegis-dark',
          fontSize:                  13,
          fontFamily:                "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
          fontLigatures:             true,
          lineNumbers:               'on',
          lineNumbersMinChars:       4,
          glyphMargin:               false,
          folding:                   true,
          minimap:                   { enabled: true, scale: 1, renderCharacters: false, maxColumn: 80 },
          scrollBeyondLastLine:      false,
          wordWrap:                  'off',
          automaticLayout:           true,
          tabSize:                   2,
          insertSpaces:              true,
          renderWhitespace:          'selection',
          bracketPairColorization:   { enabled: true },
          scrollbar: {
            vertical:                'visible',
            horizontal:              'visible',
            verticalScrollbarSize:   8,
            horizontalScrollbarSize: 8,
            useShadows:              false,
          },
          padding:                   { top: 16, bottom: 16 },
          smoothScrolling:           true,
          cursorBlinking:            'smooth',
          cursorSmoothCaretAnimation:'on',
          roundedSelection:          true,
          links:                     true,
          mouseWheelZoom:            true,
        });

        _monacoEditor.onDidChangeModelContent(() => {
          _isDirty = true;
          _updateStats();
          _updateDirtyIndicator();
        });

        _monacoEditor.onDidChangeCursorPosition(() => _updateStats());

        _monacoEditor.addCommand(
          monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS,
          saveRuleFile
        );

        _editorReady = true;
        if (_pendingLoad) {
          const fn = _pendingLoad;
          _pendingLoad = null;
          loadRuleFile(fn);
        }
      });
    } catch (e) {
      console.warn('[RulesEditor] Monaco failed to load:', e.message);
      _initFallbackEditor();
    }
  }

  function _initFallbackEditor() {
    const c = document.getElementById('rule-monaco-editor');
    if (!c) return;
    c.innerHTML = '<textarea id="rule-xml-ta-fallback" style="width:100%;height:100%;min-height:480px;background:#070a10;color:#d1d5db;font-family:\'JetBrains Mono\',monospace;font-size:13px;line-height:1.6;padding:16px;border:none;resize:none;outline:none;tab-size:2;" spellcheck="false" placeholder="<!-- Write custom Wazuh XML rules here -->"></textarea>';
    const ta = document.getElementById('rule-xml-ta-fallback');
    ta.addEventListener('input', () => {
      _isDirty = true;
      _updateStats();
      _updateDirtyIndicator();
    });
    ta.addEventListener('keydown', (e) => {
      if (e.key === 'Tab') {
        e.preventDefault();
        const s = ta.selectionStart;
        ta.value = ta.value.substring(0, s) + '  ' + ta.value.substring(ta.selectionEnd);
        ta.selectionStart = ta.selectionEnd = s + 2;
      }
    });

    _monacoEditor = {
      getValue:    () => ta.value,
      setValue:    (v) => { ta.value = v; },
      getPosition: () => null,
      getModel:    () => ({
        getLineCount:       () => ta.value.split('\n').length,
        getValue:           () => ta.value,
        setValue:           (v) => { ta.value = v; },
        getFullModelRange:  () => null,
        pushEditOperations: (_, ops) => { if (ops[0]) ta.value = ops[0].text; },
      }),
      layout:     () => {},
      addCommand: () => {},
      revealLine: () => {},
    };

    _editorReady = true;
    if (_pendingLoad) { loadRuleFile(_pendingLoad); _pendingLoad = null; }
  }

  function onViewOpen() {
    fetchRuleFilesList();
    if (_editorReady) {
      loadRuleFile(_currentFilename);
    } else {
      _pendingLoad = _currentFilename;
    }
    setTimeout(() => { if (_monacoEditor) _monacoEditor.layout(); }, 200);
  }

  async function fetchRuleFilesList() {
    if (_fileListEl) {
      _fileListEl.innerHTML =
        '<div class="rules-file-list-state">' +
        '<span class="rules-file-list-spinner"></span>' +
        '<span>Loading files…</span></div>';
    }
    try {
      const res  = await fetch('/api/rules');
      const data = await res.json();
      if (data.ok && Array.isArray(data.files)) {
        _fileList = data.files;
        if (_fileList.length > 0 && !_fileList.find((f) => f.name === _currentFilename)) {
          _currentFilename = _fileList[0].name;
        }
        _renderFileList(_fileList);
      } else {
        _showFileListError('Server error');
      }
    } catch (err) {
      console.warn('[RulesEditor] fetchRuleFilesList:', err.message);
      _showFileListError('Cannot reach server');
    }
  }

  function _showFileListError(msg) {
    if (_fileListEl) {
      _fileListEl.innerHTML =
        '<div class="rules-file-list-state rules-file-list-state--error">' + msg + '</div>';
    }
  }

  function _renderFileList(files) {
    if (!_fileListEl) return;

    const query    = (_fileSearchEl ? _fileSearchEl.value : '').toLowerCase().trim();
    const filtered = query ? files.filter((f) => f.name.toLowerCase().includes(query)) : files;

    if (_fileCountEl) _fileCountEl.textContent = files.length + ' files';

    if (!filtered.length) {
      _fileListEl.innerHTML = '<div class="rules-file-list-state">No matching rule files</div>';
      return;
    }

    _fileListEl.innerHTML = filtered.map((f) => {
      const isActive = f.name === _currentFilename;
      const sizeStr  = _formatBytes(f.size);
      const timeStr  = f.modified ? _relativeTime(new Date(f.modified)) : 'new';
      const icon     = f.name === 'local_rules.xml' ? 'shield' : 'file-code-2';
      return (
        '<div class="rules-file-item' + (isActive ? ' active' : '') + '"' +
        ' data-filename="' + f.name + '" role="button" tabindex="0" title="' + f.name + '">' +
        '<div class="rules-file-item-icon"><i data-lucide="' + icon + '"></i></div>' +
        '<div class="rules-file-item-info">' +
          '<span class="rules-file-item-name">' + f.name + '</span>' +
          '<span class="rules-file-item-meta">' + sizeStr + ' • ' + timeStr + '</span>' +
        '</div>' +
        (isActive ? '<span class="rules-file-active-pip"></span>' : '') +
        '</div>'
      );
    }).join('');

    if (typeof lucide !== 'undefined') lucide.createIcons();

    _fileListEl.querySelectorAll('.rules-file-item').forEach((el) => {
      el.addEventListener('click',   () => _selectFile(el.dataset.filename));
      el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); _selectFile(el.dataset.filename); }
      });
    });
  }

  function _selectFile(filename) {
    if (!filename || filename === _currentFilename) return;
    if (_isDirty) {
      if (!confirm('ไฟล์ ' + _currentFilename + ' มีการเปลี่ยนแปลงที่ยังไม่ได้บันทึก\nเปิดไฟล์ใหม่โดยไม่บันทึกหรือไม่?')) return;
    }
    _currentFilename = filename;
    loadRuleFile(filename);
    _renderFileList(_fileList);
  }

  async function loadRuleFile(filename) {
    if (!_monacoEditor) { _pendingLoad = filename; return; }
    _setStatus('Loading…', 'loading');
    if (_filenameEl) _filenameEl.textContent = filename;

    try {
      const res = await fetch('/api/rules/' + encodeURIComponent(filename));
      if (res.status === 404) {
        _setEditorContent(_defaultTemplate());
        _setStatus('New file', 'new');
      } else {
        const data = await res.json();
        if (data.ok) {
          _setEditorContent(data.content);
          _setStatus('Loaded', 'ok');
        } else {
          Toast.show({ type: 'error', title: 'Load Error', body: data.error || 'Failed to load XML' });
          _setStatus('Error', 'error');
        }
      }
    } catch (err) {
      Toast.show({ type: 'error', title: 'Network Error', body: 'Cannot reach server: ' + err.message });
      _setStatus('Error', 'error');
    }

    _isDirty = false;
    _updateDirtyIndicator();
  }

  function _setEditorContent(content) {
    if (!_monacoEditor) return;
    const model = _monacoEditor.getModel ? _monacoEditor.getModel() : null;
    if (model && model.setValue) { model.setValue(content); } else { _monacoEditor.setValue(content); }
    if (_monacoEditor.revealLine) _monacoEditor.revealLine(1);
    _isDirty = false;
    _updateStats();
  }

  function _defaultTemplate() {
    return [
      '<group name="custom_rules">',
      '',
      '  <!-- Add your custom Wazuh rules below.',
      '       Rule IDs 100000-109999 are reserved for local rules. -->',
      '',
      '  <rule id="100001" level="5">',
      '    <description>Custom local security rule</description>',
      '  </rule>',
      '',
      '</group>',
    ].join('\n');
  }

  async function saveRuleFile() {
    if (!_monacoEditor) return;
    const content = _monacoEditor.getValue();

    if (!content.trim()) {
      Toast.show({ type: 'warn', title: 'Validation Error', body: 'Rule content cannot be empty.' });
      return;
    }

    _setSaveLoading(true);

    try {
      const res = await fetch('/api/rules/' + encodeURIComponent(_currentFilename), {
        method:  'PUT',
        headers: { 'Content-Type': 'application/json', 'X-Aegis-User': 'AdminUI' },
        body:    JSON.stringify({ content }),
      });
      const data = await res.json();

      if (res.ok && data.ok) {
        _isDirty = false;
        _updateDirtyIndicator();
        Toast.show({
          type:     'ok',
          title:    'บันทึกสำเร็จ!',
          body:     _currentFilename + ' ถูกบันทึกเรียบร้อย',
          duration: 4000,
        });
        _setStatus('Saved ' + new Date().toLocaleTimeString('th-TH'), 'ok');
        fetchRuleFilesList();
        promptManagerRestart();
      } else {
        Toast.show({ type: 'error', title: 'บันทึกไม่สำเร็จ', body: data.error || 'เกิดข้อผิดพลาด' });
        _setStatus('Save failed', 'error');
      }
    } catch (err) {
      Toast.show({ type: 'error', title: 'Network Error', body: 'Cannot reach server: ' + err.message });
      _setStatus('Error', 'error');
    } finally {
      _setSaveLoading(false);
    }
  }

  function formatXmlContent() {
    if (!_monacoEditor) return;
    try {
      let xml       = _monacoEditor.getValue();
      let formatted = '';
      let indent    = '';
      const tab     = '  ';

      xml.split(/>\s*</).forEach((node) => {
        if (node.match(/^\/\w/)) indent = indent.substring(tab.length);
        formatted += indent + '<' + node + '>\r\n';
        if (node.match(/^<?\w[^>]*[^/]$/) && !node.startsWith('?')) indent += tab;
      });

      const newVal = formatted.substring(1, formatted.length - 3);
      const model  = _monacoEditor.getModel ? _monacoEditor.getModel() : null;
      if (model && model.pushEditOperations && model.getFullModelRange) {
        model.pushEditOperations([], [{ range: model.getFullModelRange(), text: newVal }], () => null);
      } else {
        _monacoEditor.setValue(newVal);
      }
      Toast.show({ type: 'ok', title: 'Formatted', body: 'XML structure formatted.' });
    } catch (err) {
      Toast.show({ type: 'warn', title: 'Format Error', body: 'Could not format XML structure.' });
    }
  }

  function copyXmlContent() {
    if (!_monacoEditor) return;
    navigator.clipboard.writeText(_monacoEditor.getValue())
      .then(() => Toast.show({ type: 'ok',   title: 'Copied',      body: 'XML copied to clipboard.' }))
      .catch(() => Toast.show({ type: 'warn', title: 'Copy Failed', body: 'Clipboard access denied.' }));
  }

  function _createNewFile() {
    const name = prompt('Enter filename for new rule file (e.g., my_rules.xml):');
    if (!name) return;
    const fn = name.endsWith('.xml') ? name : name + '.xml';
    if (!_fileList.find((f) => f.name === fn)) {
      _fileList.push({ name: fn, size: 0, modified: null });
    }
    _currentFilename = fn;
    _setEditorContent(_defaultTemplate());
    _renderFileList(_fileList);
    if (_filenameEl) _filenameEl.textContent = fn;
    _setStatus('New file — not yet saved', 'new');
    Toast.show({ type: 'info', title: 'New File', body: 'Created "' + fn + '". Save to write to disk.', duration: 4000 });
  }

  function promptManagerRestart() {
    if (_modal) {
      _modal.style.display = 'flex';
      _modal.classList.add('modal-open');
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }
  }

  function closeModal() {
    if (_modal) {
      _modal.style.display = 'none';
      _modal.classList.remove('modal-open');
    }
  }

  async function executeManagerRestart() {
    if (_modalRestartBtn) {
      _modalRestartBtn.disabled = true;
      _modalRestartBtn.innerHTML =
        '<span class="rules-btn-spinner"></span> กำลัง Restart…';
    }
    try {
      const res  = await fetch('/api/wazuh-restart', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'X-Aegis-User': 'AdminUI' },
      });
      const data = await res.json();
      if (res.ok && data.ok) {
        Toast.show({
          type:     'ok',
          title:    'Restart สำเร็จ',
          body:     'ส่งคำสั่ง Restart Wazuh Manager แล้ว — กฎใหม่มีผลทันที',
          duration: 5000,
        });
        closeModal();
      } else {
        Toast.show({ type: 'error', title: 'Restart ไม่สำเร็จ', body: data.error || 'เกิดข้อผิดพลาด' });
      }
    } catch (err) {
      Toast.show({ type: 'error', title: 'Connection Error', body: 'ไม่สามารถเชื่อมต่อ: ' + err.message });
    } finally {
      if (_modalRestartBtn) {
        _modalRestartBtn.disabled = false;
        _modalRestartBtn.innerHTML = '<i data-lucide="refresh-cw"></i> Restart Manager ตอนนี้';
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }
    }
  }

  function _setStatus(text, type) {
    if (!_statusEl) return;
    _statusEl.textContent        = text;
    _statusEl.dataset.statusType = type || '';
  }

  function _updateStats() {
    if (!_statsEl || !_monacoEditor) return;
    const pos   = _monacoEditor.getPosition ? _monacoEditor.getPosition() : null;
    const model = _monacoEditor.getModel    ? _monacoEditor.getModel()    : null;
    const lines = model && model.getLineCount ? model.getLineCount() : 0;
    const chars = model && model.getValue    ? model.getValue().length : 0;
    const ln    = pos ? pos.lineNumber : 1;
    const col   = pos ? pos.column    : 1;
    _statsEl.textContent =
      'Ln ' + ln + ', Col ' + col + '  •  ' + lines + ' lines  •  ' + chars + ' chars';
  }

  function _updateDirtyIndicator() {
    if (!_filenameEl) return;
    _filenameEl.textContent = _isDirty ? ('● ' + _currentFilename) : _currentFilename;
    if (_saveBtn) _saveBtn.classList.toggle('has-changes', _isDirty);
  }

  function _setSaveLoading(saving) {
    if (!_saveBtn) return;
    _saveBtn.disabled = saving;
    _saveBtn.innerHTML = saving
      ? '<span class="rules-btn-spinner"></span> กำลังบันทึก…'
      : '<i data-lucide="save"></i> บันทึก Rules (PUT)';
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  function _formatBytes(bytes) {
    if (!bytes) return '—';
    if (bytes < 1024)    return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  function _relativeTime(date) {
    if (!date || isNaN(date)) return '—';
    const diff = Date.now() - date.getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1)   return 'just now';
    if (mins < 60)  return mins + 'm ago';
    const hrs = Math.floor(mins / 60);
    if (hrs  < 24)  return hrs + 'h ago';
    return Math.floor(hrs / 24) + 'd ago';
  }

  return {
    init,
    onViewOpen,
    loadRuleFile,
    saveRuleFile,
    promptManagerRestart,
    closeModal,
    executeManagerRestart,
  };
})();

window.RulesEditorController = RulesEditorController;
