/**
 * Aegis SOC — Sidebar Controller
 */

'use strict';

const SidebarController = (() => {
  let _collapsed = false;
  let _sidebarEl = null;
  let _mainWrapEl = null;
  let _breadcrumbEl = null;

  const NAV_ITEMS = [
    { id: 'nav-dashboard', label: 'Security Overview', breadcrumb: 'Security Overview' },
    { id: 'nav-rules',     label: 'Rules Management', breadcrumb: 'Rules Management' },
    { id: 'nav-terminal',  label: 'Server Console',   breadcrumb: 'Server Console' },
  ];

  function init() {
    _sidebarEl    = document.getElementById('sidebar');
    _mainWrapEl   = document.getElementById('main-wrapper');
    _breadcrumbEl = document.getElementById('breadcrumb-current');

    if (!_sidebarEl) return;

    // Wire up nav items
    NAV_ITEMS.forEach(({ id, breadcrumb }) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.addEventListener('click', () => setActive(id, breadcrumb));
    });

    // Restore collapsed state from localStorage
    const saved = localStorage.getItem('aegis-sidebar-collapsed');
    if (saved === 'true') {
      _collapsed = true;
      _sidebarEl.classList.add('collapsed');
    }
  }

  function toggle() {
    _collapsed = !_collapsed;
    _sidebarEl.classList.toggle('collapsed', _collapsed);
    localStorage.setItem('aegis-sidebar-collapsed', _collapsed);
  }

  function setActive(activeId, breadcrumb) {
    NAV_ITEMS.forEach(({ id }) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.classList.toggle('active', id === activeId);
    });

    const dashboardView = document.getElementById('view-dashboard');
    const settingsView  = document.getElementById('view-settings');
    const rulesView     = document.getElementById('view-rules');
    const terminalView  = document.getElementById('view-terminal');

    if (dashboardView) dashboardView.style.display = (activeId === 'nav-dashboard') ? 'flex' : 'none';
    if (settingsView)  settingsView.style.display  = (activeId === 'nav-settings')  ? 'flex' : 'none';
    if (rulesView)     rulesView.style.display     = (activeId === 'nav-rules')     ? 'flex' : 'none';
    if (terminalView)  terminalView.style.display  = (activeId === 'nav-terminal')  ? 'flex' : 'none';

    if (activeId === 'nav-rules' && window.RulesEditorController) {
      window.RulesEditorController.onViewOpen();
    }

    if (activeId === 'nav-terminal' && window.TerminalController) {
      window.TerminalController.onViewOpen();
    }

    if (_breadcrumbEl && breadcrumb) {
      _breadcrumbEl.textContent = breadcrumb;
    }
  }

  /** Update the sensor count in the sidebar footer */
  function setSensorCount(active, total) {
    const el = document.getElementById('sensor-count');
    if (!el) return;
    el.textContent = `${active} / ${total} ONLINE`;
  }

  return { init, toggle, setActive, setSensorCount };
})();

window.SidebarController = SidebarController;
