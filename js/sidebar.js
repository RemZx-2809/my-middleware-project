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
    { id: 'nav-discover',  label: 'Discover',          breadcrumb: 'Discover / Logs' },
    { id: 'nav-storage',   label: 'Database',          breadcrumb: 'Database Storage' },
    { id: 'nav-history',   label: 'History',           breadcrumb: 'File Edit History' },
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
    const discoverView  = document.getElementById('view-discover');
    const settingsView  = document.getElementById('view-settings');
    const storageView   = document.getElementById('view-storage');
    const historyView   = document.getElementById('view-history');

    if (dashboardView) dashboardView.style.display = (activeId === 'nav-dashboard') ? 'flex' : 'none';
    if (discoverView) {
      discoverView.style.display = (activeId === 'nav-discover') ? 'flex' : 'none';
      if (activeId === 'nav-discover' && window.DiscoverController && typeof window.DiscoverController.reload === 'function') {
        window.DiscoverController.reload();
      }
    }
    if (settingsView)  settingsView.style.display  = (activeId === 'nav-settings')  ? 'flex' : 'none';
    if (storageView) {
      storageView.style.display = (activeId === 'nav-storage') ? 'flex' : 'none';
      if (activeId === 'nav-storage' && window.DbStorageController && typeof window.DbStorageController.load === 'function') {
        window.DbStorageController.load();
      }
    }
    if (historyView) {
      historyView.style.display = (activeId === 'nav-history') ? 'flex' : 'none';
      if (activeId === 'nav-history' && window.FileHistoryController && typeof window.FileHistoryController.load === 'function') {
        window.FileHistoryController.load();
      }
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
