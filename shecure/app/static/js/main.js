/* SHEcure — Main JS */

// ── PST timestamp helper ─────────────────────
function toPST(isoString) {
  if (!isoString) return '—';
  // If already has PST suffix, return as-is
  if (typeof isoString === 'string' && isoString.endsWith('PST')) return isoString;
  // Parse and convert to UTC+8
  const d = new Date(isoString);
  if (isNaN(d)) return isoString;
  const pst = new Date(d.getTime() + (8 * 60 * 60 * 1000));
  const pad = n => String(n).padStart(2, '0');
  return `${pst.getUTCFullYear()}-${pad(pst.getUTCMonth()+1)}-${pad(pst.getUTCDate())} `
       + `${pad(pst.getUTCHours())}:${pad(pst.getUTCMinutes())}:${pad(pst.getUTCSeconds())} PST`;
}

function toPSTTime(isoString) {
  const full = toPST(isoString);
  // Return only HH:MM:SS PST part
  const match = full.match(/(\d{2}:\d{2}:\d{2} PST)$/);
  return match ? match[1] : full;
}

// Convert all static server-rendered timestamps on page load
document.querySelectorAll('[data-utc]').forEach(el => {
  el.textContent = toPST(el.dataset.utc);
});

// ── Alert count polling ──────────────────────
let alertCountEl = document.getElementById('alert-count-badge');
let alertBellDot = document.getElementById('alert-bell-dot');

function pollAlertCount() {
  fetch('/api/alerts/count')
    .then(r => r.json())
    .then(data => {
      if (alertCountEl) {
        alertCountEl.textContent = data.count;
        alertCountEl.style.display = data.count > 0 ? '' : 'none';
      }
      if (alertBellDot) {
        alertBellDot.style.display = data.count > 0 ? '' : 'none';
      }
    })
    .catch(() => {});
}

if (alertCountEl || alertBellDot) {
  pollAlertCount();
  setInterval(pollAlertCount, 15000);
}

// ── Toast notification system ────────────────
function showToast(message, type = 'info', duration = 4000) {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const icons = { success: '⚜', danger: '𔓘', warning: '⏾', info: '𓆉'};

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'polite');
  toast.innerHTML = `
    <span style="font-size:1.1rem">${icons[type] || icons.info}</span>
    <span style="flex:1">${message}</span>
    <button onclick="this.parentElement.remove()" aria-label="Dismiss"
      style="background:none;border:none;cursor:pointer;color:#9ca3af;font-size:1rem">✕</button>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = 'all .3s';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

window.showToast = showToast;

// ── Flash message auto-dismiss ───────────────
document.querySelectorAll('.alert[data-auto-dismiss]').forEach(el => {
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity .4s';
    setTimeout(() => el.remove(), 400);
  }, 5000);
});

// ── Mobile sidebar toggle ────────────────────
const menuBtn = document.getElementById('menu-toggle');
const sidebar = document.querySelector('.sidebar');
const overlay = document.getElementById('sidebar-overlay');

function openSidebar() {
  sidebar?.classList.add('open');
  overlay?.classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeSidebar() {
  sidebar?.classList.remove('open');
  overlay?.classList.remove('active');
  document.body.style.overflow = '';
}

menuBtn?.addEventListener('click', openSidebar);
overlay?.addEventListener('click', closeSidebar);

// ── Resolve alert button ─────────────────────
document.querySelectorAll('.resolve-alert-btn').forEach(btn => {
  btn.addEventListener('click', async function () {
    const alertId = this.dataset.alertId;
    const csrf = this.dataset.csrf;
    const res = await fetch(`/admin/alerts/${alertId}/resolve`, {
      method: 'POST',
      headers: { 'X-CSRFToken': csrf },
    });
    const data = await res.json();
    if (data.ok) {
      const row = document.getElementById(`alert-row-${alertId}`);
      if (row) {
        row.classList.add('resolved');
        row.querySelector('.resolve-alert-btn').remove();
      }
      showToast('Alert resolved.', 'success');
      pollAlertCount();
    }
  });
});

// ── Custom confirm modal ─────────────────────
// Handles both [data-confirm] buttons and forms with [data-confirm].
// Falls back to the native dialog if the modal DOM isn't present (e.g. non-admin pages).
document.addEventListener('DOMContentLoaded', function () {
(function () {
  const modal   = document.getElementById('admin-confirm-modal');
  const msgEl   = document.getElementById('admin-confirm-message');
  const iconEl  = document.getElementById('admin-confirm-icon');
  const okBtn   = document.getElementById('admin-confirm-ok');
  const cancelBtn = document.getElementById('admin-confirm-cancel');

  if (!modal) {
    // No modal on this page — fall back to native confirm for data-confirm elements
    document.querySelectorAll('[data-confirm]').forEach(el => {
      el.addEventListener('click', function (e) {
        if (!confirm(this.dataset.confirm)) e.preventDefault();
      });
    });
    return;
  }

  let _pendingAction = null;

  function showModal(message, icon, okLabel, onConfirm) {
    msgEl.textContent  = message;
    iconEl.textContent = icon || '⚠️';
    okBtn.textContent  = okLabel || 'Confirm';
    _pendingAction     = onConfirm;
    modal.style.display       = 'flex';
    modal.style.visibility    = 'visible';
    modal.style.pointerEvents = 'auto';
  }

  function hideModal() {
    modal.style.display       = 'none';
    modal.style.visibility    = 'hidden';
    modal.style.pointerEvents = 'none';
    _pendingAction = null;
  }

  okBtn.addEventListener('click', () => {
    const action = _pendingAction;
    hideModal();
    if (action) action();
  });

  cancelBtn.addEventListener('click', hideModal);

  // Close on backdrop click
  modal.addEventListener('click', e => { if (e.target === modal) hideModal(); });

  // [data-confirm] on a <button type="submit"> inside a <form>
  document.querySelectorAll('button[data-confirm]').forEach(btn => {
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      const form = this.closest('form');
      showModal(this.dataset.confirm, this.dataset.confirmIcon, this.dataset.confirmOk, () => {
        if (form) form.submit();
      });
    });
  });

  // [data-confirm] on a <form> directly (submit intercept)
  document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      showModal(this.dataset.confirm, this.dataset.confirmIcon, this.dataset.confirmOk, () => {
        this.submit();
      });
    });
  });
})();
}); // end DOMContentLoaded

// ── Camera status (dashboard home only — camera page manages its own) ────────
// Only run this lightweight check on pages that embed the status element
// but are NOT the dedicated /camera/ page (which has full reconnection logic).
const cameraStatusEl = document.getElementById('camera-status-text');
if (cameraStatusEl && !window.location.pathname.startsWith('/camera')) {
  fetch('/camera/status')
    .then(r => r.json())
    .then(data => {
      cameraStatusEl.textContent = data.online ? 'LIVE' : 'OFFLINE';
      cameraStatusEl.style.color = data.online ? '#10b981' : '#ef4444';
    })
    .catch(() => {
      if (cameraStatusEl) cameraStatusEl.textContent = 'UNKNOWN';
    });
}

// ── Table row highlight for suspicious ───────
document.querySelectorAll('tr[data-suspicious="true"]').forEach(row => {
  row.style.background = '#fff5f7';
});

// ── Real-time activity feed (dashboard) ──────
// Shows BOTH access logs and activity logs merged and sorted by time
const activityFeed = document.getElementById('live-activity-feed');
if (activityFeed) {
  function refreshActivity() {
    Promise.all([
      fetch('/api/access/recent').then(r => r.json()).catch(() => []),
      fetch('/api/activity/recent').then(r => r.json()).catch(() => []),
    ]).then(([accessLogs, activityLogs]) => {
      // Merge: access logs get IP+user+status, activity logs get action
      const rows = [];

      accessLogs.forEach(log => {
        rows.push({
          ip: log.ip || '—',
          user: log.username || '—',
          action: log.status === 'success' ? 'Login' :
                  log.status === 'blocked' ? 'Blocked' :
                  log.status === 'logout'  ? 'Logout' : '⚠️ ' + log.status,
          statusClass: log.status === 'success' ? 'badge-success' :
                       log.status === 'blocked' ? 'badge-danger' : 'badge-warning',
          time: log.timestamp,
        });
      });

      activityLogs.forEach(log => {
        // Skip static/api noise unless suspicious
        if (log.endpoint && log.endpoint.startsWith('/static')) return;
        rows.push({
          ip: log.ip || '—',
          user: log.username || '—',
          action: log.action || log.description || log.endpoint || '—',
          statusClass: log.suspicious ? 'badge-danger' : 'badge-info',
          time: log.timestamp,
        });
      });

      // Sort newest first, take top 10
      rows.sort((a, b) => {
        const ta = a.time ? new Date(a.time.replace(' PST','')) : 0;
        const tb = b.time ? new Date(b.time.replace(' PST','')) : 0;
        return tb - ta;
      });

      activityFeed.innerHTML = rows.slice(0, 10).map(row => `
        <tr>
          <td><span class="text-mono" style="font-size:.78rem">${row.ip}</span></td>
          <td style="font-size:.85rem">${row.user}</td>
          <td><span class="badge ${row.statusClass}" style="font-size:.72rem">${row.action}</span></td>
          <td class="text-muted" style="font-size:.75rem">${toPSTTime(row.time)}</td>
        </tr>`).join('');
    });
  }

  refreshActivity();
  setInterval(refreshActivity, 8000);
}

// ── Sidebar active state ─────────────────────
const currentPath = window.location.pathname;
document.querySelectorAll('.sidebar-nav-item').forEach(item => {
  const href = item.getAttribute('href');
  if (href && currentPath.startsWith(href) && href !== '/') {
    item.classList.add('active');
  } else if (href === '/' && currentPath === '/') {
    item.classList.add('active');
  }
});
